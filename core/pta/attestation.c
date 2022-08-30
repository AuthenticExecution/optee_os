#include <compiler.h>
#include <stdio.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <pta_attestation.h>
#include <string.h>
#include <string_ext.h>
#include <stdlib.h>
#include <tee_api_types.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>

#include <kernel/attestation_ta.h>

static TEE_Result get_hardware_unique_key(uint8_t *key)
{
	/*
	 * TODO: Dummy function get_endorsement_key
	 * do something hardware specific
	 */
	uint8_t end_key[] = {0x9a, 0x04, 0xaa, 0x18,
			0x2d, 0x03, 0x96, 0x74,
			0x70, 0x8c, 0xe8, 0x07,
			0xed, 0x91, 0x4c, 0xd1,
			0x53, 0xcd, 0x9d, 0xf7,
			0x80, 0x5e, 0x61, 0x74,
			0x2f, 0x0a, 0xe4, 0x12,
			0x94, 0x75, 0x8d, 0xd3 };
	memcpy(key, end_key, HASH_SIZE);
	return TEE_SUCCESS;
}

static TEE_Result get_hash(uint8_t *dst, uint8_t *src, size_t src_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *ctx = NULL;
	size_t digest_len = TEE_SHA256_HASH_SIZE;

	res = crypto_hash_alloc_ctx(&ctx, TEE_ALG_SHA256);
	if (res)
		goto err;

	res = crypto_hash_init(ctx);
	if (res)
		goto err;

	res = crypto_hash_update(ctx, src, src_len);
	if (res)
		goto err;

	res = crypto_hash_final(ctx, dst, digest_len);
	if (res)
		goto err;

	res = TEE_SUCCESS;
err:
	crypto_hash_free_ctx(ctx);
	return res;
}


static TEE_Result attestation(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT, 
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	if (exp_pt != type || p[0].memref.size != VENDOR_ID_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t huk_vendor[HASH_SIZE + VENDOR_ID_SIZE];
	uint8_t vendor_module[2 * HASH_SIZE];
	uint8_t module_key[HASH_SIZE];

	res = get_hardware_unique_key(huk_vendor);
	if(res)
		return res;

	uint8_t *vendor_id = (uint8_t *)p[0].memref.buffer;
	memcpy(huk_vendor + HASH_SIZE, vendor_id, VENDOR_ID_SIZE);

	/* generate the vendor key, from the HUK and vendor ID */
	res = get_hash(vendor_module, huk_vendor, HASH_SIZE + VENDOR_ID_SIZE);
	if (res)
		return res;

	/* get the hash of the calling TA */
	res = get_ree_fs_ta_hash(&ts_get_calling_session()->ctx->uuid, vendor_module + HASH_SIZE);

	if(res) {
		DMSG("Error in get_ree_fs_ta_hash: %d", res);
		return res;
	}

	/* generate the module key from the vendor key and the TA's hash */
	res = get_hash(module_key, vendor_module, 2 * HASH_SIZE);
	if (res)
		return res;

	// copy only the first TA_KEY_SIZE bytes
	p[1].memref.size = TA_KEY_SIZE;
	memcpy(p[1].memref.buffer, module_key, TA_KEY_SIZE);

	DMSG("---- module key was issued! ----");
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{

	DMSG("Attestation-PTA got called (cmd): %d", cmd);
	switch (cmd) {
	case ATTESTATION_CMD_GET_MODULE_KEY:
		DMSG(" ATTESTATION_CMD_GET_MODULE_KEY has been called");
		return attestation(ptypes, params);

	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = ATTESTATION_UUID, .name = "attestation.pta",
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
