#ifndef ATTESTATION_TA_H
#define ATTESTATION_TA_H

#include <tee_api_types.h>
#include <utee_defines.h>

#define HASH_SIZE TEE_SHA256_HASH_SIZE // 32
#define TA_KEY_SIZE 16 // should be <= HASH_SIZE

TEE_Result add_ree_fs_ta_hash(uint8_t *uuid, void *hash);
TEE_Result get_ree_fs_ta_hash(TEE_UUID *uuid, void *result);

#endif
