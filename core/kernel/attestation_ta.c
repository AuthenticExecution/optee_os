#include <kernel/attestation_ta.h>
#include <tee/uuid.h>
#include <stdlib.h>
#include <string.h>

struct hash_node {
  TEE_UUID uuid;
  uint8_t hash[HASH_SIZE];
  struct hash_node *next;
};

struct hash_node *hashes = NULL;

int are_uuids_equal(TEE_UUID *uuid1, TEE_UUID *uuid2);

TEE_Result add_ree_fs_ta_hash(uint8_t *uuid, void *hash) {
  //TODO if uuid already exists, replace hash instead of creating a new node.

  struct hash_node *hash_node = malloc(sizeof(struct hash_node));
  if(hash_node == NULL) return TEE_ERROR_OUT_OF_MEMORY;

  tee_uuid_from_octets(&hash_node->uuid, uuid);
  memcpy(hash_node->hash, hash, HASH_SIZE);
  hash_node->next = hashes;
  hashes = hash_node;

  return TEE_SUCCESS;
}

int are_uuids_equal(TEE_UUID *uuid1, TEE_UUID *uuid2) {
  int i, equals = 1;
  for(i=0; i<8; i++) {
    if(uuid1->clockSeqAndNode[i] != uuid2->clockSeqAndNode[i]) {
      equals = 0;
      break;
    }
  }

  return equals &&
         uuid1->timeLow == uuid2->timeLow &&
         uuid1->timeMid == uuid2->timeMid &&
         uuid1->timeHiAndVersion == uuid2->timeHiAndVersion;
}

TEE_Result get_ree_fs_ta_hash(TEE_UUID *uuid, void *result) {
  struct hash_node *hash_node = NULL;

  for(hash_node = hashes; hash_node != NULL; hash_node = hash_node->next) {
    if(are_uuids_equal(uuid, &hash_node->uuid)) {
      memcpy(result, hash_node->hash, HASH_SIZE);
      return TEE_SUCCESS;
    }
  }

  return TEE_ERROR_GENERIC;
}
