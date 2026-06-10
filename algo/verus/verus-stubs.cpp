#include "miner.h"

#include <string.h>

extern "C" void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target,
                                           struct work *work, int nonce)
{
   (void)target;

   if (!work || !hash || nonce < 0 || nonce >= MAX_NONCES)
      return;

   memcpy(work->submit_hashes[nonce], hash, sizeof(work->submit_hashes[nonce]));
}
