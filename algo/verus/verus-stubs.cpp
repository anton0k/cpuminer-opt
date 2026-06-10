#include "miner.h"

extern "C" void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target,
                                           struct work *work, int nonce)
{
   (void)hash;
   (void)target;
   (void)nonce;
   if (work)
      work->sharediff = work->targetdiff;
}
