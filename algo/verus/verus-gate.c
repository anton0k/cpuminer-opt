#include "algo-gate-api.h"

#include <stdlib.h>
#include <string.h>

#define VERUS_NTIME_INDEX 25
#define VERUS_NBITS_INDEX 26
#define VERUS_NONCE_INDEX 30
#define VERUS_SCAN_WINDOW 8191U
#define VERUS_SUBMIT_SOL_BYTES 1347
#define VERUS_SOLUTION_BYTES 1344

extern int scanhash_verus(int thr_id, struct work *work, uint32_t max_nonce,
                          unsigned long *hashes_done);

static uint32_t verus_scan_round[MAX_GPUS];

static double verus_mining_factor(void)
{
   const char *value = getenv("CPUMINER_VERUS_M");
   double factor = (value && *value) ? atof(value) : 1.2;
   return factor > 0.0 ? factor : 1.0;
}

static double verus_target_to_diff_equi(const uint32_t *target)
{
   const unsigned char *tgt = (const unsigned char*)target;
   uint64_t m = (uint64_t)tgt[30] << 24 |
                (uint64_t)tgt[29] << 16 |
                (uint64_t)tgt[28] << 8  |
                (uint64_t)tgt[27];
   if (!m)
      return 0.0;
   return (double)0xffff0000UL / (double)m;
}

static void verus_diff_to_target_equi(uint32_t *target, double diff)
{
   uint64_t m;
   int k;

   if (diff <= 0.0)
      diff = 1.0;

   for (k = 6; k > 0 && diff > 1.0; k--)
      diff /= 4294967296.0;

   m = (uint64_t)(4294901760.0 / diff);
   if (m == 0 && k == 6)
   {
      memset(target, 0xff, 32);
   }
   else
   {
      memset(target, 0, 32);
      target[k + 1] = (uint32_t)(m >> 8);
      target[k + 2] = (uint32_t)(m >> 40);
      for (k = 0; k < 28 && ((unsigned char*)target)[k] == 0; k++)
         ((unsigned char*)target)[k] = 0xff;
   }
}

static double verus_diff_from_pool_target(const unsigned char *target_bin)
{
   unsigned char target_be[32];
   int filled = 0;

   memset(target_be, 0xff, sizeof(target_be));
   for (int i = 0; i < 32; i++)
   {
      if (filled == 3)
         break;
      target_be[31 - i] = target_bin[i];
      if (target_bin[i])
         filled++;
   }

   double diff = verus_target_to_diff_equi((const uint32_t*)target_be);
   return diff > 0.0 ? diff : 1.0;
}

void verus_get_new_work(struct work *work, struct work *g_work, int thr_id,
                        uint32_t *end_nonce_ptr)
{
   const int slot = thr_id % MAX_GPUS;

   work_free(work);
   work_copy(work, g_work);

   work->data[VERUS_NONCE_INDEX] = 0;
   work->data[32] = (verus_scan_round[slot]++ << 8)
                    | (uint32_t)(thr_id & 0xff);
   work->valid_nonces = 0;
   work->submit_nonce_id = 0;
   *end_nonce_ptr = 0xffffffffU;
}

void verus_build_extraheader(struct work *g_work, struct stratum_ctx *sctx)
{
   size_t xnonce1_size = sctx->xnonce1_size;
   unsigned char *nonce_bytes = (unsigned char*)&g_work->data[27];

   memset(g_work->data, 0, sizeof(g_work->data));
   g_work->data[0] = le32dec(sctx->job.version);
   for (int i = 0; i < 8; i++)
      g_work->data[1 + i] = le32dec(sctx->job.prevhash + i * 4);

   if (sctx->job.coinbase_size >= 64)
   {
      memcpy(&g_work->data[9], sctx->job.coinbase, 32);
      memcpy(&g_work->data[17], sctx->job.coinbase + 32, 32);
   }

   g_work->data[VERUS_NTIME_INDEX] = le32dec(sctx->job.ntime);
   g_work->data[VERUS_NBITS_INDEX] = le32dec(sctx->job.nbits);

   if (xnonce1_size > 32)
      xnonce1_size = 32;
   if (sctx->xnonce1 && xnonce1_size)
      memcpy(nonce_bytes, sctx->xnonce1, xnonce1_size);

   g_work->xnonce2_len = 32 - xnonce1_size;
   g_work->xnonce2 = (unsigned char*)realloc(g_work->xnonce2,
                                             g_work->xnonce2_len);
   if (g_work->xnonce2_len)
      memcpy(g_work->xnonce2, nonce_bytes + xnonce1_size,
             g_work->xnonce2_len);

   g_work->data[35] = 0x80;
   memcpy(g_work->solution, sctx->job.verus_solution, VERUS_SOLUTION_BYTES);

   double pool_diff = sctx->job.verus_have_target
                    ? verus_diff_from_pool_target(sctx->job.verus_target)
                    : (sctx->job.diff > 0.0 ? sctx->job.diff : 1.0);
   g_work->targetdiff = pool_diff;
   verus_diff_to_target_equi(g_work->target, pool_diff * verus_mining_factor());
}

void verus_build_stratum_request(char *req, struct work *work,
                                 struct stratum_ctx *sctx)
{
   (void)sctx;
   char timehex[9] = { 0 };
   char noncestr[65] = { 0 };
   char solhex[(VERUS_SUBMIT_SOL_BYTES * 2) + 1] = { 0 };
   char restore[(64 * 2) + 1] = { 0 };
   size_t xnonce1_size;
   size_t nonce_len;
   unsigned char *nonce;
   int idnonce = work->submit_nonce_id;

   if (idnonce < 0 || idnonce >= MAX_NONCES)
      idnonce = 0;

   work->data[VERUS_NONCE_INDEX] = work->nonces[idnonce];
   nonce = (unsigned char*)(&work->data[27]);
   xnonce1_size = 32 - work->xnonce2_len;
   if (xnonce1_size > 32)
      xnonce1_size = 32;
   nonce_len = 32 - xnonce1_size;

   cbin2hex(noncestr, (const char*)(nonce + xnonce1_size), nonce_len);
   cbin2hex(solhex, (const char*)work->extra, VERUS_SUBMIT_SOL_BYTES);
   cbin2hex(restore, (const char*)&work->solution[8], 64);
   memcpy(&solhex[6 + 16], restore, 64 * 2);

   snprintf(timehex, sizeof(timehex), "%08x",
            bswap_32(work->data[VERUS_NTIME_INDEX]));

   snprintf(req, JSON_BUF_LEN,
            "{\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\","
            "\"%s\",\"%s\",\"%s\"],\"id\":4}",
            rpc_user, work->job_id ? work->job_id : "", timehex,
            noncestr, solhex);
}

int verus_scanhash(struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr)
{
   (void)max_nonce;
   unsigned long done = 0;
   int hits;
   int thr_id = mythr->id;

   work->valid_nonces = 0;
   work->submit_nonce_id = 0;

   hits = scanhash_verus(thr_id, work, VERUS_SCAN_WINDOW, &done);
   *hashes_done = done;

   if (hits > 0 && work->valid_nonces > 0 && !opt_benchmark)
   {
      work->submit_nonce_id = 0;
      work->data[VERUS_NONCE_INDEX] = work->nonces[0];
      submit_solution(work, work->target, mythr);
   }

   return 0;
}

bool register_verus_algo(algo_gate_t *gate)
{
   opt_target_factor = 1.0;
   gate->scanhash = (void*)&verus_scanhash;
   gate->get_new_work = (void*)&verus_get_new_work;
   gate->build_extraheader = (void*)&verus_build_extraheader;
   gate->build_stratum_request = (void*)&verus_build_stratum_request;
   gate->optimizations = AES_OPT | NEON_OPT | SSE2_OPT;
   gate->ntime_index = VERUS_NTIME_INDEX;
   gate->nbits_index = VERUS_NBITS_INDEX;
   gate->nonce_index = VERUS_NONCE_INDEX;
   gate->work_cmp_size = 35 * sizeof(uint32_t);
   return true;
}
