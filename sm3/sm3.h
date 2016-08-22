#ifndef OSCCA_SM3_H
#define OSCCA_SM3_H

#define SM3_DIGEST_SIZE (32)
#define SM3_BLOCK_SIZE (64)

typedef struct sm3_t
{
  uint32_t digest[SM3_DIGEST_SIZE / sizeof(uint32_t)];
  uint32_t workspace[SM3_BLOCK_SIZE / sizeof(uint32_t)];
  uint32_t workspace_used;
  uint32_t processed_high;
  uint32_t processed_low;
} sm3_t;

uint16_t sm3_init(sm3_t* ctx);
uint16_t sm3_update(sm3_t* ctx, uint8_t* input, uint32_t length);
uint16_t sm3_finalize(sm3_t* ctx, uint8_t* output);

#endif
