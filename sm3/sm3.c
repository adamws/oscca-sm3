#include <stdint.h>
#include <string.h>

#include <sm3.h>
#include <sm3_internal.h>

uint16_t sm3_init(sm3_t* ctx)
{
  ctx->digest[0] = 0x7380166F;
  ctx->digest[1] = 0x4914B2B9;
  ctx->digest[2] = 0x172442D7;
  ctx->digest[3] = 0xDA8A0600;
  ctx->digest[4] = 0xA96F30BC;
  ctx->digest[5] = 0x163138AA;
  ctx->digest[6] = 0xE38DEE4D;
  ctx->digest[7] = 0xB0FB0E4E;

  for(uint8_t j = 0; j < (SM3_BLOCK_SIZE / sizeof(uint32_t)); ++j)
  {
    ctx->workspace[j] = 0;
  }
  ctx->workspace_used = 0;
  ctx->processed_high = 0;
  ctx->processed_low = 0;

  return 0;
}

uint16_t sm3_update(sm3_t* ctx, uint8_t* input, uint32_t length)
{
  uint8_t* local = (uint8_t*)ctx->workspace;
  uint16_t ret_val = 0;

  while(length)
  {
    uint32_t add = min(length, SM3_BLOCK_SIZE - ctx->workspace_used);

    memcpy(&local[ctx->workspace_used], input, add);

    ctx->workspace_used += add;
    input += add;
    length -= add;

    if(ctx->workspace_used == SM3_BLOCK_SIZE)
    {
      ret_val = sm3_transform_block(ctx->digest, local);
      addwc(&ctx->processed_high, &ctx->processed_low, SM3_BLOCK_SIZE);
      ctx->workspace_used = 0;
    }
  }

  return ret_val;
}

uint16_t sm3_finalize(sm3_t* ctx, uint8_t* output)
{
  uint16_t ret_val = 0;
  uint8_t* local = (uint8_t*)ctx->workspace;
  addwc(&ctx->processed_high, &ctx->processed_low, ctx->workspace_used);

  local[ctx->workspace_used++] = 0x80;

  if(ctx->workspace_used > SM3_PAD_SIZE)
  {
    memset(&local[ctx->workspace_used], 0, SM3_BLOCK_SIZE - ctx->workspace_used);
    ctx->workspace_used += SM3_BLOCK_SIZE - ctx->workspace_used;

    ret_val = sm3_transform_block(ctx->digest, local);
    ctx->workspace_used = 0;
  }

  memset(&local[ctx->workspace_used], 0, SM3_PAD_SIZE - ctx->workspace_used);

  uint32_t processed_bits_high = swap(ctx->processed_high << 3 | ((ctx->processed_low >> 29) & 0x07));
  memcpy(&local[SM3_PAD_SIZE], &processed_bits_high, sizeof(uint32_t));

  uint32_t processed_bits_low = swap(ctx->processed_low << 3);
  memcpy(&local[SM3_PAD_SIZE + sizeof(uint32_t)], &processed_bits_low, sizeof(uint32_t));

  ret_val = sm3_transform_block(ctx->digest, local);

  uint8_t* temp = output;
  for(uint8_t j = 0; j < (SM3_DIGEST_SIZE / sizeof(uint32_t)); ++j)
  {
    *temp++ = (ctx->digest[j]) >> 24;
    *temp++ = (ctx->digest[j]) >> 16;
    *temp++ = (ctx->digest[j]) >> 8;
    *temp++ = (ctx->digest[j]);
    ctx->digest[j] = 0;
    ctx->workspace[j] = 0;
  }
  for(uint8_t j = 8; j < (SM3_BLOCK_SIZE / sizeof(uint32_t)); ++j)
  {
    ctx->workspace[j] = 0;
  }
  ctx->workspace_used = 0;
  ctx->processed_low = 0;
  ctx->processed_high = 0;

  return ret_val;
}
