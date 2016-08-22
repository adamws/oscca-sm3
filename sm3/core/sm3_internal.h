#ifndef OSCCA_SM3_INTERNAL_H
#define OSCCA_SM3_INTERNAL_H

uint16_t sm3_transform_block(uint32_t* digest, uint8_t* input);

#define SM3_PAD_SIZE (56)

#define T0 (0x79cc4519)
#define T1 (0x7a879d8a)

#define FF0(x, y, z) (( x ) ^ ( y ) ^ ( z ))
#define FF1(x, y, z) ((( x ) & ( y )) | (( x ) & ( z )) | (( y ) & ( z )))
#define GG0(x, y, z) (( x ) ^ ( y ) ^ ( z ))
#define GG1(x, y, z) ((( x ) & ( y )) | (( ~x ) & ( z )))

static inline uint32_t rotleft(uint32_t x, uint8_t y)
{
  return (x << y) | (x >> (32 - (y & 0x3F)));
}

static inline uint32_t p0(uint32_t x)
{
  return x ^ rotleft(x, 9) ^ rotleft(x, 17);
}

static inline uint32_t p1(uint32_t x)
{
  return (x ^ rotleft(x, 15) ^ rotleft(x, 23));
}

static inline uint32_t min(uint32_t x, uint32_t y)
{
  return (x > y) ? y : x;
}

static inline uint32_t swap(uint32_t x)
{
  return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | (x << 24);
}

static inline void addwc(uint32_t* hi, uint32_t* lo, uint32_t val)
{
  *lo += val;
  *hi += *lo < val;
}

#endif
