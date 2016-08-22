#include <stdint.h>
#include <sm3_internal.h>

uint16_t sm3_transform_block(uint32_t* digest, uint8_t* input)
{
  uint32_t W[68];
  uint32_t W1[64];

  for(uint8_t j = 0, i = 0; j < 64; ++j, i += 4)
  {
    W[j] = (input[i] << 24) | (input[i + 1] << 16) | (input[i + 2] << 8) | input[i + 3];
  }

  for(uint8_t j = 16; j < 68; ++j)
  {
    uint32_t wj3 = W[j - 3];
    uint32_t r15 = rotleft(wj3, 15);
    uint32_t wj13 = W[j - 13];
    uint32_t r7 = rotleft(wj13, 7);
    W[j] = p1(W[j - 16] ^ W[j - 9] ^ r15) ^ r7 ^ W[j - 6];
  }

  for(uint8_t j = 0; j < 64; ++j)
  {
    W1[j] = W[j] ^ W[j + 4];
  }

  uint32_t A = digest[0];
  uint32_t B = digest[1];
  uint32_t C = digest[2];
  uint32_t D = digest[3];
  uint32_t E = digest[4];
  uint32_t F = digest[5];
  uint32_t G = digest[6];
  uint32_t H = digest[7];

  for(uint8_t j = 0; j < 16; ++j)
  {
    uint32_t a12 = rotleft(A, 12);
    uint32_t s1  = a12 + E + rotleft(T0, j);
    uint32_t SS1 = rotleft(s1, 7);
    uint32_t SS2 = SS1 ^ a12;
    uint32_t TT1 = FF0(A, B, C) + D + SS2 + W1[j];
    uint32_t TT2 = GG0(E, F, G) + H + SS1 + W[j];

    D = C;
    C = rotleft(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotleft(F, 19);
    F = E;
    E = p0(TT2);
  }

  for(uint8_t j = 16; j < 64; ++j)
  {
    uint32_t a12 = rotleft(A, 12);
    uint32_t s1  = a12 + E + rotleft(T1, (j % 32));
    uint32_t SS1 = rotleft(s1, 7);
    uint32_t SS2 = SS1 ^ a12;
    uint32_t TT1 = FF1(A, B, C) + D + SS2 + W1[j];
    uint32_t TT2 = GG1(E, F, G) + H + SS1 + W[j];

    D = C;
    C = rotleft(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = rotleft(F, 19);
    F = E;
    E = p0(TT2);
  }

  digest[0] ^= A;
  digest[1] ^= B;
  digest[2] ^= C;
  digest[3] ^= D;
  digest[4] ^= E;
  digest[5] ^= F;
  digest[6] ^= G;
  digest[7] ^= H;

  return 0;
}

