// Copyright (C) 2024 Hibiki AI Limited <info@hibiki-ai.com>
//
// This file is part of secretbase.
//
// secretbase is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// secretbase is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// secretbase. If not, see <https://www.gnu.org/licenses/>.

// secretbase ------------------------------------------------------------------

#include "secret.h"

// secretbase - sha3 implementation --------------------------------------------

/*
 *  FIPS-202 compliant SHA3 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  The SHA-3 Secure Hash Standard was published by NIST in 2015.
 *
 *  https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf
 */

static mbedtls_sha3_family_functions sha3_families[] = {
  { MBEDTLS_SHA3_SHAKE256, 1088,   0, 0x1F },
  { MBEDTLS_SHA3_224,      1152, 224, 0x06 },
  { MBEDTLS_SHA3_256,      1088, 256, 0x06 },
  { MBEDTLS_SHA3_384,       832, 384, 0x06 },
  { MBEDTLS_SHA3_512,       576, 512, 0x06 }
};

static const uint64_t rc[24] = {
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

static const uint8_t rho[24] = {
  1, 62, 28, 27, 36, 44,  6, 55, 20,
  3, 10, 43, 25, 39, 41, 45, 15,
  21,  8, 18,  2, 61, 56, 14
};

static const uint8_t pi[24] = {
  10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6, 1,
};

#define ROT64( x , y ) ( ( ( x ) << ( y ) ) | ( ( x ) >> ( 64U - ( y ) ) ) )
#define ABSORB( ctx, idx, v ) do { ctx->state[( idx ) >> 3] ^= ( ( uint64_t ) ( v ) ) << ( ( ( idx ) & 0x7 ) << 3 ); } while ( 0 )
#define SQUEEZE( ctx, idx ) ( ( uint8_t )( ctx->state[( idx ) >> 3] >> ( ( ( idx ) & 0x7 ) << 3 ) ) )
#define SWAP( x, y ) do { uint64_t tmp = ( x ); ( x ) = ( y ); ( y ) = tmp; } while ( 0 )

static void keccak_f1600(mbedtls_sha3_context *ctx) {
  
  uint64_t lane[5];
  uint64_t *s = ctx->state;
  int i;
  
  for (int round = 0; round < 24; round++) {
    
    uint64_t t;
    
    /* Theta */
    lane[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
    lane[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
    lane[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
    lane[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
    lane[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];
    
    t = lane[4] ^ ROT64( lane[1], 1 );
    s[0] ^= t; s[5] ^= t; s[10] ^= t; s[15] ^= t; s[20] ^= t;
    
    t = lane[0] ^ ROT64( lane[2], 1 );
    s[1] ^= t; s[6] ^= t; s[11] ^= t; s[16] ^= t; s[21] ^= t;
    
    t = lane[1] ^ ROT64( lane[3], 1 );
    s[2] ^= t; s[7] ^= t; s[12] ^= t; s[17] ^= t; s[22] ^= t;
    
    t = lane[2] ^ ROT64( lane[4], 1 );
    s[3] ^= t; s[8] ^= t; s[13] ^= t; s[18] ^= t; s[23] ^= t;
    
    t = lane[3] ^ ROT64( lane[0], 1 );
    s[4] ^= t; s[9] ^= t; s[14] ^= t; s[19] ^= t; s[24] ^= t;
    
    /* Rho */
    for ( i = 1; i < 25; i++ )
      s[i] = ROT64(s[i], rho[i-1]);
    
    /* Pi */
    t = s[1];
    for (i = 0; i < 24; i++)
      SWAP(s[pi[i]], t);
    
    /* Chi */
    lane[0] = s[0]; lane[1] = s[1]; lane[2] = s[2]; lane[3] = s[3]; lane[4] = s[4];
    s[0] ^= (~lane[1]) & lane[2];
    s[1] ^= (~lane[2]) & lane[3];
    s[2] ^= (~lane[3]) & lane[4];
    s[3] ^= (~lane[4]) & lane[0];
    s[4] ^= (~lane[0]) & lane[1];
    
    lane[0] = s[5]; lane[1] = s[6]; lane[2] = s[7]; lane[3] = s[8]; lane[4] = s[9];
    s[5] ^= (~lane[1]) & lane[2];
    s[6] ^= (~lane[2]) & lane[3];
    s[7] ^= (~lane[3]) & lane[4];
    s[8] ^= (~lane[4]) & lane[0];
    s[9] ^= (~lane[0]) & lane[1];
    
    lane[0] = s[10]; lane[1] = s[11]; lane[2] = s[12]; lane[3] = s[13]; lane[4] = s[14];
    s[10] ^= (~lane[1]) & lane[2];
    s[11] ^= (~lane[2]) & lane[3];
    s[12] ^= (~lane[3]) & lane[4];
    s[13] ^= (~lane[4]) & lane[0];
    s[14] ^= (~lane[0]) & lane[1];
    
    lane[0] = s[15]; lane[1] = s[16]; lane[2] = s[17]; lane[3] = s[18]; lane[4] = s[19];
    s[15] ^= (~lane[1]) & lane[2];
    s[16] ^= (~lane[2]) & lane[3];
    s[17] ^= (~lane[3]) & lane[4];
    s[18] ^= (~lane[4]) & lane[0];
    s[19] ^= (~lane[0]) & lane[1];
    
    lane[0] = s[20]; lane[1] = s[21]; lane[2] = s[22]; lane[3] = s[23]; lane[4] = s[24];
    s[20] ^= (~lane[1]) & lane[2];
    s[21] ^= (~lane[2]) & lane[3];
    s[22] ^= (~lane[3]) & lane[4];
    s[23] ^= (~lane[4]) & lane[0];
    s[24] ^= (~lane[0]) & lane[1];
    
    /* Iota */
    s[0] ^= rc[round];
  }
  
}

static void mbedtls_sha3_init(mbedtls_sha3_context *ctx) {

  memset(ctx, 0, sizeof(mbedtls_sha3_context));
  
}

static void mbedtls_sha3_starts(mbedtls_sha3_context *ctx, mbedtls_sha3_id id) {
  
  mbedtls_sha3_family_functions p = sha3_families[id];
  
  ctx->r = p.r;
  ctx->olen = p.olen / 8;
  ctx->xor_byte = p.xor_byte;
  ctx->max_block_size = ctx->r / 8;
  
}

static void mbedtls_sha3_update(mbedtls_sha3_context *ctx, const uint8_t *input, size_t ilen) {
  
  if (ilen == 0 || input == NULL)
    return;
  
  while (ilen-- > 0) {
    ABSORB(ctx, ctx->index, *input++);
    if ((ctx->index = (ctx->index + 1) % ctx->max_block_size) == 0)
      keccak_f1600(ctx);
  }
  
}

static void mbedtls_sha3_finish(mbedtls_sha3_context *ctx, uint8_t *output, size_t olen) {

  ABSORB(ctx, ctx->index, ctx->xor_byte);
  ABSORB(ctx, ctx->max_block_size - 1, 0x80);
  keccak_f1600(ctx);
  ctx->index = 0;
  
  while (olen-- > 0) {
    *output++ = SQUEEZE(ctx, ctx->index);
    if ((ctx->index = (ctx->index + 1) % ctx->max_block_size) == 0)
      keccak_f1600(ctx);
  }
  
}

// secretbase - sha256 implementation ------------------------------------------

/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

static uint32_t mbedtls_get_unaligned_uint32(const void *p) {
  uint32_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

static void mbedtls_put_unaligned_uint32(void *p, uint32_t x) {
  memcpy(p, &x, sizeof(x));
}

#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4, 8)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif /* __GNUC_PREREQ(4,8) */
#if __GNUC_PREREQ(4, 3)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif /* __GNUC_PREREQ(4,3) */
#endif /* defined(__GNUC__) && defined(__GNUC_PREREQ) */

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap16) && !defined(MBEDTLS_BSWAP16)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif /* __has_builtin(__builtin_bswap16) */
#if __has_builtin(__builtin_bswap32) && !defined(MBEDTLS_BSWAP32)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#endif /* __has_builtin(__builtin_bswap32) */
#if __has_builtin(__builtin_bswap64) && !defined(MBEDTLS_BSWAP64)
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif /* __has_builtin(__builtin_bswap64) */
#endif /* defined(__clang__) && defined(__has_builtin) */

#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 410000) && !defined(MBEDTLS_BSWAP32)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#endif
#define MBEDTLS_BSWAP32 __rev
#endif

#if defined(__IAR_SYSTEMS_ICC__)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#define MBEDTLS_BSWAP16(x) ((uint16_t) __rev16((uint32_t) (x)))
#define MBEDTLS_BSWAP32 __rev
#define MBEDTLS_BSWAP64 __revll
#endif
#endif

#if !defined(MBEDTLS_BSWAP16)
static inline uint16_t mbedtls_bswap16(uint16_t x) {
  return
  (x & 0x00ff) << 8 |
    (x & 0xff00) >> 8;
}
#define MBEDTLS_BSWAP16 mbedtls_bswap16
#endif /* !defined(MBEDTLS_BSWAP16) */

#if !defined(MBEDTLS_BSWAP32)
static inline uint32_t mbedtls_bswap32(uint32_t x) {
  return
  (x & 0x000000ff) << 24 |
    (x & 0x0000ff00) <<  8 |
    (x & 0x00ff0000) >>  8 |
    (x & 0xff000000) >> 24;
}
#define MBEDTLS_BSWAP32 mbedtls_bswap32
#endif /* !defined(MBEDTLS_BSWAP32) */

#if !defined(MBEDTLS_BSWAP64)
static inline uint64_t mbedtls_bswap64(uint64_t x) {
  return
  (x & 0x00000000000000ffULL) << 56 |
    (x & 0x000000000000ff00ULL) << 40 |
    (x & 0x0000000000ff0000ULL) << 24 |
    (x & 0x00000000ff000000ULL) <<  8 |
    (x & 0x000000ff00000000ULL) >>  8 |
    (x & 0x0000ff0000000000ULL) >> 24 |
    (x & 0x00ff000000000000ULL) >> 40 |
    (x & 0xff00000000000000ULL) >> 56;
}
#define MBEDTLS_BSWAP64 mbedtls_bswap64
#endif /* !defined(MBEDTLS_BSWAP64) */

#define MBEDTLS_GET_UINT32_BE(data, offset)                                \
((MBEDTLS_IS_BIG_ENDIAN)                                                   \
   ? mbedtls_get_unaligned_uint32((data) + (offset))                       \
   : MBEDTLS_BSWAP32(mbedtls_get_unaligned_uint32((data) + (offset)))      \
)

#define MBEDTLS_PUT_UINT32_BE(n, data, offset)                                        \
{                                                                                     \
  if (MBEDTLS_IS_BIG_ENDIAN)                                                          \
  {                                                                                   \
    mbedtls_put_unaligned_uint32((data) + (offset), (uint32_t) (n));                  \
  }                                                                                   \
  else                                                                                \
  {                                                                                   \
    mbedtls_put_unaligned_uint32((data) + (offset), MBEDTLS_BSWAP32((uint32_t) (n))); \
  }                                                                                   \
}                                                                                     \

static void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
  
  memset(ctx, 0, sizeof(mbedtls_sha256_context));
  
}

static void mbedtls_sha256_starts(mbedtls_sha256_context *ctx) {
  
  ctx->total[0] = 0;
  ctx->total[1] = 0;
  
  ctx->state[0] = 0x6A09E667;
  ctx->state[1] = 0xBB67AE85;
  ctx->state[2] = 0x3C6EF372;
  ctx->state[3] = 0xA54FF53A;
  ctx->state[4] = 0x510E527F;
  ctx->state[5] = 0x9B05688C;
  ctx->state[6] = 0x1F83D9AB;
  ctx->state[7] = 0x5BE0CD19;
  
}

static const uint32_t K[] =
  {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
  0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
  0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
  0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
  0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
  0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
  0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
  0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
  0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
  };

#define  SHR(x, n) (((x) & 0xFFFFFFFF) >> (n))
#define ROTR(x, n) (SHR(x, n) | ((x) << (32 - (n))))

#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^  SHR(x, 3))
#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^  SHR(x, 10))

#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))

#define F0(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define F1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

#define R(t)                                                        \
(                                                                   \
    local.W[t] = S1(local.W[(t) -  2]) + local.W[(t) -  7] +        \
      S0(local.W[(t) - 15]) + local.W[(t) - 16]                     \
)

#define P(a, b, c, d, e, f, g, h, x, K)                                      \
do                                                                           \
{                                                                            \
  local.temp1 = (h) + S3(e) + F1((e), (f), (g)) + (K) + (x);                 \
  local.temp2 = S2(a) + F0((a), (b), (c));                                   \
  (d) += local.temp1; (h) = local.temp1 + local.temp2;                       \
} while (0)

static void mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx,
                                            const unsigned char data[64]) {
  
  struct {
    uint32_t temp1, temp2, W[64];
    uint32_t A[8];
  } local;
  
  unsigned int i;
  
  for (i = 0; i < 8; i++) {
    local.A[i] = ctx->state[i];
  }
  
  for (i = 0; i < 16; i++) {
    local.W[i] = MBEDTLS_GET_UINT32_BE(data, 4 * i);
  }
  
  for (i = 0; i < 16; i += 8) {
    P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
      local.A[5], local.A[6], local.A[7], local.W[i+0], K[i+0]);
    P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3],
      local.A[4], local.A[5], local.A[6], local.W[i+1], K[i+1]);
    P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2],
      local.A[3], local.A[4], local.A[5], local.W[i+2], K[i+2]);
    P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1],
      local.A[2], local.A[3], local.A[4], local.W[i+3], K[i+3]);
    P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0],
      local.A[1], local.A[2], local.A[3], local.W[i+4], K[i+4]);
    P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7],
      local.A[0], local.A[1], local.A[2], local.W[i+5], K[i+5]);
    P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6],
      local.A[7], local.A[0], local.A[1], local.W[i+6], K[i+6]);
    P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5],
      local.A[6], local.A[7], local.A[0], local.W[i+7], K[i+7]);
  }
  
  for (i = 16; i < 64; i += 8) {
    P(local.A[0], local.A[1], local.A[2], local.A[3], local.A[4],
      local.A[5], local.A[6], local.A[7], R(i+0), K[i+0]);
    P(local.A[7], local.A[0], local.A[1], local.A[2], local.A[3],
      local.A[4], local.A[5], local.A[6], R(i+1), K[i+1]);
    P(local.A[6], local.A[7], local.A[0], local.A[1], local.A[2],
      local.A[3], local.A[4], local.A[5], R(i+2), K[i+2]);
    P(local.A[5], local.A[6], local.A[7], local.A[0], local.A[1],
      local.A[2], local.A[3], local.A[4], R(i+3), K[i+3]);
    P(local.A[4], local.A[5], local.A[6], local.A[7], local.A[0],
      local.A[1], local.A[2], local.A[3], R(i+4), K[i+4]);
    P(local.A[3], local.A[4], local.A[5], local.A[6], local.A[7],
      local.A[0], local.A[1], local.A[2], R(i+5), K[i+5]);
    P(local.A[2], local.A[3], local.A[4], local.A[5], local.A[6],
      local.A[7], local.A[0], local.A[1], R(i+6), K[i+6]);
    P(local.A[1], local.A[2], local.A[3], local.A[4], local.A[5],
      local.A[6], local.A[7], local.A[0], R(i+7), K[i+7]);
  }
  
  for (i = 0; i < 8; i++) {
    ctx->state[i] += local.A[i];
  }
  
}

static size_t mbedtls_internal_sha256_process_many(mbedtls_sha256_context *ctx,
                                                   const uint8_t *data,
                                                   size_t len) {
  
  size_t processed = 0;
  while (len >= 64) {
    mbedtls_internal_sha256_process(ctx, data);
    data += 64;
    len  -= 64;
    processed += 64;
  }
  
  return processed;
  
}

static void mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                                  const unsigned char *input,
                                  size_t ilen) {
  
  size_t fill;
  uint32_t left;
  
  if (ilen == 0) {
    return;
  }
  
  left = ctx->total[0] & 0x3F;
  fill = 64 - left;
  
  ctx->total[0] += (uint32_t) ilen;
  ctx->total[0] &= 0xFFFFFFFF;
  
  if (ctx->total[0] < (uint32_t) ilen) {
    ctx->total[1]++;
  }
  
  if (left && ilen >= fill) {
    memcpy((void *) (ctx->buffer + left), input, fill);
    mbedtls_internal_sha256_process(ctx, ctx->buffer);
    input += fill;
    ilen  -= fill;
    left = 0;
  }
  
  while (ilen >= 64) {
    size_t processed = mbedtls_internal_sha256_process_many(ctx, input, ilen);
    input += processed;
    ilen  -= processed;
  }
  
  if (ilen > 0) {
    memcpy((void *) (ctx->buffer + left), input, ilen);
  }
  
}

static void mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                                  unsigned char *output) {
  
  uint32_t used;
  uint32_t high, low;
  
  used = ctx->total[0] & 0x3F;
  
  ctx->buffer[used++] = 0x80;
  
  if (used <= 56) {
    memset(ctx->buffer + used, 0, 56 - used);
  } else {
    memset(ctx->buffer + used, 0, 64 - used);
    mbedtls_internal_sha256_process(ctx, ctx->buffer);
    memset(ctx->buffer, 0, 56);
  }

  high = (ctx->total[0] >> 29)
    | (ctx->total[1] <<  3);
  low  = (ctx->total[0] <<  3);
  
  MBEDTLS_PUT_UINT32_BE(high, ctx->buffer, 56);
  MBEDTLS_PUT_UINT32_BE(low,  ctx->buffer, 60);
  
  mbedtls_internal_sha256_process(ctx, ctx->buffer);

  MBEDTLS_PUT_UINT32_BE(ctx->state[0], output,  0);
  MBEDTLS_PUT_UINT32_BE(ctx->state[1], output,  4);
  MBEDTLS_PUT_UINT32_BE(ctx->state[2], output,  8);
  MBEDTLS_PUT_UINT32_BE(ctx->state[3], output, 12);
  MBEDTLS_PUT_UINT32_BE(ctx->state[4], output, 16);
  MBEDTLS_PUT_UINT32_BE(ctx->state[5], output, 20);
  MBEDTLS_PUT_UINT32_BE(ctx->state[6], output, 24);
  MBEDTLS_PUT_UINT32_BE(ctx->state[7], output, 28);

}

// secretbase - internals ------------------------------------------------------

static void * (*const volatile secure_memset)(void *, int, size_t) = memset;

static void clear_buffer(void *buf, size_t sz) {
  
  secure_memset(buf, 0, sz);
  
}

static void hash_bytes(R_outpstream_t stream, void *src, int len) {
  
  secretbase_context *sctx = (secretbase_context *) stream->data;
  sctx->skip ? (void) sctx->skip-- : sctx->update(sctx->ctx, (uint8_t *) src, (size_t) len);
  
}

void hash_file(const update_func update, void *ctx, const SEXP x) {
  
  if (TYPEOF(x) != STRSXP)
    Rf_error("'file' must be specified as a character string");
  const char *file = R_ExpandFileName(CHAR(STRING_ELT(x, 0)));
  unsigned char buf[SB_BUF_SIZE];
  FILE *f;
  size_t cur;
  
  if ((f = fopen(file, "rb")) == NULL)
    Rf_error("file not found or no read permission at '%s'", file);
  
  setbuf(f, NULL);
  
  while ((cur = fread(buf, sizeof(char), SB_BUF_SIZE, f))) {
    update(ctx, buf, cur);
  }
  
  if (ferror(f)) {
    fclose(f);
    Rf_error("file read error at '%s'", file);
  }
  fclose(f);
  
}

void hash_object(const update_func update, void *ctx, const SEXP x) {
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && ATTRIB(x) == R_NilValue) {
      const char *s = CHAR(STRING_ELT(x, 0));
      update(ctx, (uint8_t *) s, strlen(s));
      return;
    }
    break;
  case RAWSXP:
    if (ATTRIB(x) == R_NilValue) {
      update(ctx, (uint8_t *) STDVEC_DATAPTR(x), (size_t) XLENGTH(x));
      return;
    }
    break;
  }
  
  secretbase_context sctx;
  sctx.skip = SB_SERIAL_HEADERS;
  sctx.ctx = ctx;
  sctx.update = update;
  
  struct R_outpstream_st output_stream;
  R_InitOutPStream(
    &output_stream,
    (R_pstream_data_t) &sctx,
    R_pstream_xdr_format,
    SB_R_SERIAL_VER,
    NULL,
    hash_bytes,
    NULL,
    R_NilValue
  );
  R_Serialize(x, &output_stream);
  
}

SEXP hash_to_sexp(unsigned char *buf, size_t sz, int conv) {
  
  SEXP out;
  if (conv == 0) {
    out = Rf_allocVector(RAWSXP, sz);
    memcpy(STDVEC_DATAPTR(out), buf, sz);
  } else if (conv == 1) {
    char cbuf[sz + sz + 1];
    char *cptr = cbuf;
    for (size_t i = 0; i < sz; i++)
      cptr += snprintf(cptr, 3, "%.2x", buf[i]);
    PROTECT(out = Rf_allocVector(STRSXP, 1));
    SET_STRING_ELT(out, 0, Rf_mkCharLenCE(cbuf, (int) (sz + sz), CE_NATIVE));
    UNPROTECT(1);
  } else {
    out = Rf_allocVector(INTSXP, sz / sizeof(int));
    memcpy(STDVEC_DATAPTR(out), buf, sz);
  }
  
  return out;
  
}

static SEXP secretbase_sha3_impl(const SEXP x, const SEXP bits, const SEXP convert,
                                 const hash_func hfunc) {
  
  const int conv = LOGICAL(convert)[0];
  const int bt = Rf_asInteger(bits);
  if (bt < 8 || bt > (1 << 24))
    Rf_error("'bits' outside valid range of 8 to 2^24");
  const size_t sz = (size_t) (bt / 8);
  unsigned char buf[sz];
  
  mbedtls_sha3_id id = bt == 256 ? MBEDTLS_SHA3_256 :
    bt == 512 ? MBEDTLS_SHA3_512 :
    bt == 224 ? MBEDTLS_SHA3_224 :
    bt == 384 ? MBEDTLS_SHA3_384 :
    MBEDTLS_SHA3_SHAKE256;
  
  mbedtls_sha3_context ctx;
  mbedtls_sha3_init(&ctx);
  mbedtls_sha3_starts(&ctx, id);
  hfunc((update_func) mbedtls_sha3_update, &ctx, x);
  mbedtls_sha3_finish(&ctx, buf, sz);
  clear_buffer(&ctx, sizeof(mbedtls_sha3_context));
  
  return hash_to_sexp(buf, sz, conv);
  
}

static SEXP secretbase_sha256_impl(const SEXP x, const SEXP convert,
                                   const hash_func hfunc) {
  
  const int conv = LOGICAL(convert)[0];
  const size_t sz = 32;
  unsigned char buf[sz];
  
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx);
  hfunc((update_func) mbedtls_sha256_update, &ctx, x);
  mbedtls_sha256_finish(&ctx, buf);
  clear_buffer(&ctx, sizeof(mbedtls_sha256_context));
  
  return hash_to_sexp(buf, sz, conv);
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_sha3(SEXP x, SEXP bits, SEXP convert) {
  
  return secretbase_sha3_impl(x, bits, convert, hash_object);
  
}

SEXP secretbase_sha3_file(SEXP x, SEXP bits, SEXP convert) {
  
  return secretbase_sha3_impl(x, bits, convert, hash_file);
  
}

SEXP secretbase_sha256(SEXP x, SEXP convert) {
  
  return secretbase_sha256_impl(x, convert, hash_object);
  
}

SEXP secretbase_sha256_file(SEXP x, SEXP convert) {
  
  return secretbase_sha256_impl(x, convert, hash_file);
  
}
