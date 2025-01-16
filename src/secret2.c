// Copyright (C) 2024-2025 Hibiki AI Limited <info@hibiki-ai.com>
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

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint32_t mbedtls_get_unaligned_uint32(const void *p) {
  uint32_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint32(void *p, uint32_t x) {
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

static inline void mbedtls_xor(unsigned char *r,
                               const unsigned char *a,
                               const unsigned char *b,
                               size_t n)
{
  size_t i = 0;
  for (; i < n; i++) {
    r[i] = a[i] ^ b[i];
  }
}

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
  
  if (ctx->total[0] < (uint32_t) ilen) { ctx->total[1]++; }
  
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

static inline void hash_bytes(R_outpstream_t stream, void *src, int len) {
  
  secretbase_context *sctx = (secretbase_context *) stream->data;
  sctx->skip ? (void) sctx->skip-- :
    mbedtls_sha256_update((mbedtls_sha256_context *) sctx->ctx, (uint8_t *) src, (size_t) len);
  
}

static void hash_file(mbedtls_sha256_context *ctx, const SEXP x) {
  
  SB_ASSERT_STR(x);
  const char *file = R_ExpandFileName(CHAR(*STRING_PTR_RO(x)));
  unsigned char buf[SB_BUF_SIZE];
  FILE *f;
  size_t cur;
  
  if ((f = fopen(file, "rb")) == NULL)
    ERROR_FOPEN(file);
  
  setbuf(f, NULL);
  
  while ((cur = fread(buf, sizeof(char), SB_BUF_SIZE, f))) {
    mbedtls_sha256_update(ctx, buf, cur);
  }
  
  if (ferror(f)) {
    fclose(f);
    ERROR_FREAD(file);
  }
  fclose(f);
  
}

static void hash_object(mbedtls_sha256_context *ctx, const SEXP x) {
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && !ANY_ATTRIB(x)) {
      const char *s = CHAR(*STRING_PTR_RO(x));
      mbedtls_sha256_update(ctx, (uint8_t *) s, strlen(s));
      return;
    }
    break;
  case RAWSXP:
    if (!ANY_ATTRIB(x)) {
      mbedtls_sha256_update(ctx, (uint8_t *) DATAPTR_RO(x), (size_t) XLENGTH(x));
      return;
    }
    break;
  }
  
  secretbase_context sctx;
  sctx.skip = SB_SERIAL_HEADERS;
  sctx.ctx = ctx;
  
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

static SEXP secretbase_sha256_impl(const SEXP x, const SEXP key, const SEXP convert,
                                   void (*const hash_func)(mbedtls_sha256_context *, SEXP)) {
  
  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  unsigned char buf[SB_SHA256_SIZE];
  
  if (key == R_NilValue) {
    
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx);
    hash_func(&ctx, x);
    mbedtls_sha256_finish(&ctx, buf);
    sb_clear_buffer(&ctx, sizeof(mbedtls_sha256_context));
    
  } else {
    
    size_t klen;
    unsigned char sum[SB_SHA256_BLK], ipad[SB_SHA256_BLK], opad[SB_SHA256_BLK];
    mbedtls_sha256_context ctx;
    memset(sum, 0, SB_SHA256_BLK);
    unsigned char *data;
    
    switch (TYPEOF(key)) {
    case STRSXP:
      data = (unsigned char *) (XLENGTH(key) ? CHAR(*STRING_PTR_RO(key)) : "");
      klen = strlen((char *) data);
      break;
    case RAWSXP:
      data = (unsigned char *) DATAPTR_RO(key);
      klen = XLENGTH(key);
      break;
    default:
      Rf_error("'key' must be a character string, raw vector or NULL");
    }
    
    if (klen > SB_SHA256_BLK) {
      mbedtls_sha256_init(&ctx);
      mbedtls_sha256_starts(&ctx);
      hash_object(&ctx, key);
      mbedtls_sha256_finish(&ctx, sum);
    } else {
      memcpy(sum, data, klen);
    }
    
    memset(ipad, 0x36, SB_SHA256_BLK);
    memset(opad, 0x5C, SB_SHA256_BLK);
    
    mbedtls_xor(ipad, ipad, sum, SB_SHA256_BLK);
    mbedtls_xor(opad, opad, sum, SB_SHA256_BLK);
    
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx);
    mbedtls_sha256_update(&ctx, ipad, SB_SHA256_BLK);
    hash_func(&ctx, x);
    mbedtls_sha256_finish(&ctx, buf);
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx);
    mbedtls_sha256_update(&ctx, opad, SB_SHA256_BLK);
    mbedtls_sha256_update(&ctx, buf, SB_SHA256_SIZE);
    mbedtls_sha256_finish(&ctx, buf);
    sb_clear_buffer(&ctx, sizeof(mbedtls_sha256_context));

  }
  
  return sb_hash_sexp(buf, SB_SHA256_SIZE, conv);
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_sha256(SEXP x, SEXP key, SEXP convert) {
  
  return secretbase_sha256_impl(x, key, convert, hash_object);
  
}

SEXP secretbase_sha256_file(SEXP x, SEXP key, SEXP convert) {
  
  return secretbase_sha256_impl(x, key, convert, hash_file);
  
}
