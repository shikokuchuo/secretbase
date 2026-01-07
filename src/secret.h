// secretbase - header file ----------------------------------------------------

#ifndef SECRETBASE_H
#define SECRETBASE_H

#include <stdint.h>
#include <stdlib.h>
#ifndef R_NO_REMAP
#define R_NO_REMAP
#endif
#ifndef STRICT_R_HEADERS
#define STRICT_R_HEADERS
#endif
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Visibility.h>

#ifdef WORDS_BIGENDIAN
# define MBEDTLS_IS_BIG_ENDIAN 1
#else
# define MBEDTLS_IS_BIG_ENDIAN 0
#endif

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL -1
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER -2

#if defined(__GNUC__) && (!defined(__ARMCC_VERSION) || \
__ARMCC_VERSION >= 6000000)
#define MBEDTLS_CT_ASM
#endif

// secretbase - byte order helpers from Mbed TLS ------------------------------

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4, 8)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif
#if __GNUC_PREREQ(4, 3)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif
#endif

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap16) && !defined(MBEDTLS_BSWAP16)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif
#if __has_builtin(__builtin_bswap32) && !defined(MBEDTLS_BSWAP32)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#endif
#if __has_builtin(__builtin_bswap64) && !defined(MBEDTLS_BSWAP64)
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif
#endif

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
  return (x & 0x00ff) << 8 |
         (x & 0xff00) >> 8;
}
#define MBEDTLS_BSWAP16 mbedtls_bswap16
#endif

#if !defined(MBEDTLS_BSWAP32)
static inline uint32_t mbedtls_bswap32(uint32_t x) {
  return (x & 0x000000ff) << 24 |
         (x & 0x0000ff00) <<  8 |
         (x & 0x00ff0000) >>  8 |
         (x & 0xff000000) >> 24;
}
#define MBEDTLS_BSWAP32 mbedtls_bswap32
#endif

#if !defined(MBEDTLS_BSWAP64)
static inline uint64_t mbedtls_bswap64(uint64_t x) {
  return (x & 0x00000000000000ffULL) << 56 |
         (x & 0x000000000000ff00ULL) << 40 |
         (x & 0x0000000000ff0000ULL) << 24 |
         (x & 0x00000000ff000000ULL) <<  8 |
         (x & 0x000000ff00000000ULL) >>  8 |
         (x & 0x0000ff0000000000ULL) >> 24 |
         (x & 0x00ff000000000000ULL) >> 40 |
         (x & 0xff00000000000000ULL) >> 56;
}
#define MBEDTLS_BSWAP64 mbedtls_bswap64
#endif

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint16_t mbedtls_get_unaligned_uint16(const void *p) {
  uint16_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint16(void *p, uint16_t x) {
  memcpy(p, &x, sizeof(x));
}

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

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint64_t mbedtls_get_unaligned_uint64(const void *p) {
  uint64_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint64(void *p, uint64_t x) {
  memcpy(p, &x, sizeof(x));
}

#define MBEDTLS_GET_UINT16_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? mbedtls_get_unaligned_uint16((data) + (offset)) \
   : MBEDTLS_BSWAP16(mbedtls_get_unaligned_uint16((data) + (offset))))

#define MBEDTLS_PUT_UINT16_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      mbedtls_put_unaligned_uint16((data) + (offset), (uint16_t) (n)); \
    else \
      mbedtls_put_unaligned_uint16((data) + (offset), MBEDTLS_BSWAP16((uint16_t) (n))); \
  }

#define MBEDTLS_GET_UINT32_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? mbedtls_get_unaligned_uint32((data) + (offset)) \
   : MBEDTLS_BSWAP32(mbedtls_get_unaligned_uint32((data) + (offset))))

#define MBEDTLS_PUT_UINT32_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      mbedtls_put_unaligned_uint32((data) + (offset), (uint32_t) (n)); \
    else \
      mbedtls_put_unaligned_uint32((data) + (offset), MBEDTLS_BSWAP32((uint32_t) (n))); \
  }

#define MBEDTLS_GET_UINT64_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? mbedtls_get_unaligned_uint64((data) + (offset)) \
   : MBEDTLS_BSWAP64(mbedtls_get_unaligned_uint64((data) + (offset))))

#define MBEDTLS_PUT_UINT64_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      mbedtls_put_unaligned_uint64((data) + (offset), (uint64_t) (n)); \
    else \
      mbedtls_put_unaligned_uint64((data) + (offset), MBEDTLS_BSWAP64((uint64_t) (n))); \
  }

// secretbase - internals ------------------------------------------------------

typedef struct mbedtls_sha3_context {
  uint64_t state[25];
  uint8_t index;
  uint8_t id;
  uint16_t r;
  uint16_t olen;
  uint8_t xor_byte;
  uint16_t max_block_size;
} mbedtls_sha3_context;

typedef struct mbedtls_sha256_context {
  unsigned char buffer[64];
  uint32_t total[2];
  uint32_t state[8];
} mbedtls_sha256_context;

typedef struct CSipHash {
  uint64_t v0;
  uint64_t v1;
  uint64_t v2;
  uint64_t v3;
  uint64_t padding;
  size_t n_bytes;
} CSipHash;

typedef struct secretbase_context {
  int skip;
  void *ctx;
} secretbase_context;

typedef struct nano_buf_s {
  unsigned char *buf;
  size_t len;
  size_t cur;
} nano_buf;

#define SB_SHA256_SIZE 32
#define SB_SHA256_BLK 64
#define SB_SIPH_SIZE 8
#define SB_SKEY_SIZE 16
#define SB_R_SERIAL_VER 3
#define SB_SERIAL_HEADERS 6
#define SB_BUF_SIZE 65536
#define SB_INIT_BUFSIZE 4096
#define SB_SERIAL_THR 134217728

#ifndef NO_ATTRIB
#define NO_ATTRIB(x) (ATTRIB(x) == R_NilValue)
#endif
#define SB_DATAPTR(x) (void *) DATAPTR_RO(x)
#define SB_LOGICAL(x) *(int *) DATAPTR_RO(x)
#define SB_ASSERT_LOGICAL(x) if (TYPEOF(x) != LGLSXP)          \
Rf_error("'convert' must be a logical value")
#define SB_ASSERT_STR(x) if (TYPEOF(x) != STRSXP)              \
Rf_error("'file' must be a character string")
#define NANO_ALLOC(x, sz)                                      \
(x)->buf = malloc(sz);                                         \
if ((x)->buf == NULL) Rf_error("memory allocation failed");    \
(x)->len = sz;                                                 \
(x)->cur = 0
#define NANO_INIT(x, ptr, sz)                                  \
(x)->buf = ptr;                                                \
(x)->len = 0;                                                  \
(x)->cur = sz
#define NANO_FREE(x) if (x.len) free(x.buf)
#define CHECK_ERROR(x, y) if (x) { free(y);                    \
Rf_error("write buffer insufficient"); }
#define ERROR_OUT(x) if (x->len) free(x->buf);                 \
Rf_error("serialization exceeds max length of raw vector")
#define ERROR_FOPEN(x) Rf_error("file not found or no read permission at '%s'", x)
#define ERROR_FREAD(x) Rf_error("file read error at '%s'", x)

void sb_clear_buffer(void *, const size_t);
SEXP sb_hash_sexp(unsigned char *, const size_t, const int);
nano_buf sb_any_buf(const SEXP);
SEXP sb_raw_char(unsigned char *, const size_t);
SEXP sb_unserialize(unsigned char *, const size_t);
void sb_sha256_raw(const void *, size_t, void *);

SEXP secretbase_base64enc(SEXP, SEXP);
SEXP secretbase_base64dec(SEXP, SEXP);
SEXP secretbase_base58enc(SEXP, SEXP);
SEXP secretbase_base58dec(SEXP, SEXP);
SEXP secretbase_sha3(SEXP, SEXP, SEXP);
SEXP secretbase_sha3_file(SEXP, SEXP, SEXP);
SEXP secretbase_shake256(SEXP, SEXP, SEXP);
SEXP secretbase_shake256_file(SEXP, SEXP, SEXP);
SEXP secretbase_keccak(SEXP, SEXP, SEXP);
SEXP secretbase_keccak_file(SEXP, SEXP, SEXP);
SEXP secretbase_sha256(SEXP, SEXP, SEXP);
SEXP secretbase_sha256_file(SEXP, SEXP, SEXP);
SEXP secretbase_siphash13(SEXP, SEXP, SEXP);
SEXP secretbase_siphash13_file(SEXP, SEXP, SEXP);

#endif
