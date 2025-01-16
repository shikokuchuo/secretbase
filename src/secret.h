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

// secretbase - header file ----------------------------------------------------

#ifndef SECRETBASE_H
#define SECRETBASE_H

#include <stdint.h>
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

#ifndef ANY_ATTRIB
#define ANY_ATTRIB(x) (ATTRIB(x) != R_NilValue)
#endif
#define SB_DATAPTR(x) (void *) DATAPTR_RO(x)
#define SB_LOGICAL(x) *(int *) DATAPTR_RO(x)
#define SB_ASSERT_LOGICAL(x) if (TYPEOF(x) != LGLSXP)          \
Rf_error("'convert' must be a logical value")
#define SB_ASSERT_STR(x) if (TYPEOF(x) != STRSXP)              \
Rf_error("'file' must be a character string")
#define NANO_ALLOC(x, sz)                                      \
(x)->buf = R_Calloc(sz, unsigned char);                        \
(x)->len = sz;                                                 \
(x)->cur = 0
#define NANO_INIT(x, ptr, sz)                                  \
(x)->buf = ptr;                                                \
(x)->len = 0;                                                  \
(x)->cur = sz
#define NANO_FREE(x) if (x.len) R_Free(x.buf)
#define CHECK_ERROR(x, y) if (x) { R_Free(y);                  \
Rf_error("write buffer insufficient"); }
#define ERROR_OUT(x) if (x->len) R_Free(x->buf);               \
Rf_error("serialization exceeds max length of raw vector")
#define ERROR_CONVERT(x) R_Free(x);                            \
Rf_error("data could not be converted to a character string")
#define ERROR_FOPEN(x) Rf_error("file not found or no read permission at '%s'", x)
#define ERROR_FREAD(x) Rf_error("file read error at '%s'", x)

void sb_clear_buffer(void *, const size_t);
SEXP sb_hash_sexp(unsigned char *, const size_t, const int);

SEXP secretbase_base64enc(SEXP, SEXP);
SEXP secretbase_base64dec(SEXP, SEXP);
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
