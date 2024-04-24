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

// secretbase - header file ----------------------------------------------------

#ifndef SECRETBASE_H
#define SECRETBASE_H

#include <stdint.h>
#define R_NO_REMAP
#define STRICT_R_HEADERS
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Visibility.h>

#define SB_R_SERIAL_VER 3
#define SB_SERIAL_HEADERS 6
#define SB_BUF_SIZE 4096

#ifdef WORDS_BIGENDIAN
# define MBEDTLS_IS_BIG_ENDIAN 1
#else
# define MBEDTLS_IS_BIG_ENDIAN 0
#endif

#define SB_SHA256_SIZE 32
#define SB_SHA256_BLK 64
#define SB_SIPH_SIZE 8
#define SB_SKEY_SIZE 16

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

typedef struct secretbase_sha3_context {
  int skip;
  mbedtls_sha3_context *ctx;
} secretbase_sha3_context;

typedef struct secretbase_sha256_context {
  int skip;
  mbedtls_sha256_context *ctx;
} secretbase_sha256_context;

typedef struct secretbase_siphash_context {
  int skip;
  CSipHash *ctx;
} secretbase_siphash_context;

void clear_buffer(void *, size_t);
SEXP hash_to_sexp(unsigned char *, size_t, int);

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
