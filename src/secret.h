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

typedef enum {
  MBEDTLS_SHA3_SHAKE256 = 0,
  MBEDTLS_SHA3_224,
  MBEDTLS_SHA3_256,
  MBEDTLS_SHA3_384,
  MBEDTLS_SHA3_512
} mbedtls_sha3_id;

typedef struct mbedtls_sha3_family_functions {
  mbedtls_sha3_id id;
  uint16_t r;
  uint16_t olen;
  uint8_t xor_byte;
} mbedtls_sha3_family_functions;

typedef struct mbedtls_sha3_context {
  uint64_t state[25];
  uint8_t index;
  uint8_t id;
  uint16_t r;
  uint16_t olen;
  uint8_t xor_byte;
  uint16_t max_block_size;
} mbedtls_sha3_context;

typedef struct secretbase_context {
  int skip;
  mbedtls_sha3_context *ctx;
} secretbase_context;

SEXP secretbase_sha3(SEXP, SEXP, SEXP);
SEXP secretbase_sha3_file(SEXP, SEXP, SEXP);

#endif
