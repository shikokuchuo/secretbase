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

// SipHash 2-4 Implementation --------------------------------------------------

#include "secret.h"

// secretbase - SipHash-1-3 implementation -------------------------------------

// Modified from the implementation at https://github.com/c-util/c-siphash.
// SipHash was created by Jean-Philippe Aumasson and Daniel J. Bernstein in 2012
// and the reference implementation was released as public domain software under
// the CC0.

//  This program is free software; you can redistribute it and/or modify it
//  under the terms of the GNU Lesser General Public License as published
//  by the Free Software Foundation; either version 2.1 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program; If not, see <http://www.gnu.org/licenses/>.
//  
//  COPYRIGHT: (ordered alphabetically)
//  Copyright (C) 2015-2022 Red Hat, Inc.
//
//  AUTHORS: (ordered alphabetically)
//    Daniele Nicolodi <daniele@grinta.net>
//    David Rheinsberg <david.rheinsberg@gmail.com>
//    Tom Gundersen <teg@jklm.no>

#include <stddef.h>
#include <stdint.h>

static inline uint64_t c_siphash_read_le64(const uint8_t bytes[8]) {
  return  ((uint64_t) bytes[0]) |
    (((uint64_t) bytes[1]) <<  8) |
    (((uint64_t) bytes[2]) << 16) |
    (((uint64_t) bytes[3]) << 24) |
    (((uint64_t) bytes[4]) << 32) |
    (((uint64_t) bytes[5]) << 40) |
    (((uint64_t) bytes[6]) << 48) |
    (((uint64_t) bytes[7]) << 56);
}

static inline uint64_t c_siphash_rotate_left(uint64_t x, uint8_t b) {
  return (x << b) | (x >> (64 - b));
}

static inline void c_siphash_sipround(CSipHash *state) {
  state->v0 += state->v1;
  state->v1 = c_siphash_rotate_left(state->v1, 13);
  state->v1 ^= state->v0;
  state->v0 = c_siphash_rotate_left(state->v0, 32);
  state->v2 += state->v3;
  state->v3 = c_siphash_rotate_left(state->v3, 16);
  state->v3 ^= state->v2;
  state->v0 += state->v3;
  state->v3 = c_siphash_rotate_left(state->v3, 21);
  state->v3 ^= state->v0;
  state->v2 += state->v1;
  state->v1 = c_siphash_rotate_left(state->v1, 17);
  state->v1 ^= state->v2;
  state->v2 = c_siphash_rotate_left(state->v2, 32);
}

void c_siphash_init(CSipHash *state) {

  *state = (CSipHash) {
    .v0 = 0x736f6d6570736575ULL,
    .v1 = 0x646f72616e646f6dULL,
    .v2 = 0x6c7967656e657261ULL,
    .v3 = 0x7465646279746573ULL,
    .padding = 0,
    .n_bytes = 0,
  };
}

static inline void c_siphash_append_N(CSipHash *state, const uint8_t *bytes, size_t n_bytes, unsigned N) {
  const uint8_t *end = bytes + n_bytes;
  size_t left = state->n_bytes & 7;
  uint64_t m;
  
  state->n_bytes += n_bytes;

  if (left > 0) {
    for ( ; bytes < end && left < 8; ++bytes, ++left)
      state->padding |= ((uint64_t) *bytes) << (left * 8);
    
    if (bytes == end && left < 8)
      return;
    
    state->v3 ^= state->padding;
    for (unsigned i = 0; i < N; i++)
      c_siphash_sipround(state);
    state->v0 ^= state->padding;
    
    state->padding = 0;
  }
  
  end -= (state->n_bytes % sizeof(uint64_t));

  for ( ; bytes < end; bytes += 8) {
    m = c_siphash_read_le64(bytes);
    
    state->v3 ^= m;
    for (unsigned i = 0; i < N; i++)
      c_siphash_sipround(state);
    state->v0 ^= m;
  }

  left = state->n_bytes & 7;
  switch (left) {
  case 7:
    state->padding |= ((uint64_t) bytes[6]) << 48;
  case 6:
    state->padding |= ((uint64_t) bytes[5]) << 40;
  case 5:
    state->padding |= ((uint64_t) bytes[4]) << 32;
  case 4:
    state->padding |= ((uint64_t) bytes[3]) << 24;
  case 3:
    state->padding |= ((uint64_t) bytes[2]) << 16;
  case 2:
    state->padding |= ((uint64_t) bytes[1]) <<  8;
  case 1:
    state->padding |= ((uint64_t) bytes[0]);
  case 0:
    break;
  }
}

static inline uint64_t c_siphash_finalize_NM(CSipHash *state, unsigned N, unsigned M) {
  uint64_t b;
  
  b = state->padding | (((uint64_t) state->n_bytes) << 56);
  
  state->v3 ^= b;
  for (unsigned i = 0; i < N; i++)
    c_siphash_sipround(state);
  state->v0 ^= b;
  
  state->v2 ^= 0xff;
  
  for (unsigned i = 0; i < M; i++)
    c_siphash_sipround(state);
  
  return state->v0 ^ state->v1 ^ state->v2  ^ state->v3;
}

static void c_siphash_append_13(CSipHash *state, const uint8_t *bytes, size_t n_bytes) {
  c_siphash_append_N(state, bytes, n_bytes, 1);
}

static uint64_t c_siphash_finalize_13(CSipHash *state) {
  return c_siphash_finalize_NM(state, 1, 3);
}

// secretbase - internals ------------------------------------------------------

static void hash_bytes(R_outpstream_t stream, void *src, int len) {
  
  secretbase_siphash_context *sctx = (secretbase_siphash_context *) stream->data;
  sctx->skip ? (void) sctx->skip-- : c_siphash_append_13(sctx->ctx, (uint8_t *) src, (size_t) len);
  
}

static void hash_file(CSipHash *ctx, const SEXP x) {
  
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
    c_siphash_append_13(ctx, buf, cur);
  }
  
  if (ferror(f)) {
    fclose(f);
    Rf_error("file read error at '%s'", file);
  }
  fclose(f);
  
}

static void hash_object(CSipHash *ctx, const SEXP x) {
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && ATTRIB(x) == R_NilValue) {
      const char *s = CHAR(STRING_ELT(x, 0));
      c_siphash_append_13(ctx, (uint8_t *) s, strlen(s));
      return;
    }
    break;
  case RAWSXP:
    if (ATTRIB(x) == R_NilValue) {
      c_siphash_append_13(ctx, (uint8_t *) STDVEC_DATAPTR(x), (size_t) XLENGTH(x));
      return;
    }
    break;
  }
  
  secretbase_siphash_context sctx;
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

static SEXP secretbase_siphash13_impl(const SEXP x, const SEXP convert,
                                      void (*const hash_func)(CSipHash *, SEXP)) {
  
  const int conv = LOGICAL(convert)[0];
  uint64_t hash;
  const size_t sz = 8;
  
  CSipHash ctx;
  c_siphash_init(&ctx);
  hash_func(&ctx, x);
  hash = c_siphash_finalize_13(&ctx);
  clear_buffer(&ctx, sizeof(CSipHash));
  
  return hash_to_sexp((unsigned char *) &hash, sz, conv);
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_siphash13(SEXP x, SEXP convert) {
  
  return secretbase_siphash13_impl(x, convert, hash_object);
  
}

SEXP secretbase_siphash13_file(SEXP x, SEXP convert) {
  
  return secretbase_siphash13_impl(x, convert, hash_file);
  
}
