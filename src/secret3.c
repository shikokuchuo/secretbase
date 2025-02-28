// secretbase ------------------------------------------------------------------

#include "secret.h"

// secretbase - SipHash implementation -----------------------------------------

/*  LICENSE:
 This project is dual-licensed under both the Apache License, Version
 2.0, and the GNU Lesser General Public License, Version 2.1+.
 
 AUTHORS-ASL:
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 
 COPYRIGHT: (ordered alphabetically)
 Copyright (C) 2015-2022 Red Hat, Inc.
 
 AUTHORS: (ordered alphabetically)
 Daniele Nicolodi <daniele@grinta.net>
 David Rheinsberg <david.rheinsberg@gmail.com>
 Tom Gundersen <teg@jklm.no>
 */

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

static void c_siphash_init(CSipHash *state, const uint8_t seed[16]) {
  
  uint64_t k0, k1;
  
  k0 = c_siphash_read_le64(seed);
  k1 = c_siphash_read_le64(seed + 8);

  *state = (CSipHash) {
    .v0 = 0x736f6d6570736575ULL ^ k0,
    .v1 = 0x646f72616e646f6dULL ^ k1,
    .v2 = 0x6c7967656e657261ULL ^ k0,
    .v3 = 0x7465646279746573ULL ^ k1,
    .padding = 0,
    .n_bytes = 0,
  };
  
}

static void c_siphash_init_nokey(CSipHash *state) {
  
  *state = (CSipHash) {
    .v0 = 0x736f6d6570736575ULL,
    .v1 = 0x646f72616e646f6dULL,
    .v2 = 0x6c7967656e657261ULL,
    .v3 = 0x7465646279746573ULL,
    .padding = 0,
    .n_bytes = 0,
  };
  
}

static inline void c_siphash_append(CSipHash *state, const uint8_t *bytes, size_t n_bytes) {
  
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
    c_siphash_sipround(state);
    state->v0 ^= state->padding;
    
    state->padding = 0;
  }
  
  end -= (state->n_bytes % sizeof(uint64_t));

  for ( ; bytes < end; bytes += 8) {
    m = c_siphash_read_le64(bytes);
    
    state->v3 ^= m;
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

static inline uint64_t c_siphash_finalize(CSipHash *state) {
  
  uint64_t b;
  
  b = state->padding | (((uint64_t) state->n_bytes) << 56);
  
  state->v3 ^= b;
  c_siphash_sipround(state);
  state->v0 ^= b;
  
  state->v2 ^= 0xff;
  
  for (unsigned i = 0; i < 3; i++)
    c_siphash_sipround(state);
  
  return state->v0 ^ state->v1 ^ state->v2  ^ state->v3;
  
}

// secretbase - internals ------------------------------------------------------

static inline void hash_bytes(R_outpstream_t stream, void *src, int len) {
  
  secretbase_context *sctx = (secretbase_context *) stream->data;
  sctx->skip ? (void) sctx->skip-- :
    c_siphash_append((CSipHash *) sctx->ctx, (uint8_t *) src, (size_t) len);
  
}

static void hash_file(CSipHash *ctx, const SEXP x) {
  
  SB_ASSERT_STR(x);
  const char *file = R_ExpandFileName(CHAR(*STRING_PTR_RO(x)));
  unsigned char buf[SB_BUF_SIZE];
  FILE *f;
  size_t cur;
  
  if ((f = fopen(file, "rb")) == NULL)
    ERROR_FOPEN(file);
  
  while ((cur = fread(buf, sizeof(char), SB_BUF_SIZE, f))) {
    c_siphash_append(ctx, buf, cur);
  }
  
  if (ferror(f)) {
    fclose(f);
    ERROR_FREAD(file);
  }
  fclose(f);
  
}

static void hash_object(CSipHash *ctx, const SEXP x) {
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && !ANY_ATTRIB(x)) {
      const char *s = CHAR(*STRING_PTR_RO(x));
      c_siphash_append(ctx, (uint8_t *) s, strlen(s));
      return;
    }
    break;
  case RAWSXP:
    if (!ANY_ATTRIB(x)) {
      c_siphash_append(ctx, (uint8_t *) DATAPTR_RO(x), (size_t) XLENGTH(x));
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

static SEXP secretbase_siphash_impl(const SEXP x, const SEXP key, const SEXP convert,
                                    void (*const hash_func)(CSipHash *, SEXP)) {
  
  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  uint64_t hash;
  
  CSipHash ctx;
  if (key == R_NilValue) {
    c_siphash_init_nokey(&ctx);
  } else {
    uint8_t seed[SB_SKEY_SIZE];
    memset(seed, 0, SB_SKEY_SIZE);
    unsigned char * data;
    size_t klen;
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
    memcpy(seed, data, klen < SB_SKEY_SIZE ? klen : SB_SKEY_SIZE);
    c_siphash_init(&ctx, seed);
  }
  hash_func(&ctx, x);
  hash = c_siphash_finalize(&ctx);
  
  return sb_hash_sexp((unsigned char *) &hash, SB_SIPH_SIZE, conv);
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_siphash13(SEXP x, SEXP key, SEXP convert) {
  
  return secretbase_siphash_impl(x, key, convert, hash_object);
  
}

SEXP secretbase_siphash13_file(SEXP x, SEXP key, SEXP convert) {
  
  return secretbase_siphash_impl(x, key, convert, hash_file);
  
}
