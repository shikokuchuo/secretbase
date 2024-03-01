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

// secretbase - xxHash64 implementation ----------------------------------------

/*
 * xxHash - Extremely Fast Hash algorithm
 * Header File
 * Copyright (C) 2012-2023 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

// XXH_VERSION_MAJOR    0  XXH_VERSION_MINOR    8  XXH_VERSION_RELEASE  2

#if defined (__GNUC__)
# define XXH_PUREF   __attribute__((pure))
#else
# define XXH_PUREF
#endif

#ifdef __has_attribute
# define XXH_HAS_ATTRIBUTE(x) __has_attribute(x)
#else
# define XXH_HAS_ATTRIBUTE(x) 0
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L) && defined(__has_c_attribute)
# define XXH_HAS_C_ATTRIBUTE(x) __has_c_attribute(x)
#else
# define XXH_HAS_C_ATTRIBUTE(x) 0
#endif

#if XXH_HAS_C_ATTRIBUTE(fallthrough)
# define XXH_FALLTHROUGH [[fallthrough]]
#elif XXH_HAS_ATTRIBUTE(__fallthrough__)
# define XXH_FALLTHROUGH __attribute__ ((__fallthrough__))
#else
# define XXH_FALLTHROUGH /* fallthrough */
#endif

#if XXH_HAS_ATTRIBUTE(noescape)
# define XXH_NOESCAPE __attribute__((noescape))
#else
# define XXH_NOESCAPE
#endif

#if defined(__GNUC__) && !(defined(__ARM_ARCH) && __ARM_ARCH < 7 && defined(__ARM_FEATURE_UNALIGNED))
#  define XXH_FORCE_MEMORY_ACCESS 1
#endif

static void* XXH_memcpy(void* dest, const void* src, size_t size)
{
    return memcpy(dest,src,size);
}

#if defined(__GNUC__) || defined(__clang__)
#  define XXH_FORCE_INLINE static __inline__ __attribute__((always_inline, unused))
#  define XXH_NO_INLINE static __attribute__((noinline))
#elif defined (__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)   /* C99 */
#  define XXH_FORCE_INLINE static inline
#  define XXH_NO_INLINE static
#else
#  define XXH_FORCE_INLINE static
#  define XXH_NO_INLINE static
#endif

#if defined(__INTEL_COMPILER)
#  define XXH_ASSERT(c)   XXH_ASSUME((unsigned char) (c))
#else
#  define XXH_ASSERT(c)   XXH_ASSUME(c)
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)    /* C11 */
#  define XXH_STATIC_ASSERT_WITH_MESSAGE(c,m) do { _Static_assert((c),m); } while(0)
#else
#  define XXH_STATIC_ASSERT_WITH_MESSAGE(c,m) do { struct xxh_sa { char x[(c) ? 1 : -1]; }; } while(0)
#endif

#define XXH_STATIC_ASSERT(c) XXH_STATIC_ASSERT_WITH_MESSAGE((c),#c)

#define XXH_GCC_VERSION (__GNUC__ * 100 + __GNUC_MINOR__)

#ifdef __has_builtin
#  define XXH_HAS_BUILTIN(x) __has_builtin(x)
#else
#  define XXH_HAS_BUILTIN(x) 0
#endif

#if XXH_HAS_BUILTIN(__builtin_unreachable)
#  define XXH_UNREACHABLE() __builtin_unreachable()

#else
#  define XXH_UNREACHABLE()
#endif

#if XXH_HAS_BUILTIN(__builtin_assume)
#  define XXH_ASSUME(c) __builtin_assume(c)
#else
#  define XXH_ASSUME(c) if (!(c)) { XXH_UNREACHABLE(); }
#endif

#if (defined(XXH_FORCE_MEMORY_ACCESS))

static uint64_t XXH_read64(const void* ptr)
{
  typedef __attribute__((aligned(1))) uint64_t xxh_unalign64;
  return *((const xxh_unalign64*)ptr);
}

#else

static uint64_t XXH_read64(const void* memPtr)
{
  uint64_t val;
  XXH_memcpy(&val, memPtr, sizeof(val));
  return val;
}

#endif   /* XXH_FORCE_DIRECT_MEMORY_ACCESS */

#if !defined(NO_CLANG_BUILTIN) && XXH_HAS_BUILTIN(__builtin_rotateleft32) \
                               && XXH_HAS_BUILTIN(__builtin_rotateleft64)
#  define XXH_rotl32 __builtin_rotateleft32
#  define XXH_rotl64 __builtin_rotateleft64

#else
#  define XXH_rotl32(x,r) (((x) << (r)) | ((x) >> (32 - (r))))
#  define XXH_rotl64(x,r) (((x) << (r)) | ((x) >> (64 - (r))))
#endif

#if XXH_GCC_VERSION >= 403
#  define XXH_swap32 __builtin_bswap32
#  define XXH_swap64 __builtin_bswap64
#else
static uint32_t XXH_swap32 (uint32_t x)
{
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff );
}

static uint64_t XXH_swap64(uint64_t x)
{
  return  ((x << 56) & 0xff00000000000000ULL) |
    ((x << 40) & 0x00ff000000000000ULL) |
    ((x << 24) & 0x0000ff0000000000ULL) |
    ((x << 8)  & 0x000000ff00000000ULL) |
    ((x >> 8)  & 0x00000000ff000000ULL) |
    ((x >> 24) & 0x0000000000ff0000ULL) |
    ((x >> 40) & 0x000000000000ff00ULL) |
    ((x >> 56) & 0x00000000000000ffULL);
}
#endif

XXH_FORCE_INLINE uint32_t XXH_get32bits(const void* ptr)
{
    return SB_IS_BIG_ENDIAN ? XXH_swap32(*(const uint32_t*)ptr) : *(const uint32_t*)ptr;
}

XXH_FORCE_INLINE uint64_t XXH_readLE64(const void* ptr)
{
    return SB_IS_BIG_ENDIAN ? XXH_swap64(XXH_read64(ptr)) : XXH_read64(ptr);
}

XXH_FORCE_INLINE uint64_t XXH_get64bits(const void* ptr)
{
    return SB_IS_BIG_ENDIAN ? XXH_swap64(*(const uint64_t*)ptr) : *(const uint64_t*)ptr;
}

#define XXH_PRIME64_1  0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2  0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3  0x165667B19E3779F9ULL
#define XXH_PRIME64_4  0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5  0x27D4EB2F165667C5ULL

static uint64_t XXH64_round(uint64_t acc, uint64_t input)
{
    acc += input * XXH_PRIME64_2;
    acc  = XXH_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static uint64_t XXH64_mergeRound(uint64_t acc, uint64_t val)
{
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static uint64_t XXH64_avalanche(uint64_t hash)
{
    hash ^= hash >> 33;
    hash *= XXH_PRIME64_2;
    hash ^= hash >> 29;
    hash *= XXH_PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

static XXH_PUREF uint64_t
XXH64_finalize(uint64_t hash, const uint8_t* ptr, size_t len)
{
    if (ptr==NULL) XXH_ASSERT(len == 0);
    len &= 31;
    while (len >= 8) {
        uint64_t const k1 = XXH64_round(0, XXH_get64bits(ptr));
        ptr += 8;
        hash ^= k1;
        hash  = XXH_rotl64(hash,27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        len -= 8;
    }
    if (len >= 4) {
        hash ^= (uint64_t)(XXH_get32bits(ptr)) * XXH_PRIME64_1;
        ptr += 4;
        hash = XXH_rotl64(hash, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        len -= 4;
    }
    while (len > 0) {
        hash ^= (*ptr++) * XXH_PRIME64_5;
        hash = XXH_rotl64(hash, 11) * XXH_PRIME64_1;
        --len;
    }
    return  XXH64_avalanche(hash);
}

static void XXH64_reset(XXH_NOESCAPE XXH64_state_t* statePtr)
{
    XXH_ASSERT(statePtr != NULL);
    memset(statePtr, 0, sizeof(*statePtr));
    statePtr->v[0] = XXH_PRIME64_1 + XXH_PRIME64_2;
    statePtr->v[1] = XXH_PRIME64_2;
    statePtr->v[2] = 0;
    statePtr->v[3] = -XXH_PRIME64_1;
}

static void XXH64_update (XXH_NOESCAPE XXH64_state_t* state,
                          XXH_NOESCAPE const void* input, size_t len)
{

    const uint8_t* p = (const uint8_t*)input;
    const uint8_t* const bEnd = p + len;

    state->total_len += len;

    if (state->memsize + len < 32) {  /* fill in tmp buffer */
        XXH_memcpy(((uint8_t*)state->mem64) + state->memsize, input, len);
        state->memsize += (uint32_t)len;
        return;
    }

    if (state->memsize) {   /* tmp buffer is full */
        XXH_memcpy(((uint8_t*)state->mem64) + state->memsize, input, 32-state->memsize);
        state->v[0] = XXH64_round(state->v[0], XXH_readLE64(state->mem64+0));
        state->v[1] = XXH64_round(state->v[1], XXH_readLE64(state->mem64+1));
        state->v[2] = XXH64_round(state->v[2], XXH_readLE64(state->mem64+2));
        state->v[3] = XXH64_round(state->v[3], XXH_readLE64(state->mem64+3));
        p += 32 - state->memsize;
        state->memsize = 0;
    }

    if (p+32 <= bEnd) {
        const uint8_t* const limit = bEnd - 32;

        do {
            state->v[0] = XXH64_round(state->v[0], XXH_readLE64(p)); p+=8;
            state->v[1] = XXH64_round(state->v[1], XXH_readLE64(p)); p+=8;
            state->v[2] = XXH64_round(state->v[2], XXH_readLE64(p)); p+=8;
            state->v[3] = XXH64_round(state->v[3], XXH_readLE64(p)); p+=8;
        } while (p<=limit);

    }

    if (p < bEnd) {
        XXH_memcpy(state->mem64, p, (size_t)(bEnd-p));
        state->memsize = (unsigned)(bEnd-p);
    }    

}

static uint64_t XXH64_digest(XXH_NOESCAPE const XXH64_state_t* state)
{
    uint64_t h64;

    if (state->total_len >= 32) {
        h64 = XXH_rotl64(state->v[0], 1) + XXH_rotl64(state->v[1], 7) + XXH_rotl64(state->v[2], 12) + XXH_rotl64(state->v[3], 18);
        h64 = XXH64_mergeRound(h64, state->v[0]);
        h64 = XXH64_mergeRound(h64, state->v[1]);
        h64 = XXH64_mergeRound(h64, state->v[2]);
        h64 = XXH64_mergeRound(h64, state->v[3]);
    } else {
        h64  = state->v[2] /*seed*/ + XXH_PRIME64_5;
    }

    h64 += (uint64_t) state->total_len;
    
    h64 = XXH64_finalize(h64, (const uint8_t*)state->mem64, (size_t)state->total_len);

    return SB_IS_BIG_ENDIAN ? h64 : XXH_swap64(h64);
}

// secretbase - internals ------------------------------------------------------

static void hash_bytes(R_outpstream_t stream, void *src, int len) {
  
  secretbase_xxh64_context *sctx = (secretbase_xxh64_context *) stream->data;
  sctx->skip ? (void) sctx->skip-- : XXH64_update(sctx->ctx, (uint8_t *) src, (size_t) len);
  
}

static void hash_file(XXH64_state_t *ctx, const SEXP x) {
  
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
    XXH64_update(ctx, buf, cur);
  }
  
  if (ferror(f)) {
    fclose(f);
    Rf_error("file read error at '%s'", file);
  }
  fclose(f);
  
}

static void hash_object(XXH64_state_t *ctx, const SEXP x) {
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && ATTRIB(x) == R_NilValue) {
      const char *s = CHAR(STRING_ELT(x, 0));
      XXH64_update(ctx, (uint8_t *) s, strlen(s));
      return;
    }
    break;
  case RAWSXP:
    if (ATTRIB(x) == R_NilValue) {
      XXH64_update(ctx, (uint8_t *) STDVEC_DATAPTR(x), (size_t) XLENGTH(x));
      return;
    }
    break;
  }
  
  secretbase_xxh64_context sctx;
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

SEXP secretbase_xxh64_impl(const SEXP x, const SEXP convert,
                           void (*const hash_func)(XXH64_state_t *, SEXP)) {
  
  const int conv = LOGICAL(convert)[0];
  uint64_t buf;
  struct XXH64_state_s state;
  
  XXH64_reset(&state);
  hash_func(&state, x);
  buf = XXH64_digest(&state);
  
  return hash_to_sexp((unsigned char *) &buf, sizeof(uint64_t), conv);
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_xxh64(SEXP x, SEXP convert) {
  
  return secretbase_xxh64_impl(x, convert, hash_object);
  
}

SEXP secretbase_xxh64_file(SEXP x, SEXP convert) {
  
  return secretbase_xxh64_impl(x, convert, hash_file);
  
}
