// secretbase ------------------------------------------------------------------

#include "secret.h"
#include <string.h>

// secretbase - CBOR implementation --------------------------------------------

/*
 *  CBOR (RFC 8949) encoder/decoder for R
 *
 *  https://www.rfc-editor.org/rfc/rfc8949.html
 *
 *  Supports a minimal subset:
 *  - Major type 0: unsigned integers
 *  - Major type 1: negative integers
 *  - Major type 2: byte strings (raw vectors)
 *  - Major type 3: text strings (UTF-8)
 *  - Major type 4: arrays (lists)
 *  - Major type 5: maps (named lists)
 *  - Major type 7: simple values (false, true, null, undefined), float32, float64
 */

// CBOR major type constants
#define CBOR_UINT     0x00  // Major type 0: unsigned integer
#define CBOR_NEGINT   0x20  // Major type 1: negative integer
#define CBOR_BYTES    0x40  // Major type 2: byte string
#define CBOR_TEXT     0x60  // Major type 3: text string
#define CBOR_ARRAY    0x80  // Major type 4: array
#define CBOR_MAP      0xA0  // Major type 5: map
#define CBOR_SIMPLE   0xE0  // Major type 7: simple values

// Simple values
#define CBOR_FALSE    0xF4
#define CBOR_TRUE     0xF5
#define CBOR_NULL     0xF6
#define CBOR_UNDEF    0xF7
#define CBOR_FLOAT64  0xFB

// Additional info thresholds
#define CBOR_UINT8    24
#define CBOR_UINT16   25
#define CBOR_UINT32   26
#define CBOR_UINT64   27

// Maximum nesting depth for decoder (stack overflow protection)
#define CBOR_MAX_DEPTH 512

// secretbase - byte order helpers  --------------------------------------------

/*
 *  Byte-order helpers from Mbed TLS
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4, 8)
#define CBOR_BSWAP16 __builtin_bswap16
#endif
#if __GNUC_PREREQ(4, 3)
#define CBOR_BSWAP32 __builtin_bswap32
#define CBOR_BSWAP64 __builtin_bswap64
#endif
#endif

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap16) && !defined(CBOR_BSWAP16)
#define CBOR_BSWAP16 __builtin_bswap16
#endif
#if __has_builtin(__builtin_bswap32) && !defined(CBOR_BSWAP32)
#define CBOR_BSWAP32 __builtin_bswap32
#endif
#if __has_builtin(__builtin_bswap64) && !defined(CBOR_BSWAP64)
#define CBOR_BSWAP64 __builtin_bswap64
#endif
#endif

#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 410000) && !defined(CBOR_BSWAP32)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#endif
#define CBOR_BSWAP32 __rev
#endif

#if defined(__IAR_SYSTEMS_ICC__)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#define CBOR_BSWAP16(x) ((uint16_t) __rev16((uint32_t) (x)))
#define CBOR_BSWAP32 __rev
#define CBOR_BSWAP64 __revll
#endif
#endif

#if !defined(CBOR_BSWAP16)
static inline uint16_t cbor_bswap16(uint16_t x) {
  return (x & 0x00ff) << 8 |
         (x & 0xff00) >> 8;
}
#define CBOR_BSWAP16 cbor_bswap16
#endif

#if !defined(CBOR_BSWAP32)
static inline uint32_t cbor_bswap32(uint32_t x) {
  return (x & 0x000000ff) << 24 |
         (x & 0x0000ff00) <<  8 |
         (x & 0x00ff0000) >>  8 |
         (x & 0xff000000) >> 24;
}
#define CBOR_BSWAP32 cbor_bswap32
#endif

#if !defined(CBOR_BSWAP64)
static inline uint64_t cbor_bswap64(uint64_t x) {
  return (x & 0x00000000000000ffULL) << 56 |
         (x & 0x000000000000ff00ULL) << 40 |
         (x & 0x0000000000ff0000ULL) << 24 |
         (x & 0x00000000ff000000ULL) <<  8 |
         (x & 0x000000ff00000000ULL) >>  8 |
         (x & 0x0000ff0000000000ULL) >> 24 |
         (x & 0x00ff000000000000ULL) >> 40 |
         (x & 0xff00000000000000ULL) >> 56;
}
#define CBOR_BSWAP64 cbor_bswap64
#endif

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint16_t cbor_get_unaligned_uint16(const void *p) {
  uint16_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void cbor_put_unaligned_uint16(void *p, uint16_t x) {
  memcpy(p, &x, sizeof(x));
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint32_t cbor_get_unaligned_uint32(const void *p) {
  uint32_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void cbor_put_unaligned_uint32(void *p, uint32_t x) {
  memcpy(p, &x, sizeof(x));
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint64_t cbor_get_unaligned_uint64(const void *p) {
  uint64_t r;
  memcpy(&r, p, sizeof(r));
  return r;
}

#if defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void cbor_put_unaligned_uint64(void *p, uint64_t x) {
  memcpy(p, &x, sizeof(x));
}

#define CBOR_GET_UINT16_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? cbor_get_unaligned_uint16((data) + (offset)) \
   : CBOR_BSWAP16(cbor_get_unaligned_uint16((data) + (offset))))

#define CBOR_PUT_UINT16_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      cbor_put_unaligned_uint16((data) + (offset), (uint16_t) (n)); \
    else \
      cbor_put_unaligned_uint16((data) + (offset), CBOR_BSWAP16((uint16_t) (n))); \
  }

#define CBOR_GET_UINT32_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? cbor_get_unaligned_uint32((data) + (offset)) \
   : CBOR_BSWAP32(cbor_get_unaligned_uint32((data) + (offset))))

#define CBOR_PUT_UINT32_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      cbor_put_unaligned_uint32((data) + (offset), (uint32_t) (n)); \
    else \
      cbor_put_unaligned_uint32((data) + (offset), CBOR_BSWAP32((uint32_t) (n))); \
  }

#define CBOR_GET_UINT64_BE(data, offset) \
  ((MBEDTLS_IS_BIG_ENDIAN) \
   ? cbor_get_unaligned_uint64((data) + (offset)) \
   : CBOR_BSWAP64(cbor_get_unaligned_uint64((data) + (offset))))

#define CBOR_PUT_UINT64_BE(n, data, offset) \
  { \
    if (MBEDTLS_IS_BIG_ENDIAN) \
      cbor_put_unaligned_uint64((data) + (offset), (uint64_t) (n)); \
    else \
      cbor_put_unaligned_uint64((data) + (offset), CBOR_BSWAP64((uint64_t) (n))); \
  }

// secretbase - internals ------------------------------------------------------

static inline void cbor_buf_ensure(nano_buf *buf, size_t additional) {
  size_t req = buf->cur + additional;
  if (req > buf->len) {
    if (req > R_XLEN_T_MAX) { ERROR_OUT(buf); }
    do {
      buf->len += buf->len > SB_SERIAL_THR ? SB_SERIAL_THR : buf->len;
    } while (buf->len < req);
    unsigned char *tmp = realloc(buf->buf, buf->len);
    if (tmp == NULL) {
      free(buf->buf);
      Rf_error("memory allocation failed");
    }
    buf->buf = tmp;
  }
}

static inline void cbor_write_byte(nano_buf *buf, unsigned char b) {
  cbor_buf_ensure(buf, 1);
  buf->buf[buf->cur++] = b;
}

static inline void cbor_write_bytes(nano_buf *buf, const unsigned char *data, size_t len) {
  cbor_buf_ensure(buf, len);
  memcpy(buf->buf + buf->cur, data, len);
  buf->cur += len;
}

static void cbor_encode_uint(nano_buf *buf, unsigned char major, uint64_t val) {
  if (val < 24) {
    cbor_write_byte(buf, major | (unsigned char) val);
  } else if (val <= 0xFF) {
    cbor_buf_ensure(buf, 2);
    buf->buf[buf->cur++] = major | CBOR_UINT8;
    buf->buf[buf->cur++] = (unsigned char) val;
  } else if (val <= 0xFFFF) {
    cbor_buf_ensure(buf, 3);
    buf->buf[buf->cur++] = major | CBOR_UINT16;
    CBOR_PUT_UINT16_BE((uint16_t) val, buf->buf, buf->cur);
    buf->cur += 2;
  } else if (val <= 0xFFFFFFFF) {
    cbor_buf_ensure(buf, 5);
    buf->buf[buf->cur++] = major | CBOR_UINT32;
    CBOR_PUT_UINT32_BE((uint32_t) val, buf->buf, buf->cur);
    buf->cur += 4;
  } else {
    cbor_buf_ensure(buf, 9);
    buf->buf[buf->cur++] = major | CBOR_UINT64;
    CBOR_PUT_UINT64_BE(val, buf->buf, buf->cur);
    buf->cur += 8;
  }
}

static void cbor_encode_int(nano_buf *buf, int64_t val) {
  if (val >= 0) {
    cbor_encode_uint(buf, CBOR_UINT, (uint64_t) val);
  } else {
    cbor_encode_uint(buf, CBOR_NEGINT, (uint64_t) (-1 - val));
  }
}

static void cbor_encode_double(nano_buf *buf, double val) {
  cbor_write_byte(buf, CBOR_FLOAT64);
  cbor_buf_ensure(buf, 8);
  union {
    double d;
    uint64_t u;
  } conv;
  conv.d = val;

  CBOR_PUT_UINT64_BE(conv.u, buf->buf, buf->cur);
  buf->cur += 8;
}

static void cbor_encode_bytes(nano_buf *buf, const unsigned char *data, size_t len) {
  cbor_encode_uint(buf, CBOR_BYTES, len);
  cbor_write_bytes(buf, data, len);
}

static void cbor_encode_text(nano_buf *buf, const char *str, size_t len) {
  cbor_encode_uint(buf, CBOR_TEXT, len);
  cbor_write_bytes(buf, (const unsigned char *) str, len);
}

static void cbor_encode_sexp(nano_buf *buf, SEXP x);

static void cbor_encode_logical_vec(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  const int *p = LOGICAL_RO(x);

  if (n == 1 && NO_ATTRIB(x)) {
    cbor_write_byte(buf, p[0] == NA_LOGICAL ? CBOR_UNDEF :
                         p[0] ? CBOR_TRUE : CBOR_FALSE);
  } else {
    cbor_encode_uint(buf, CBOR_ARRAY, n);
    for (R_xlen_t i = 0; i < n; i++) {
      cbor_write_byte(buf, p[i] == NA_LOGICAL ? CBOR_UNDEF :
                           p[i] ? CBOR_TRUE : CBOR_FALSE);
    }
  }
}

static void cbor_encode_integer_vec(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  const int *p = INTEGER_RO(x);

  if (n == 1 && NO_ATTRIB(x)) {
    cbor_encode_int(buf, p[0]);
  } else {
    cbor_encode_uint(buf, CBOR_ARRAY, n);
    for (R_xlen_t i = 0; i < n; i++) {
      cbor_encode_int(buf, p[i]);
    }
  }
}

static void cbor_encode_double_vec(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  const double *p = REAL_RO(x);

  if (n == 1 && NO_ATTRIB(x)) {
    cbor_encode_double(buf, p[0]);
  } else {
    cbor_encode_uint(buf, CBOR_ARRAY, n);
    for (R_xlen_t i = 0; i < n; i++) {
      cbor_encode_double(buf, p[i]);
    }
  }
}

static void cbor_encode_character_vec(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  const SEXP *p = STRING_PTR_RO(x);

  if (n == 1 && NO_ATTRIB(x)) {
    if (p[0] == NA_STRING) {
      cbor_write_byte(buf, CBOR_UNDEF);
    } else {
      const char *s = Rf_translateCharUTF8(p[0]);
      cbor_encode_text(buf, s, strlen(s));
    }
  } else {
    cbor_encode_uint(buf, CBOR_ARRAY, n);
    for (R_xlen_t i = 0; i < n; i++) {
      if (p[i] == NA_STRING) {
        cbor_write_byte(buf, CBOR_UNDEF);
      } else {
        const char *s = Rf_translateCharUTF8(p[i]);
        cbor_encode_text(buf, s, strlen(s));
      }
    }
  }
}

static void cbor_encode_raw(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  cbor_encode_bytes(buf, (const unsigned char *) DATAPTR_RO(x), n);
}

static void cbor_encode_list(nano_buf *buf, SEXP x) {
  R_xlen_t n = XLENGTH(x);
  SEXP names = Rf_getAttrib(x, R_NamesSymbol);

  if (names == R_NilValue) {
    cbor_encode_uint(buf, CBOR_ARRAY, n);
    for (R_xlen_t i = 0; i < n; i++) {
      cbor_encode_sexp(buf, VECTOR_ELT(x, i));
    }
  } else {
    cbor_encode_uint(buf, CBOR_MAP, n);
    for (R_xlen_t i = 0; i < n; i++) {
      const char *key = Rf_translateCharUTF8(STRING_ELT(names, i));
      cbor_encode_text(buf, key, strlen(key));
      cbor_encode_sexp(buf, VECTOR_ELT(x, i));
    }
  }
}

static void cbor_encode_sexp(nano_buf *buf, SEXP x) {
  switch (TYPEOF(x)) {
  case NILSXP:
    cbor_write_byte(buf, CBOR_NULL);
    break;
  case LGLSXP:
    cbor_encode_logical_vec(buf, x);
    break;
  case INTSXP:
    cbor_encode_integer_vec(buf, x);
    break;
  case REALSXP:
    cbor_encode_double_vec(buf, x);
    break;
  case STRSXP:
    cbor_encode_character_vec(buf, x);
    break;
  case RAWSXP:
    cbor_encode_raw(buf, x);
    break;
  case VECSXP:
    cbor_encode_list(buf, x);
    break;
  default:
    if (buf->len) free(buf->buf);
    Rf_error("unsupported type for CBOR encoding: %s", Rf_type2char(TYPEOF(x)));
  }
}

typedef struct {
  const unsigned char *data;
  size_t len;
  size_t pos;
} cbor_decoder;

static inline unsigned char cbor_read_byte(cbor_decoder *dec) {
  if (dec->pos >= dec->len)
    Rf_error("CBOR decode error: unexpected end of input");
  return dec->data[dec->pos++];
}

static uint64_t cbor_read_uint(cbor_decoder *dec, unsigned char info) {
  if (info < 24) {
    return info;
  } else if (info == CBOR_UINT8) {
    return cbor_read_byte(dec);
  } else if (info == CBOR_UINT16) {
    if (dec->pos + 2 > dec->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint16_t val = CBOR_GET_UINT16_BE(dec->data, dec->pos);
    dec->pos += 2;
    return val;
  } else if (info == CBOR_UINT32) {
    if (dec->pos + 4 > dec->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint32_t val = CBOR_GET_UINT32_BE(dec->data, dec->pos);
    dec->pos += 4;
    return val;
  } else if (info == CBOR_UINT64) {
    if (dec->pos + 8 > dec->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint64_t val = CBOR_GET_UINT64_BE(dec->data, dec->pos);
    dec->pos += 8;
    return val;
  }
  Rf_error("CBOR decode error: invalid additional info %d", info);
}

static SEXP cbor_decode_item(cbor_decoder *dec, int depth) {
  if (depth > CBOR_MAX_DEPTH)
    Rf_error("CBOR decode error: nesting depth exceeded");

  unsigned char byte = cbor_read_byte(dec);
  unsigned char major = byte & 0xE0;
  unsigned char info = byte & 0x1F;

  switch (major) {
  case CBOR_UINT: {
    uint64_t val = cbor_read_uint(dec, info);
    if (val <= INT_MAX) {
      return Rf_ScalarInteger((int) val);
    } else {
      return Rf_ScalarReal((double) val);
    }
  }

  case CBOR_NEGINT: {
    uint64_t val = cbor_read_uint(dec, info);
    if (val <= 2147483647ULL) {
      return Rf_ScalarInteger((int) (-1 - (int64_t) val));
    } else {
      return Rf_ScalarReal(-1.0 - (double) val);
    }
  }

  case CBOR_BYTES: {
    uint64_t len = cbor_read_uint(dec, info);
    if (dec->pos + len > dec->len)
      Rf_error("CBOR decode error: byte string exceeds input");
    SEXP out = Rf_allocVector(RAWSXP, len);
    memcpy(RAW(out), dec->data + dec->pos, len);
    dec->pos += len;
    return out;
  }

  case CBOR_TEXT: {
    uint64_t len = cbor_read_uint(dec, info);
    if (dec->pos + len > dec->len)
      Rf_error("CBOR decode error: text string exceeds input");
    SEXP out = Rf_mkCharLenCE((const char *) (dec->data + dec->pos), (int) len, CE_UTF8);
    dec->pos += len;
    return Rf_ScalarString(out);
  }

  case CBOR_ARRAY: {
    uint64_t n = cbor_read_uint(dec, info);
    SEXP out = PROTECT(Rf_allocVector(VECSXP, n));
    for (uint64_t i = 0; i < n; i++) {
      SET_VECTOR_ELT(out, i, cbor_decode_item(dec, depth + 1));
    }
    UNPROTECT(1);
    return out;
  }

  case CBOR_MAP: {
    uint64_t n = cbor_read_uint(dec, info);
    SEXP out = PROTECT(Rf_allocVector(VECSXP, n));
    SEXP names = PROTECT(Rf_allocVector(STRSXP, n));

    for (uint64_t i = 0; i < n; i++) {
      unsigned char kb = cbor_read_byte(dec);
      if ((kb & 0xE0) != CBOR_TEXT)
        Rf_error("CBOR decode error: map key must be text string");
      uint64_t klen = cbor_read_uint(dec, kb & 0x1F);
      if (dec->pos + klen > dec->len)
        Rf_error("CBOR decode error: map key exceeds input");
      SET_STRING_ELT(names, i, Rf_mkCharLenCE((const char *) (dec->data + dec->pos), (int) klen, CE_UTF8));
      dec->pos += klen;
      SET_VECTOR_ELT(out, i, cbor_decode_item(dec, depth + 1));
    }

    Rf_setAttrib(out, R_NamesSymbol, names);
    UNPROTECT(2);
    return out;
  }

  case CBOR_SIMPLE: {
    if (byte == CBOR_FALSE) {
      return Rf_ScalarLogical(FALSE);
    } else if (byte == CBOR_TRUE) {
      return Rf_ScalarLogical(TRUE);
    } else if (byte == CBOR_NULL) {
      return R_NilValue;
    } else if (byte == CBOR_UNDEF) {
      return Rf_ScalarLogical(NA_LOGICAL);
    } else if (byte == 0xFA) {
      if (dec->pos + 4 > dec->len)
        Rf_error("CBOR decode error: float32 exceeds input");
      union {
        uint32_t u;
        float f;
      } conv;
      conv.u = CBOR_GET_UINT32_BE(dec->data, dec->pos);
      dec->pos += 4;
      return Rf_ScalarReal((double) conv.f);
    } else if (byte == CBOR_FLOAT64) {
      if (dec->pos + 8 > dec->len)
        Rf_error("CBOR decode error: float64 exceeds input");
      union {
        uint64_t u;
        double d;
      } conv;
      conv.u = CBOR_GET_UINT64_BE(dec->data, dec->pos);
      dec->pos += 8;
      return Rf_ScalarReal(conv.d);
    }
    Rf_error("CBOR decode error: unsupported simple value 0x%02x", byte);
  }

  default:
    Rf_error("CBOR decode error: unsupported major type %d", major >> 5);
  }
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_cborenc(SEXP x) {
  nano_buf buf;
  NANO_ALLOC(&buf, SB_INIT_BUFSIZE);

  cbor_encode_sexp(&buf, x);

  SEXP out = Rf_allocVector(RAWSXP, buf.cur);
  memcpy(RAW(out), buf.buf, buf.cur);

  NANO_FREE(buf);
  return out;
}

SEXP secretbase_cbordec(SEXP x) {
  if (TYPEOF(x) != RAWSXP)
    Rf_error("'x' must be a raw vector");

  cbor_decoder dec;
  dec.data = (const unsigned char *) DATAPTR_RO(x);
  dec.len = XLENGTH(x);
  dec.pos = 0;

  SEXP out = cbor_decode_item(&dec, 0);

  if (dec.pos != dec.len)
    Rf_warning("CBOR decode: %zu trailing bytes ignored", dec.len - dec.pos);

  return out;
}
