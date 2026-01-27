// secretbase ------------------------------------------------------------------

#include "secret.h"

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
#define CBOR_FLOAT16  0xF9
#define CBOR_FLOAT32  0xFA
#define CBOR_FLOAT64  0xFB

// Additional info thresholds
#define CBOR_UINT8    24
#define CBOR_UINT16   25
#define CBOR_UINT32   26
#define CBOR_UINT64   27

// Byte extraction macros
#define CBOR_MAJOR(b)  ((b) & 0xE0)
#define CBOR_INFO(b)   ((b) & 0x1F)

// Maximum nesting depth for decoder (stack overflow protection)
#define CBOR_MAX_DEPTH 512

// secretbase - internals ------------------------------------------------------

static inline void cbor_buf_ensure(nano_buf *buf, size_t additional) {
  if (additional > R_XLEN_T_MAX - buf->cur) { ERROR_OUT(buf); }
  size_t req = buf->cur + additional;
  if (req > buf->len) {
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

static void cbor_encode_uint(nano_buf *buf, unsigned char major, uint64_t val) {
  if (val < 24) {
    cbor_buf_ensure(buf, 1);
    buf->buf[buf->cur++] = major | (unsigned char) val;
  } else if (val <= 0xFF) {
    cbor_buf_ensure(buf, 2);
    buf->buf[buf->cur++] = major | CBOR_UINT8;
    buf->buf[buf->cur++] = (unsigned char) val;
  } else if (val <= 0xFFFF) {
    cbor_buf_ensure(buf, 3);
    buf->buf[buf->cur++] = major | CBOR_UINT16;
    MBEDTLS_PUT_UINT16_BE((uint16_t) val, buf->buf, buf->cur);
    buf->cur += 2;
  } else if (val <= 0xFFFFFFFF) {
    cbor_buf_ensure(buf, 5);
    buf->buf[buf->cur++] = major | CBOR_UINT32;
    MBEDTLS_PUT_UINT32_BE((uint32_t) val, buf->buf, buf->cur);
    buf->cur += 4;
  } else {
    cbor_buf_ensure(buf, 9);
    buf->buf[buf->cur++] = major | CBOR_UINT64;
    MBEDTLS_PUT_UINT64_BE(val, buf->buf, buf->cur);
    buf->cur += 8;
  }
}

static inline void cbor_encode_int(nano_buf *buf, int64_t val) {
  if (val >= 0) {
    cbor_encode_uint(buf, CBOR_UINT, (uint64_t) val);
  } else {
    cbor_encode_uint(buf, CBOR_NEGINT, (uint64_t) (-1 - val));
  }
}

static inline void cbor_encode_double(nano_buf *buf, double val) {
  buf->buf[buf->cur++] = CBOR_FLOAT64;
  union {
    double d;
    uint64_t u;
  } conv;
  conv.d = val;
  MBEDTLS_PUT_UINT64_BE(conv.u, buf->buf, buf->cur);
  buf->cur += 8;
}

static inline void cbor_encode_bytes(nano_buf *buf, const unsigned char *data, size_t len) {
  cbor_encode_uint(buf, CBOR_BYTES, len);
  cbor_buf_ensure(buf, len);
  memcpy(buf->buf + buf->cur, data, len);
  buf->cur += len;
}

static inline void cbor_encode_text(nano_buf *buf, const char *str, size_t len) {
  cbor_encode_uint(buf, CBOR_TEXT, len);
  cbor_buf_ensure(buf, len);
  memcpy(buf->buf + buf->cur, str, len);
  buf->cur += len;
}

static inline void cbor_encode_undef(nano_buf *buf) {
  buf->buf[buf->cur++] = CBOR_UNDEF;
}

static void cbor_encode_sexp(nano_buf *buf, SEXP x);

static void cbor_encode_logical_vec(nano_buf *buf, SEXP x) {
  R_xlen_t xlen = XLENGTH(x);
  const int *p = (const int *) DATAPTR_RO(x);

  if (xlen != 1)
    cbor_encode_uint(buf, CBOR_ARRAY, xlen);

  cbor_buf_ensure(buf, xlen);
  for (R_xlen_t i = 0; i < xlen; i++) {
    buf->buf[buf->cur++] = p[i] == NA_LOGICAL ? CBOR_UNDEF :
                           p[i] ? CBOR_TRUE : CBOR_FALSE;
  }
}

static void cbor_encode_integer_vec(nano_buf *buf, SEXP x) {
  R_xlen_t xlen = XLENGTH(x);
  const int *p = (const int *) DATAPTR_RO(x);

  if (xlen != 1)
    cbor_encode_uint(buf, CBOR_ARRAY, xlen);

  cbor_buf_ensure(buf, (size_t) xlen * 5);
  for (R_xlen_t i = 0; i < xlen; i++) {
    if (p[i] == NA_INTEGER) {
      cbor_encode_undef(buf);
    } else {
      cbor_encode_int(buf, p[i]);
    }
  }
}

static void cbor_encode_double_vec(nano_buf *buf, SEXP x) {
  R_xlen_t xlen = XLENGTH(x);
  const double *p = (const double *) DATAPTR_RO(x);

  if (xlen != 1)
    cbor_encode_uint(buf, CBOR_ARRAY, xlen);

  cbor_buf_ensure(buf, (size_t) xlen * 9);
  for (R_xlen_t i = 0; i < xlen; i++) {
    if (ISNA(p[i])) {
      cbor_encode_undef(buf);
    } else {
      cbor_encode_double(buf, p[i]);
    }
  }
}

static void cbor_encode_character_vec(nano_buf *buf, SEXP x) {
  R_xlen_t xlen = XLENGTH(x);
  const SEXP *p = STRING_PTR_RO(x);

  if (xlen != 1)
    cbor_encode_uint(buf, CBOR_ARRAY, xlen);

  for (R_xlen_t i = 0; i < xlen; i++) {
    if (p[i] == NA_STRING) {
      cbor_buf_ensure(buf, 1);
      cbor_encode_undef(buf);
    } else {
      const char *s = Rf_translateCharUTF8(p[i]);
      cbor_encode_text(buf, s, strlen(s));
    }
  }
}

static inline void cbor_encode_raw(nano_buf *buf, SEXP x) {
  cbor_encode_bytes(buf, (const unsigned char *) DATAPTR_RO(x), XLENGTH(x));
}

static void cbor_encode_list(nano_buf *buf, SEXP x) {
  R_xlen_t xlen = XLENGTH(x);
  SEXP names = Rf_getAttrib(x, R_NamesSymbol);
  if (names == R_NilValue) {
    cbor_encode_uint(buf, CBOR_ARRAY, xlen);
    for (R_xlen_t i = 0; i < xlen; i++) {
      cbor_encode_sexp(buf, VECTOR_ELT(x, i));
    }
  } else {
    PROTECT(names);
    cbor_encode_uint(buf, CBOR_MAP, xlen);
    for (R_xlen_t i = 0; i < xlen; i++) {
      const char *key = Rf_translateCharUTF8(STRING_ELT(names, i));
      cbor_encode_text(buf, key, strlen(key));
      cbor_encode_sexp(buf, VECTOR_ELT(x, i));
    }
    UNPROTECT(1);
  }
}

static void cbor_encode_sexp(nano_buf *buf, SEXP x) {
  switch (TYPEOF(x)) {
  case NILSXP:
    cbor_buf_ensure(buf, 1);
    buf->buf[buf->cur++] = CBOR_NULL;
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

static inline unsigned char cbor_read_byte(nano_buf *buf) {
  if (buf->cur >= buf->len)
    Rf_error("CBOR decode error: unexpected end of input");
  return buf->buf[buf->cur++];
}

static uint64_t cbor_read_uint(nano_buf *buf, unsigned char info) {
  if (info < 24)
    return info;
  switch (info) {
  case CBOR_UINT8:
    return cbor_read_byte(buf);
  case CBOR_UINT16:
    if (buf->cur + 2 > buf->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint16_t val16 = MBEDTLS_GET_UINT16_BE(buf->buf, buf->cur);
    buf->cur += 2;
    return val16;
  case CBOR_UINT32:
    if (buf->cur + 4 > buf->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint32_t val32 = MBEDTLS_GET_UINT32_BE(buf->buf, buf->cur);
    buf->cur += 4;
    return val32;
  case CBOR_UINT64:
    if (buf->cur + 8 > buf->len)
      Rf_error("CBOR decode error: unexpected end of input");
    uint64_t val64 = MBEDTLS_GET_UINT64_BE(buf->buf, buf->cur);
    buf->cur += 8;
    return val64;
  default:
    Rf_error("CBOR decode error: invalid additional info %d", info);
  }
}

static SEXP cbor_decode_item(nano_buf *buf, int depth) {
  if (depth > CBOR_MAX_DEPTH)
    Rf_error("CBOR decode error: nesting depth exceeded");

  unsigned char byte = cbor_read_byte(buf);
  unsigned char major = CBOR_MAJOR(byte);
  unsigned char info = CBOR_INFO(byte);

  switch (major) {
  case CBOR_UINT: {
    uint64_t val = cbor_read_uint(buf, info);
    if (val <= INT_MAX) {
      return Rf_ScalarInteger((int) val);
    } else {
      return Rf_ScalarReal((double) val);
    }
  }

  case CBOR_NEGINT: {
    uint64_t val = cbor_read_uint(buf, info);
    if (val <= INT_MAX) {
      return Rf_ScalarInteger((int) (-1 - (int64_t) val));
    } else {
      return Rf_ScalarReal(-1.0 - (double) val);
    }
  }

  case CBOR_BYTES: {
    uint64_t len = cbor_read_uint(buf, info);
    if (len > buf->len - buf->cur)
      Rf_error("CBOR decode error: byte string exceeds input");
    SEXP out = Rf_allocVector(RAWSXP, len);
    memcpy(RAW(out), buf->buf + buf->cur, len);
    buf->cur += len;
    return out;
  }

  case CBOR_TEXT: {
    uint64_t len = cbor_read_uint(buf, info);
    if (len > buf->len - buf->cur)
      Rf_error("CBOR decode error: text string exceeds input");
    SEXP out = Rf_mkCharLenCE((const char *) (buf->buf + buf->cur), (int) len, CE_UTF8);
    buf->cur += len;
    return Rf_ScalarString(out);
  }

  case CBOR_ARRAY: {
    uint64_t n = cbor_read_uint(buf, info);
    SEXP out = PROTECT(Rf_allocVector(VECSXP, n));
    for (uint64_t i = 0; i < n; i++) {
      SET_VECTOR_ELT(out, i, cbor_decode_item(buf, depth + 1));
    }
    UNPROTECT(1);
    return out;
  }

  case CBOR_MAP: {
    uint64_t n = cbor_read_uint(buf, info);
    SEXP out = PROTECT(Rf_allocVector(VECSXP, n));
    SEXP names = Rf_allocVector(STRSXP, n);
    Rf_namesgets(out, names);

    for (uint64_t i = 0; i < n; i++) {
      unsigned char kb = cbor_read_byte(buf);
      if (CBOR_MAJOR(kb) != CBOR_TEXT)
        Rf_error("CBOR decode error: map key must be text string");
      uint64_t klen = cbor_read_uint(buf, CBOR_INFO(kb));
      if (klen > buf->len - buf->cur)
        Rf_error("CBOR decode error: map key exceeds input");
      SET_STRING_ELT(names, i, Rf_mkCharLenCE((const char *) (buf->buf + buf->cur), (int) klen, CE_UTF8));
      buf->cur += klen;
      SET_VECTOR_ELT(out, i, cbor_decode_item(buf, depth + 1));
    }

    UNPROTECT(1);
    return out;
  }

  case CBOR_SIMPLE:
    switch (byte) {
    case CBOR_FALSE:
      return Rf_ScalarLogical(FALSE);
    case CBOR_TRUE:
      return Rf_ScalarLogical(TRUE);
    case CBOR_NULL:
      return R_NilValue;
    case CBOR_UNDEF:
      return Rf_ScalarLogical(NA_LOGICAL);
    case CBOR_FLOAT64: {
      if (buf->cur + 8 > buf->len)
        Rf_error("CBOR decode error: float64 exceeds input");
      union {
        uint64_t u;
        double d;
      } conv;
      conv.u = MBEDTLS_GET_UINT64_BE(buf->buf, buf->cur);
      buf->cur += 8;
      return Rf_ScalarReal(conv.d);
    }
    case CBOR_FLOAT32: {
      if (buf->cur + 4 > buf->len)
        Rf_error("CBOR decode error: float32 exceeds input");
      union {
        uint32_t u;
        float f;
      } conv;
      conv.u = MBEDTLS_GET_UINT32_BE(buf->buf, buf->cur);
      buf->cur += 4;
      return Rf_ScalarReal((double) conv.f);
    }
    case CBOR_FLOAT16: {
      if (buf->cur + 2 > buf->len)
        Rf_error("CBOR decode error: float16 exceeds input");
      uint16_t half = MBEDTLS_GET_UINT16_BE(buf->buf, buf->cur);
      buf->cur += 2;
      int exp = (half >> 10) & 0x1F;
      int mant = half & 0x3FF;
      double val;
      if (exp == 0) {
        val = ldexp(mant, -24);
      } else if (exp == 31) {
        val = mant == 0 ? R_PosInf : R_NaN;
      } else {
        val = ldexp(mant + 1024, exp - 25);
      }
      if (half & 0x8000) val = -val;
      return Rf_ScalarReal(val);
    }
    default:
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
  memcpy(SB_DATAPTR(out), buf.buf, buf.cur);
  NANO_FREE(buf);
  
  return out;
}

SEXP secretbase_cbordec(SEXP x) {
  if (TYPEOF(x) != RAWSXP)
    Rf_error("'x' must be a raw vector");

  nano_buf buf = {.buf = (unsigned char *) DATAPTR_RO(x), .len = XLENGTH(x), .cur = 0};
  return cbor_decode_item(&buf, 0);
}
