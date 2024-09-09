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

// secretbase - base64 implementation ------------------------------------------

/*
 *  RFC 1521 base64 encoding/decoding
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
#define MBEDTLS_BYTE_1(x) ((uint8_t) (((x) >>  8) & 0xff))
#define MBEDTLS_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))

#if !defined(MBEDTLS_CT_ASM)
volatile uint32_t mbedtls_ct_zero = 0;
#endif

static inline uint32_t mbedtls_ct_compiler_opaque(uint32_t x) {
#if defined(MBEDTLS_CT_ASM)
  asm volatile ("" : [x] "+r" (x) :);
  return x;
#else
  return x ^ mbedtls_ct_zero;
#endif
}

static inline unsigned char mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t) {
  const unsigned char co = (unsigned char) mbedtls_ct_compiler_opaque(c);
  const unsigned char to = (unsigned char) mbedtls_ct_compiler_opaque(t);
  unsigned low_mask = ((unsigned) co - low) >> 8;
  unsigned high_mask = ((unsigned) high - co) >> 8;
  return (unsigned char) (~(low_mask | high_mask)) & to;
}

unsigned char mbedtls_ct_base64_enc_char(unsigned char value) {
  unsigned char digit = 0;
  digit |= mbedtls_ct_uchar_in_range_if(0, 25, value, 'A' + value);
  digit |= mbedtls_ct_uchar_in_range_if(26, 51, value, 'a' + value - 26);
  digit |= mbedtls_ct_uchar_in_range_if(52, 61, value, '0' + value - 52);
  digit |= mbedtls_ct_uchar_in_range_if(62, 62, value, '+');
  digit |= mbedtls_ct_uchar_in_range_if(63, 63, value, '/');
  return digit;
}

signed char mbedtls_ct_base64_dec_value(unsigned char c) {
  unsigned char val = 0;
  val |= mbedtls_ct_uchar_in_range_if('A', 'Z', c, c - 'A' +  0 + 1);
  val |= mbedtls_ct_uchar_in_range_if('a', 'z', c, c - 'a' + 26 + 1);
  val |= mbedtls_ct_uchar_in_range_if('0', '9', c, c - '0' + 52 + 1);
  val |= mbedtls_ct_uchar_in_range_if('+', '+', c, c - '+' + 62 + 1);
  val |= mbedtls_ct_uchar_in_range_if('/', '/', c, c - '/' + 63 + 1);
  return val - 1;
}

int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen) {
  
  size_t i, n;
  int C1, C2, C3;
  unsigned char *p;
  
  if (slen == 0) {
    *olen = 0;
    return 0;
  }
  
  n = slen / 3 + (slen % 3 != 0);
  
  if (n > (SIZE_MAX - 1) / 4) {
    *olen = SIZE_MAX; return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
  }
  
  n *= 4;
  
  if ((dlen < n + 1) || (NULL == dst)) {
    *olen = n + 1;
    return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
  }
  
  n = (slen / 3) * 3;
  
  for (i = 0, p = dst; i < n; i += 3) {
    C1 = *src++;
    C2 = *src++;
    C3 = *src++;
    
    *p++ = mbedtls_ct_base64_enc_char((C1 >> 2) & 0x3F);
    *p++ = mbedtls_ct_base64_enc_char((((C1 &  3) << 4) + (C2 >> 4))
    & 0x3F);
    *p++ = mbedtls_ct_base64_enc_char((((C2 & 15) << 2) + (C3 >> 6))
    & 0x3F);
    *p++ = mbedtls_ct_base64_enc_char(C3 & 0x3F);
  }
  
  if (i < slen) {
    C1 = *src++;
    C2 = ((i + 1) < slen) ? *src++ : 0;
    
    *p++ = mbedtls_ct_base64_enc_char((C1 >> 2) & 0x3F);
    *p++ = mbedtls_ct_base64_enc_char((((C1 & 3) << 4) + (C2 >> 4))
    & 0x3F);
    
    if ((i + 1) < slen) {
      *p++ = mbedtls_ct_base64_enc_char(((C2 & 15) << 2) & 0x3F);
    } else {
      *p++ = '=';
    }
    
    *p++ = '=';
  }
  
  *olen = (size_t) (p - dst);
  *p = 0;
  
  return 0;
  
}

int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen) {
  
  size_t i;
  size_t n;
  uint32_t x;
  unsigned accumulated_digits = 0;
  unsigned equals = 0;
  int spaces_present = 0;
  unsigned char *p;

  for (i = n = 0; i < slen; i++) {
    spaces_present = 0;
    while (i < slen && src[i] == ' ') {
      ++i;
      spaces_present = 1;
    }

    if (i == slen) { break; }
    
    if ((slen - i) >= 2 &&
        src[i] == '\r' && src[i + 1] == '\n') {
      continue;
    }
    
    if (src[i] == '\n') {
      continue;
    }

    if (spaces_present) {
      return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
    }
    
    if (src[i] > 127) { return MBEDTLS_ERR_BASE64_INVALID_CHARACTER; }
    
    if (src[i] == '=') {
      if (++equals > 2) {
        return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
      }
    } else {
      if (equals != 0) {
        return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
      }
      if (mbedtls_ct_base64_dec_value(src[i]) < 0) {
        return MBEDTLS_ERR_BASE64_INVALID_CHARACTER;
      }
    }
    n++;
  }
  
  if (n == 0) {
    *olen = 0;
    return 0;
  }

  n = (6 * (n >> 3)) + ((6 * (n & 0x7) + 7) >> 3);
  n -= equals;
  
  if (dst == NULL || dlen < n) {
    *olen = n;
    return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
  }
  
  equals = 0;
  for (x = 0, p = dst; i > 0; i--, src++) {
    if (*src == '\r' || *src == '\n' || *src == ' ') {
      continue;
    }
    
    x = x << 6;
    if (*src == '=') {
      ++equals;
    } else {
      x |= mbedtls_ct_base64_dec_value(*src);
    }
    
    if (++accumulated_digits == 4) {
      accumulated_digits = 0;
      *p++ = MBEDTLS_BYTE_2(x);
      if (equals <= 1) {
        *p++ = MBEDTLS_BYTE_1(x);
      }
      if (equals <= 0) {
        *p++ = MBEDTLS_BYTE_0(x);
      }
    }
  }
  
  *olen = (size_t) (p - dst);
  
  return 0;
  
}

// secretbase - internals ------------------------------------------------------

static SEXP rawToChar(const unsigned char *buf, const size_t sz) {
  
  SEXP out;
  int i, j;
  for (i = 0, j = -1; i < sz; i++) if (buf[i]) j = i; else break;
  if (sz - i > 1) {
    REprintf("data could not be converted to a character string\n");
    out = Rf_allocVector(RAWSXP, sz);
    memcpy(SB_DATAPTR(out), buf, sz);
    return out;
  }
  
  PROTECT(out = Rf_allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE((const char *) buf, j + 1, CE_NATIVE));
  
  UNPROTECT(1);
  return out;
  
}

static inline void sb_read_bytes(R_inpstream_t stream, void *dst, int len) {
  
  nano_buf *buf = (nano_buf *) stream->data;
  if (buf->cur + len > buf->len) Rf_error("unserialization error");
  
  memcpy(dst, buf->buf + buf->cur, len);
  buf->cur += len;
  
}

static inline void sb_write_bytes(R_outpstream_t stream, void *src, int len) {
  
  nano_buf *buf = (nano_buf *) stream->data;
  
  size_t req = buf->cur + (size_t) len;
  if (req > buf->len) {
    if (req > R_XLEN_T_MAX) { ERROR_OUT(buf); }
    do {
      buf->len += buf->len > SB_SERIAL_THR ? SB_SERIAL_THR : buf->len;
    } while (buf->len < req);
    buf->buf = R_Realloc(buf->buf, buf->len, unsigned char);
  }
  
  memcpy(buf->buf + buf->cur, src, len);
  buf->cur += len;
  
}

static void sb_serialize(nano_buf *buf, const SEXP object) {
  
  NANO_ALLOC(buf, SB_INIT_BUFSIZE);
  
  struct R_outpstream_st output_stream;
  
  R_InitOutPStream(
    &output_stream,
    (R_pstream_data_t) buf,
    R_pstream_xdr_format,
    SB_R_SERIAL_VER,
    NULL,
    sb_write_bytes,
    NULL,
    R_NilValue
  );
  
  R_Serialize(object, &output_stream);
  
}

static SEXP sb_unserialize(unsigned char *buf, const size_t sz) {

  nano_buf nbuf;
  struct R_inpstream_st input_stream;
  
  nbuf.buf = buf;
  nbuf.len = sz;
  nbuf.cur = 0;
  
  R_InitInPStream(
    &input_stream,
    (R_pstream_data_t) &nbuf,
    R_pstream_xdr_format,
    NULL,
    sb_read_bytes,
    NULL,
    R_NilValue
  );
  
  return R_Unserialize(&input_stream);
  
}

static nano_buf sb_any_buf(const SEXP x) {
  
  nano_buf buf;
  
  switch (TYPEOF(x)) {
  case STRSXP:
    if (XLENGTH(x) == 1 && !ANY_ATTRIB(x)) {
      const char *s = SB_STRING(x);
      NANO_INIT(&buf, (unsigned char *) s, strlen(s));
      goto resume;
    }
    break;
  case RAWSXP:
    if (!ANY_ATTRIB(x)) {
      NANO_INIT(&buf, (unsigned char *) DATAPTR_RO(x), XLENGTH(x));
      goto resume;
    }
  }
  
  sb_serialize(&buf, x);
  
  resume:
  return buf;
  
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_base64enc(SEXP x, SEXP convert) {
  
  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  int xc;
  SEXP out;
  size_t olen;
  
  nano_buf hash = sb_any_buf(x);
  xc = mbedtls_base64_encode(NULL, 0, &olen, hash.buf, hash.cur);
  unsigned char *buf = R_Calloc(olen, unsigned char);
  xc = mbedtls_base64_encode(buf, olen, &olen, hash.buf, hash.cur);
  NANO_FREE(hash);
  CHECK_ERROR(xc);
  
  if (conv) {
    out = rawToChar(buf, olen);
  } else {
    out = Rf_allocVector(RAWSXP, olen);
    memcpy(SB_DATAPTR(out), buf, olen);
  }
  
  R_Free(buf);
  
  return out;
  
}

SEXP secretbase_base64dec(SEXP x, SEXP convert) {
  
  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  int xc;
  unsigned char *inbuf;
  SEXP out;
  size_t inlen, olen;
  
  switch (TYPEOF(x)) {
  case STRSXP:
    inbuf = (unsigned char *) SB_STRING(x);
    inlen = XLENGTH(*((const SEXP *) DATAPTR_RO(x)));
    break;
  case RAWSXP:
    inbuf = RAW(x);
    inlen = XLENGTH(x);
    break;
  default:
    Rf_error("input is not valid base64");
  }
  
  xc = mbedtls_base64_decode(NULL, 0, &olen, inbuf, inlen);
  if (xc == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
    Rf_error("input is not valid base64");
  unsigned char *buf = R_Calloc(olen, unsigned char);
  xc = mbedtls_base64_decode(buf, olen, &olen, inbuf, inlen);
  CHECK_ERROR(xc);
  
  switch (conv) {
  case 0:
    out = Rf_allocVector(RAWSXP, olen);
    memcpy(SB_DATAPTR(out), buf, olen);
    break;
  case 1:
    out = rawToChar(buf, olen);
    break;
  default:
    out = sb_unserialize(buf, olen);
  }
  
  R_Free(buf);
  
  return out;
  
}
