// secretbase ------------------------------------------------------------------

#include "secret.h"

// secretbase - base58 implementation ------------------------------------------

/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 *
 * libbase58 - https://github.com/bitcoin/libbase58
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const int8_t b58digits_map[] = {
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
  -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
  -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
  22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
  -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
  47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

static const char b58digits_ordered[] =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz) {

  size_t binsz = *binszp;
  const unsigned char *b58u = (const unsigned char *) b58;
  unsigned char *binu = bin;
  size_t outisz = (binsz + sizeof(uint32_t) - 1) / sizeof(uint32_t);
  uint32_t *outi = R_Calloc(outisz, uint32_t);
  uint64_t t;
  uint32_t c;
  size_t i, j;
  uint8_t bytesleft = binsz % sizeof(uint32_t);
  uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
  unsigned zerocount = 0;

  if (!b58sz) b58sz = strlen(b58);

  for (i = 0; i < outisz; ++i) outi[i] = 0;

  for (i = 0; i < b58sz && b58u[i] == '1'; ++i) ++zerocount;

  for ( ; i < b58sz; ++i) {
    if (b58u[i] & 0x80) { R_Free(outi); return false; }
    if (b58digits_map[b58u[i]] == -1) { R_Free(outi); return false; }
    c = (unsigned) b58digits_map[b58u[i]];
    for (j = outisz; j--; ) {
      t = ((uint64_t) outi[j]) * 58 + c;
      c = (uint32_t) (t >> 32);
      outi[j] = (uint32_t) (t & 0xffffffff);
    }
    if (c) { R_Free(outi); return false; }
    if (outi[0] & zeromask) { R_Free(outi); return false; }
  }

  j = 0;
  if (bytesleft) {
    for (i = bytesleft; i > 0; --i) {
      *(binu++) = (uint8_t) ((outi[0] >> (8 * (i - 1))) & 0xff);
    }
    ++j;
  }

  for (; j < outisz; ++j) {
    for (i = sizeof(uint32_t); i > 0; --i) {
      *(binu++) = (uint8_t) ((outi[j] >> (8 * (i - 1))) & 0xff);
    }
  }

  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i]) break;
  }

  *binszp = binsz - i + zerocount;

  if (i > zerocount) {
    memmove(binu + zerocount, binu + i, binsz - i);
  } else if (i < zerocount) {
    memmove(binu + zerocount, binu + i, binsz - i);
  }

  memset(binu, 0, zerocount);

  R_Free(outi);
  return true;

}

static bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {

  const uint8_t *bin = data;
  int carry;
  size_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < binsz && !bin[zcount]) ++zcount;

  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t *buf = R_Calloc(size, uint8_t);
  memset(buf, 0, size);

  for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
    for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
      carry += 256 * buf[j];
      buf[j] = carry % 58;
      carry /= 58;
      if (!j) break;
    }
  }

  for (j = 0; j < size && !buf[j]; ++j);

  if (*b58sz <= zcount + size - j) {
    R_Free(buf);
    *b58sz = zcount + size - j + 1;
    return false;
  }

  if (zcount) memset(b58, '1', zcount);
  for (i = zcount; j < size; ++i, ++j) b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i;

  R_Free(buf);
  return true;

}

// secretbase - base58check functions ------------------------------------------

static bool b58check(const void *bin, size_t binsz, const char *b58, size_t b58sz) {

  unsigned char hash1[SB_SHA256_SIZE], hash2[SB_SHA256_SIZE];
  const uint8_t *binc = bin;

  if (binsz < 4) return false;

  sb_sha256_raw(bin, binsz - 4, hash1);
  sb_sha256_raw(hash1, SB_SHA256_SIZE, hash2);

  if (memcmp(&binc[binsz - 4], hash2, 4)) return false;

  return true;

}

static bool b58check_enc(char *b58c, size_t *b58c_sz, uint8_t ver,
                         const void *data, size_t datasz) {

  unsigned char hash1[SB_SHA256_SIZE], hash2[SB_SHA256_SIZE];
  uint8_t *buf = R_Calloc(1 + datasz + 4, uint8_t);

  buf[0] = ver;
  memcpy(&buf[1], data, datasz);

  sb_sha256_raw(buf, 1 + datasz, hash1);
  sb_sha256_raw(hash1, SB_SHA256_SIZE, hash2);

  memcpy(&buf[1 + datasz], hash2, 4);

  bool ret = b58enc(b58c, b58c_sz, buf, 1 + datasz + 4);

  R_Free(buf);
  return ret;

}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_base58enc(SEXP x, SEXP convert) {

  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);

  SEXP out;
  size_t olen;

  nano_buf hash = sb_any_buf(x);

  // data + version byte + 4-byte checksum
  olen = (1 + hash.cur + 4) * 138 / 100 + 2;
  unsigned char *buf = R_Calloc(olen, unsigned char);

  if (!b58check_enc((char *) buf, &olen, 0, hash.buf, hash.cur)) {
    NANO_FREE(hash);
    R_Free(buf);
    Rf_error("base58check encoding failed");
  }

  NANO_FREE(hash);

  if (conv) {
    out = sb_raw_char(buf, olen);
  } else {
    out = Rf_allocVector(RAWSXP, olen);
    memcpy(SB_DATAPTR(out), buf, olen);
  }

  R_Free(buf);

  return out;

}

SEXP secretbase_base58dec(SEXP x, SEXP convert) {

  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  char *inbuf;
  SEXP out;
  size_t inlen, olen, datalen;

  switch (TYPEOF(x)) {
  case STRSXP: ;
    const char *str = CHAR(*STRING_PTR_RO(x));
    inbuf = (char *) str;
    inlen = strlen(str);
    break;
  case RAWSXP:
    inbuf = (char *) RAW(x);
    inlen = XLENGTH(x);
    break;
  default:
    Rf_error("input is not valid base58");
  }

  olen = inlen * 733 / 1000 + 1;
  unsigned char *buf = R_Calloc(olen, unsigned char);

  if (!b58tobin(buf, &olen, inbuf, inlen)) {
    R_Free(buf);
    Rf_error("input is not valid base58");
  }

  if (!b58check(buf, olen, inbuf, inlen)) {
    R_Free(buf);
    Rf_error("base58 checksum validation failed");
  }

  // Data excludes version byte (1) and checksum (4)
  if (olen < 5) {
    R_Free(buf);
    Rf_error("base58 data too short");
  }

  datalen = olen - 5;

  switch (conv) {
  case 0:
    out = Rf_allocVector(RAWSXP, datalen);
    memcpy(SB_DATAPTR(out), buf + 1, datalen);
    break;
  case 1:
    out = sb_raw_char(buf + 1, datalen);
    break;
  default:
    out = sb_unserialize(buf + 1, datalen);
  }

  R_Free(buf);

  return out;

}
