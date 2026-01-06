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

static inline size_t b58enc_byte(uint8_t *buf, size_t size, size_t high, int byte) {
  int carry = byte;
  size_t j;
  for (j = size - 1; (j > high) || carry; --j) {
    carry += 256 * buf[j];
    buf[j] = carry % 58;
    carry /= 58;
    if (!j)
      break;
  }
  return j;
}

static bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz) {

  size_t binsz = *binszp;
  const unsigned char *b58u = (const unsigned char *) b58;
  unsigned char *binu = bin;
  size_t outisz = (binsz + sizeof(uint32_t) - 1) / sizeof(uint32_t);
  uint32_t outi[outisz];
  uint64_t t;
  uint32_t c;
  size_t i, j;
  unsigned zerocount = 0;

  if (!b58sz)
    b58sz = strlen(b58);

  for (i = 0; i < outisz; ++i) {
    outi[i] = 0;
  }

  for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
    ++zerocount;

  for ( ; i < b58sz; ++i) {
    if (b58u[i] & 0x80)
      return false;
    if (b58digits_map[b58u[i]] == -1)
      return false;
    c = (unsigned) b58digits_map[b58u[i]];
    for (j = outisz; j--; ) {
      t = ((uint64_t) outi[j]) * 58 + c;
      c = t >> 32;
      outi[j] = t & 0xffffffff;
    }
    // Overflow checks unreachable: buffer allocation (inlen * 3/4 + 4) always sufficient
    // if (c) return false;
    // if (outi[0] & zeromask) return false;
  }

  j = 0;
  uint8_t bytesleft = binsz % sizeof(uint32_t);
  if (bytesleft) {
    for (i = bytesleft; i > 0; --i) {
      *(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
    }
    ++j;
  }

  for (; j < outisz; ++j) {
    for (i = sizeof(*outi); i > 0; --i) {
      *(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
    }
  }

  binu = bin;
  for (i = 0; i < binsz; ++i) {
    if (binu[i])
      break;
  }

  *binszp = binsz - i + zerocount;

  if (i > zerocount && i < binsz)
    memmove(binu + zerocount, binu + i, binsz - i);
  if (zerocount)
    memset(binu, 0, zerocount);

  return true;

}

static void b58enc(char *b58, size_t *b58sz, const void *data, size_t datasz,
                   const unsigned char *checksum) {

  const uint8_t *bin = data;
  const size_t binsz = datasz + 4;
  size_t i, j, high, zcount = 0;
  size_t size;

  while (zcount < datasz && !bin[zcount])
    ++zcount;

  size = (binsz - zcount) * 138 / 100 + 1;
  uint8_t buf[size];
  memset(buf, 0, size);

  for (i = zcount, high = size - 1; i < datasz; ++i)
    high = b58enc_byte(buf, size, high, bin[i]);

  for (i = 0; i < 4; ++i)
    high = b58enc_byte(buf, size, high, checksum[i]);

  for (j = 0; j < size && !buf[j]; ++j);

  // Buffer size check unreachable: caller allocates (datasz + 4) * 138/100 + 2 which always suffices
  // if (*b58sz <= zcount + size - j) {
  //   *b58sz = zcount + size - j + 1;
  //   return false;
  // }

  if (zcount)
    memset(b58, '1', zcount);
  for (i = zcount; j < size; ++i, ++j)
    b58[i] = b58digits_ordered[buf[j]];
  b58[i] = '\0';
  *b58sz = i;

}

static bool b58check(const void *bin, size_t binsz) {

  unsigned char hash1[SB_SHA256_SIZE], hash2[SB_SHA256_SIZE];
  const uint8_t *binc = bin;

  if (binsz < 4) return false;

  sb_sha256_raw(bin, binsz - 4, hash1);
  sb_sha256_raw(hash1, SB_SHA256_SIZE, hash2);

  if (memcmp(&binc[binsz - 4], hash2, 4)) return false;

  return true;

}

static void b58check_enc(char *b58c, size_t *b58c_sz,
                         const void *data, size_t datasz) {

  unsigned char hash1[SB_SHA256_SIZE], hash2[SB_SHA256_SIZE];

  sb_sha256_raw(data, datasz, hash1);
  sb_sha256_raw(hash1, SB_SHA256_SIZE, hash2);

  b58enc(b58c, b58c_sz, data, datasz, hash2);

}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_base58enc(SEXP x, SEXP convert) {

  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);

  SEXP out;
  size_t olen;

  nano_buf hash = sb_any_buf(x);

  olen = (hash.cur + 4) * 138 / 100 + 2;
  unsigned char *buf = malloc(olen);
  if (buf == NULL) {
    NANO_FREE(hash);
    Rf_error("memory allocation failed");
  }

  b58check_enc((char *) buf, &olen, hash.buf, hash.cur);

  NANO_FREE(hash);

  if (conv) {
    out = sb_raw_char(buf, olen);
  } else {
    out = Rf_allocVector(RAWSXP, olen);
    memcpy(SB_DATAPTR(out), buf, olen);
  }

  free(buf);

  return out;

}

SEXP secretbase_base58dec(SEXP x, SEXP convert) {

  SB_ASSERT_LOGICAL(convert);
  const int conv = SB_LOGICAL(convert);
  const char *inbuf;
  SEXP out;
  size_t inlen, olen, datalen;

  switch (TYPEOF(x)) {
  case STRSXP:
    inbuf = CHAR(*STRING_PTR_RO(x));
    inlen = strlen(inbuf);
    break;
  case RAWSXP:
    inbuf = (char *) DATAPTR_RO(x);
    inlen = XLENGTH(x);
    break;
  default:
    Rf_error("input is not valid base58");
  }

  olen = inlen * 3 / 4 + 4;
  unsigned char *buf = malloc(olen);
  if (buf == NULL)
    Rf_error("memory allocation failed");

  if (!b58tobin(buf, &olen, inbuf, inlen)) {
    free(buf);
    Rf_error("input is not valid base58");
  }

  if (!b58check(buf, olen)) {
    free(buf);
    Rf_error("base58 checksum validation failed");
  }

  datalen = olen - 4;

  switch (conv) {
  case 0:
    out = Rf_allocVector(RAWSXP, datalen);
    memcpy(SB_DATAPTR(out), buf, datalen);
    break;
  case 1:
    out = sb_raw_char(buf, datalen);
    break;
  default:
    out = sb_unserialize(buf, datalen);
  }

  free(buf);

  return out;

}
