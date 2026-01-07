# Changelog

## secretbase (development version)

- Adds
  [`cborenc()`](https://shikokuchuo.net/secretbase/dev/reference/cborenc.md)
  and
  [`cbordec()`](https://shikokuchuo.net/secretbase/dev/reference/cbordec.md)
  for CBOR (RFC 8949) encoding/decoding, supporting integers, floats,
  strings, raw vectors, lists and simple values.
- Adds
  [`base58enc()`](https://shikokuchuo.net/secretbase/dev/reference/base58enc.md)
  and
  [`base58dec()`](https://shikokuchuo.net/secretbase/dev/reference/base58dec.md)
  for base58 encoding/decoding with a 4-byte double SHA-256 checksum.

## secretbase 1.0.5

CRAN release: 2025-03-04

- Package is re-licensed under the MIT licence.

## secretbase 1.0.4

CRAN release: 2025-01-16

- [`base64dec()`](https://shikokuchuo.net/secretbase/dev/reference/base64dec.md)
  now errors if `convert = TRUE` and conversion to a character string
  fails, no longer returning a raw vector (accompanied by a warning).

## secretbase 1.0.3

CRAN release: 2024-10-02

- [`base64dec()`](https://shikokuchuo.net/secretbase/dev/reference/base64dec.md)
  now emits a suppressable warning when failing to convert back to a
  character string.

## secretbase 1.0.2

CRAN release: 2024-09-09

- Improves hash performance in most situations, especially for large
  files, by optimizing buffer sizes.

## secretbase 1.0.1

CRAN release: 2024-07-22

- Improved error message if argument ‘convert’ is not of logical type.

## secretbase 1.0.0

CRAN release: 2024-06-16

- Adds base64 encoding and decoding.
- [`sha3()`](https://shikokuchuo.net/secretbase/dev/reference/sha3.md)
  restricts ‘bit’ argument to one of 224, 256, 384 or 512.

## secretbase 0.5.0

CRAN release: 2024-04-25

- Adds Keccak cryptographic hash algorithm.
- Adds
  [`shake256()`](https://shikokuchuo.net/secretbase/dev/reference/shake256.md)
  to delineate from
  [`sha3()`](https://shikokuchuo.net/secretbase/dev/reference/sha3.md).
- Use of
  [`sha3()`](https://shikokuchuo.net/secretbase/dev/reference/sha3.md)
  supplying ‘bit’ argument other than 224, 256, 384 or 512 is
  deprecated.

## secretbase 0.4.0

CRAN release: 2024-04-04

- Adds HMAC generation to
  [`sha256()`](https://shikokuchuo.net/secretbase/dev/reference/sha256.md).
- Adds SipHash pseudo-random function (PRF) as a fast,
  cryptographically-strong keyed hash.

## secretbase 0.3.0.1

CRAN release: 2024-03-01

- CRAN release correcting for Clang-UBSAN checks.

## secretbase 0.3.0

CRAN release: 2024-02-21

- Adds SHA-256 cryptographic hash algorithm.
- Folds file hashing into the ‘file’ argument of the main hash function.

## secretbase 0.2.0

CRAN release: 2024-02-01

- Adds file hashing interface.

## secretbase 0.1.0

CRAN release: 2024-01-22

- Initial CRAN release.

## secretbase 0.0.1

- Initial release to rOpenSci R-universe and Github.
