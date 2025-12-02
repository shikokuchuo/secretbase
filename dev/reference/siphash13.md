# SipHash Pseudorandom Function

Returns a fast, cryptographically-strong SipHash keyed hash of the
supplied object or file. SipHash-1-3 is optimised for performance. Note:
SipHash is not a cryptographic hash algorithm.

## Usage

``` r
siphash13(x, key = NULL, convert = TRUE, file)
```

## Arguments

- x:

  object to hash. A character string or raw vector (without attributes)
  is hashed as is. All other objects are stream hashed using native R
  serialization.

- key:

  a character string or raw vector comprising the 16 byte (128 bit) key
  data, or else `NULL` which is equivalent to `0`. If a longer vector is
  supplied, only the first 16 bytes are used, and if shorter, padded
  with trailing '0'. Note: for character vectors, only the first element
  is used.

- convert:

  logical `TRUE` to convert the hash to its hex representation as a
  character string, `FALSE` to return directly as a raw vector, or `NA`
  to return as a vector of (32-bit) integers.

- file:

  character file name / path. If specified, `x` is ignored. The file is
  stream hashed, and the file can be larger than memory.

## Value

A character string, raw or integer vector depending on `convert`.

## R Serialization Stream Hashing

Where this is used, serialization is always version 3 big-endian
representation and the headers (containing R version and native encoding
information) are skipped to ensure portability across platforms.

As hashing is performed in a streaming fashion, there is no
materialization of, or memory allocation for, the serialized object.

## References

The SipHash family of cryptographically-strong pseudorandom functions
(PRFs) are described in 'SipHash: a fast short-input PRF', Jean-Philippe
Aumasson and Daniel J. Bernstein, Paper 2012/351, 2012, Cryptology
ePrint Archive at <https://ia.cr/2012/351>.

This implementation is based on the SipHash streaming implementation by
Daniele Nicolodi, David Rheinsberg and Tom Gundersen at
<https://github.com/c-util/c-siphash>. This is in turn based on the
SipHash reference implementation by Jean-Philippe Aumasson and Daniel J.
Bernstein released to the public domain at
<https://github.com/veorq/SipHash>.

## Examples

``` r
# SipHash-1-3 hash as character string:
siphash13("secret base")
#> [1] "48c60a316babef0e"

# SipHash-1-3 hash as raw vector:
siphash13("secret base", convert = FALSE)
#> [1] 48 c6 0a 31 6b ab ef 0e

# SipHash-1-3 hash using a character string key:
siphash13("secret", key = "base")
#> [1] "a790b03148f72cce"

# SipHash-1-3 hash using a raw vector key:
siphash13("secret", key = charToRaw("base"))
#> [1] "a790b03148f72cce"

# SipHash-1-3 hash a file:
file <- tempfile(); cat("secret base", file = file)
siphash13(file = file)
#> [1] "48c60a316babef0e"
unlink(file)
```
