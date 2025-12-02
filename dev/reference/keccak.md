# Keccak Cryptographic Hash Algorithms

Returns a Keccak hash of the supplied object or file.

## Usage

``` r
keccak(x, bits = 256L, convert = TRUE, file)
```

## Arguments

- x:

  object to hash. A character string or raw vector (without attributes)
  is hashed as is. All other objects are stream hashed using native R
  serialization.

- bits:

  integer output size of the returned hash. Must be one of `224`, `256`,
  `384` or `512`.

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

Keccak is the underlying algorithm for SHA-3, and is identical apart
from the value of the padding parameter.

The Keccak algorithm was designed by G. Bertoni, J. Daemen, M. Peeters
and G. Van Assche.

This implementation is based on one by 'The Mbed TLS Contributors' under
the 'Mbed TLS' Trusted Firmware Project at
<https://www.trustedfirmware.org/projects/mbed-tls>.

## Examples

``` r
# Keccak-256 hash as character string:
keccak("secret base")
#> [1] "3fc6092bbec5a434a9933b486a89fa466c1ca013d1e37ab4348ce3764f3463d1"

# Keccak-256 hash as raw vector:
keccak("secret base", convert = FALSE)
#>  [1] 3f c6 09 2b be c5 a4 34 a9 93 3b 48 6a 89 fa 46 6c 1c a0 13 d1 e3 7a b4 34
#> [26] 8c e3 76 4f 34 63 d1

# Keccak-224 hash as character string:
keccak("secret base", bits = 224)
#> [1] "1ddaa7776f138ff5bba898ca7530410a52d09da412c4276bda0682a8"

# Keccak-384 hash as character string:
keccak("secret base", bits = 384)
#> [1] "c82bae24175676028e44aa08b9e2424311847adb0b071c68c7ea47edf049b0e935ddd2fc7c499333bccc08c7eb7b1203"

# Keccak-512 hash as character string:
keccak("secret base", bits = 512)
#> [1] "38297e891d9118e4cf6ff5ba6d6de8c2c3bfa790b425848da7b1d8dffcb4a6a3ca2e32ca0a66f36ce2882786ce2299642de8ffd3bae3b51a1ee145fad555a9d8"

# Keccak-256 hash a file:
file <- tempfile(); cat("secret base", file = file)
keccak(file = file)
#> [1] "3fc6092bbec5a434a9933b486a89fa466c1ca013d1e37ab4348ce3764f3463d1"
unlink(file)
```
