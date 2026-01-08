# SHA-3 Cryptographic Hash Algorithms

Returns a SHA-3 hash of the supplied object or file.

## Usage

``` r
sha3(x, bits = 256L, convert = TRUE, file)
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

The SHA-3 Secure Hash Standard was published by the National Institute
of Standards and Technology (NIST) in 2015 at
[doi:10.6028/NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202) .

This implementation is based on one by 'The Mbed TLS Contributors' under
the 'Mbed TLS' Trusted Firmware Project at
<https://www.trustedfirmware.org/projects/mbed-tls>.

## Examples

``` r
# SHA3-256 hash as character string:
sha3("secret base")
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"

# SHA3-256 hash as raw vector:
sha3("secret base", convert = FALSE)
#>  [1] a7 21 d5 75 70 e7 ce 36 6a de e2 fc cb e9 77 07 23 c6 e3 62 25 49 c3 1c 7c
#> [26] ab 9d bb 4a 79 55 20

# SHA3-224 hash as character string:
sha3("secret base", bits = 224)
#> [1] "5511b3469d3f1a87b62ce8f0d2dc9510ec5e4547579b8afb32052f99"

# SHA3-384 hash as character string:
sha3("secret base", bits = 384)
#> [1] "79e54f865df004dde10dc2f61baf47eb4637c68d87a2baeb7fe6bc0ac983c2154835ec7deb49b16c246c0dc1d43e32f9"

# SHA3-512 hash as character string:
sha3("secret base", bits = 512)
#> [1] "31076b4690961320a761be0951eeaa9efd0c75c37137a2a50877cbebb8afcc6d7927c41a120ae8fa73fdce8fff726fcbc51d448d020240bc7455963a16e639b1"

# SHA3-256 hash a file:
file <- tempfile(); cat("secret base", file = file)
sha3(file = file)
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"
unlink(file)
```
