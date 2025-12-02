# SHAKE256 Extendable Output Function

Returns a SHAKE256 hash of the supplied object or file.

## Usage

``` r
shake256(x, bits = 256L, convert = TRUE, file)
```

## Arguments

- x:

  object to hash. A character string or raw vector (without attributes)
  is hashed as is. All other objects are stream hashed using native R
  serialization.

- bits:

  integer output size of the returned hash. Value must be between `8`
  and `2^24`.

- convert:

  logical `TRUE` to convert the hash to its hex representation as a
  character string, `FALSE` to return directly as a raw vector, or `NA`
  to return as a vector of (32-bit) integers.

- file:

  character file name / path. If specified, `x` is ignored. The file is
  stream hashed, and the file can be larger than memory.

## Value

A character string, raw or integer vector depending on `convert`.

## Details

To produce single integer values suitable for use as random seeds for
R's pseudo random number generators (RNGs), set `bits` to `32` and
`convert` to `NA`.

## R Serialization Stream Hashing

Where this is used, serialization is always version 3 big-endian
representation and the headers (containing R version and native encoding
information) are skipped to ensure portability across platforms.

As hashing is performed in a streaming fashion, there is no
materialization of, or memory allocation for, the serialized object.

## References

This implementation is based on one by 'The Mbed TLS Contributors' under
the 'Mbed TLS' Trusted Firmware Project at
<https://www.trustedfirmware.org/projects/mbed-tls>.

## Examples

``` r
# SHAKE256 hash as character string:
shake256("secret base")
#> [1] "995ebac18dbfeb170606cbbc0f2accce85db4db0dcf4fbe4d3efaf8ccf4e0a94"

# SHAKE256 hash as raw vector:
shake256("secret base", convert = FALSE)
#>  [1] 99 5e ba c1 8d bf eb 17 06 06 cb bc 0f 2a cc ce 85 db 4d b0 dc f4 fb e4 d3
#> [26] ef af 8c cf 4e 0a 94

# SHAKE256 hash to integer:
shake256("secret base", bits = 32L, convert = NA)
#> [1] -1044750695

# SHAKE256 hash a file:
file <- tempfile(); cat("secret base", file = file)
shake256(file = file)
#> [1] "995ebac18dbfeb170606cbbc0f2accce85db4db0dcf4fbe4d3efaf8ccf4e0a94"
unlink(file)
```
