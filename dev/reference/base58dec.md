# Base58 Decode

Decodes a character string or raw vector from base58 encoding with
checksum.

## Usage

``` r
base58dec(x, convert = TRUE)
```

## Arguments

- x:

  a character string or raw vector containing base58 encoded data.

- convert:

  logical `TRUE` to convert back to a character string, `FALSE` to
  convert back to a raw vector or `NA` to decode and then unserialize
  back to the original object.

## Value

A character string, raw vector, or other object depending on the value
of `convert`.

## Details

The 4-byte checksum suffix is verified using double SHA-256 and an error
is raised if validation fails. Note: does not expect a version byte
prefix (unlike Bitcoin Base58Check).

The value of `convert` should be set to `TRUE`, `FALSE` or `NA` to be
the reverse of the 3 encoding operations (for strings, raw vectors and
arbitrary objects), in order to return the original object.

## References

This implementation is based on 'libbase58' by Luke Dashjr under the MIT
licence at <https://github.com/luke-jr/libbase58>.

## See also

[`base58enc()`](https://shikokuchuo.net/secretbase/dev/reference/base58enc.md)

## Examples

``` r
base58dec(base58enc("secret base"))
#> [1] "secret base"
base58dec(base58enc(as.raw(c(1L, 2L, 4L))), convert = FALSE)
#> [1] 01 02 04
base58dec(base58enc(data.frame()), convert = NA)
#> data frame with 0 columns and 0 rows
```
