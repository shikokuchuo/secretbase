# Base58 Encode

Encodes a character string, raw vector or other object to base58
encoding with a 4-byte checksum suffix.

## Usage

``` r
base58enc(x, convert = TRUE)
```

## Arguments

- x:

  an object.

- convert:

  logical `TRUE` to encode to a character string or `FALSE` to a raw
  vector.

## Value

A character string or raw vector depending on the value of `convert`.

## Details

Adds a 4-byte checksum suffix (double SHA-256) to the data before base58
encoding. Note: does not include a version byte prefix (unlike Bitcoin
Base58Check).

A character string or raw vector (with no attributes) is encoded as is,
whilst all other objects are first serialized (using R serialisation
version 3, big-endian representation).

## References

This implementation is based on 'libbase58' by Luke Dashjr under the MIT
licence at <https://github.com/luke-jr/libbase58>.

## See also

[`base58dec()`](https://shikokuchuo.net/secretbase/reference/base58dec.md)

## Examples

``` r
base58enc("secret base")
#> [1] "4EFRHUcj9ookBnv1yX9Gt"
base58enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#> [1] 33 44 56 41 66 71 55 64 77
base58enc(data.frame())
#> [1] "Z8bXTedt3w8TXknTyHvEp3k2yLQSqwwCJo1DCJDdQDNTA2HnhawihpPfu6zvEtSZgbUQp6zNvkwYcmroBAEjiZ4Q868KbwNdWJUTHroRYUs623DhtEbncedpUpeZwTAKXsRwHQ4keuY2e27DNkh79aftTQJZa4gP2GmiDTH22oFxLxSZufU6UbqGxsfRJSvJfvWodeAg9b"
```
