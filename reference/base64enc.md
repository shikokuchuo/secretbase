# Base64 Encode

Encodes a character string, raw vector or other object to base64
encoding.

## Usage

``` r
base64enc(x, convert = TRUE, url = FALSE)
```

## Arguments

- x:

  an object.

- convert:

  logical `TRUE` to encode to a character string or `FALSE` to a raw
  vector.

- url:

  logical `TRUE` to use the URL- and filename-safe base64url alphabet
  without padding, or `FALSE` (the default) for standard base64.

## Value

A character string or raw vector depending on the value of `convert`.

## Details

A character string or raw vector (with no attributes) is encoded as is,
whilst all other objects are first serialized (using R serialisation
version 3, big-endian representation).

Set `url = TRUE` for the URL- and filename-safe variant (RFC 4648
section 5), which substitutes `-` and `_` for `+` and `/` and omits
padding (`=`), making the output safe to use within URLs and filenames
without further escaping.

## References

This implementation is based that by 'The Mbed TLS Contributors' under
the 'Mbed TLS' Trusted Firmware Project at
<https://www.trustedfirmware.org/projects/mbed-tls>.

## See also

[`base64dec()`](https://shikokuchuo.net/secretbase/reference/base64dec.md)

## Examples

``` r
base64enc("secret base")
#> [1] "c2VjcmV0IGJhc2U="
base64enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#> [1] 41 51 49 45
base64enc(data.frame())
#> [1] "WAoAAAADAAQGAAADBQAAAAAFVVRGLTgAAAMTAAAAAAAABAIAAAABAAQACQAAAAVuYW1lcwAAABAAAAAAAAAEAgAAAAEABAAJAAAACXJvdy5uYW1lcwAAAA0AAAAAAAAEAgAAAAEABAAJAAAABWNsYXNzAAAAEAAAAAEABAAJAAAACmRhdGEuZnJhbWUAAAD+"
base64enc("secret base", url = TRUE)
#> [1] "c2VjcmV0IGJhc2U"
```
