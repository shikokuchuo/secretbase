# CBOR Decode

Decode CBOR (Concise Binary Object Representation, RFC 8949) data to an
R object.

## Usage

``` r
cbordec(x)
```

## Arguments

- x:

  A raw vector containing CBOR-encoded data.

## Value

The decoded R object.

## Details

CBOR types map to R types as follows:

- Integers: integer (if within range) or double

- Byte strings: raw vectors

- Text strings: character

- Arrays: lists

- Maps: named lists (keys must be text strings)

- false/true: logical

- null: NULL

- Float32/Float64: double

## See also

[`cborenc()`](https://shikokuchuo.net/secretbase/dev/reference/cborenc.md)

## Examples

``` r
# Round-trip encoding
original <- list(a = 1L, b = "test", c = TRUE)
cbordec(cborenc(original))
#> $a
#> [1] 1
#> 
#> $b
#> [1] "test"
#> 
#> $c
#> [1] TRUE
#> 
```
