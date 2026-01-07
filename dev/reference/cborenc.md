# CBOR Encode

Encode an R object to CBOR (Concise Binary Object Representation, RFC
8949) format.

## Usage

``` r
cborenc(x)
```

## Arguments

- x:

  R object to encode. Supported types: NULL, logical, integer, double,
  character, raw vectors, and lists (named lists become CBOR maps,
  unnamed become CBOR arrays).

## Value

A raw vector containing the CBOR-encoded data.

## Details

This implementation supports a minimal CBOR subset:

- Unsigned and negative integers

- Float64

- Byte strings (raw vectors)

- Text strings (UTF-8)

- Simple values: false, true, null, undefined

- Arrays (unnamed lists/vectors)

- Maps (named lists)

Scalars (length-1 vectors without attributes) encode as their CBOR
scalar equivalents. Vectors with length \> 1 or attributes encode as
CBOR arrays. NA values encode as CBOR undefined (which decodes back to
NA).

## See also

[`cbordec()`](https://shikokuchuo.net/secretbase/dev/reference/cbordec.md)

## Examples

``` r
# Encode a named list (becomes CBOR map)
cborenc(list(a = 1L, b = "hello"))
#>  [1] a2 61 61 01 61 62 65 68 65 6c 6c 6f

# Round-trip
cbordec(cborenc(list(x = TRUE, y = as.raw(1:3))))
#> $x
#> [1] TRUE
#> 
#> $y
#> [1] 01 02 03
#> 
```
