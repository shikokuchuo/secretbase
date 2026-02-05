# JSON Encode

Minimal JSON encoder. Converts an R object to a JSON string.

## Usage

``` r
jsonenc(x)
```

## Arguments

- x:

  An R object to encode as JSON.

## Value

A character string containing the JSON representation.

## Details

This is a minimal implementation designed for creating HTTP API request
bodies.

## Type Mappings

- Named list -\> object [`{}`](https://rdrr.io/r/base/Paren.html)

- Unnamed list -\> array `[]`

- Character -\> string (with escaping)

- Numeric/integer -\> number

- Logical -\> `true`/`false`

- `NULL`, `NA` -\> `null`

- Scalars (length 1) -\> primitive value

- Vectors (length \> 1) -\> array `[]`

- Unsupported types (e.g., functions) -\> `null`

## See also

[`jsondec()`](https://shikokuchuo.net/secretbase/reference/jsondec.md)

## Examples

``` r
jsonenc(list(name = "John", age = 30L))
#> [1] "{\"name\":\"John\",\"age\":30}"
jsonenc(list(valid = TRUE, count = NULL))
#> [1] "{\"valid\":true,\"count\":null}"
jsonenc(list(nested = list(a = 1, b = list(2, 3))))
#> [1] "{\"nested\":{\"a\":1,\"b\":[2,3]}}"
jsonenc(list(nums = 1:3, strs = c("a", "b")))
#> [1] "{\"nums\":[1,2,3],\"strs\":[\"a\",\"b\"]}"
```
