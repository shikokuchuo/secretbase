# JSON Decode

Minimal JSON parser. Converts JSON to R objects with proper type
handling.

## Usage

``` r
jsondec(x)
```

## Arguments

- x:

  Character string or raw vector containing JSON data.

## Value

The corresponding R object, or an empty list for invalid input.

## Details

This is a minimal implementation designed for parsing HTTP API
responses.

## Type Mappings

- Object [`{}`](https://rdrr.io/r/base/Paren.html) -\> named list

- Array `[]` -\> unnamed list

- String -\> character

- Number -\> numeric

- `true`/`false` -\> logical

- `null` -\> `NULL`

## RFC 8259 Non-conformance

- Invalid JSON returns an empty list instead of erroring.

- Duplicate keys are preserved; R accessors (`$`, `[[`) return first
  match.

- Non-standard number forms may be accepted (e.g., leading zeros,
  hexadecimal).

- Invalid escape sequences are output literally (e.g., `\\uZZZZ` becomes
  `"uZZZZ"`).

- Incomplete Unicode escape sequences for emoji are tolerated.

- Nesting depth is limited to 512 levels.

## See also

[`jsonenc()`](https://shikokuchuo.net/secretbase/reference/jsonenc.md)

## Examples

``` r
jsondec('{"name": "John", "age": 30}')
#> $name
#> [1] "John"
#> 
#> $age
#> [1] 30
#> 
jsondec('[1, 2, 3]')
#> [[1]]
#> [1] 1
#> 
#> [[2]]
#> [1] 2
#> 
#> [[3]]
#> [1] 3
#> 
jsondec('"a string"')
#> [1] "a string"
jsondec('123')
#> [1] 123
jsondec('true')
#> [1] TRUE
```
