
<!-- README.md is generated from README.Rmd. Please edit that file -->

# secretbase

<!-- badges: start -->

[![CRAN
status](https://www.r-pkg.org/badges/version/secretbase?color=17411d)](https://CRAN.R-project.org/package=secretbase)
[![secretbase status
badge](https://shikokuchuo.r-universe.dev/badges/secretbase)](https://shikokuchuo.r-universe.dev/secretbase)
[![R-CMD-check](https://github.com/shikokuchuo/secretbase/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/shikokuchuo/secretbase/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/shikokuchuo/secretbase/graph/badge.svg)](https://app.codecov.io/gh/shikokuchuo/secretbase)
<!-- badges: end -->

      ________  
     /\ sec   \
    /  \ ret   \
    \  /  base /
     \/_______/

Fast and memory-efficient streaming hash functions, binary encoding and
serialization.

Hashes strings and raw vectors directly. Stream hashes files which can
be larger than memory, as well as in-memory objects through R’s
serialization mechanism.

Implements the SHA-256, SHA-3 and ‘Keccak’ cryptographic hash functions,
SHAKE256 extendable-output function (XOF), ‘SipHash’ pseudo-random
function, base64 and base58 encoding, and ‘CBOR’ serialization.

| Function                       | Purpose                            |
|--------------------------------|------------------------------------|
| `sha3()` `sha256()` `keccak()` | Cryptographic hashes               |
| `shake256()`                   | Extendable-output function (XOF)   |
| `siphash13()`                  | Keyed, fast pseudo-random function |
| `base64enc()` `base64dec()`    | Base64 encoding                    |
| `base58enc()` `base58dec()`    | Base58 encoding with checksum      |
| `cborenc()` `cbordec()`        | CBOR serialization                 |

### Installation

``` r
install.packages("secretbase")
```

### Get Started

``` r
library(secretbase)
```

### Hash Functions

#### SHA-3

Specify `bits` as `224`, `256`, `384` or `512`:

``` r
sha3("secret base")
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"
sha3("secret base", convert = FALSE)
#>  [1] a7 21 d5 75 70 e7 ce 36 6a de e2 fc cb e9 77 07 23 c6 e3 62 25 49 c3 1c 7c
#> [26] ab 9d bb 4a 79 55 20
sha3("秘密の基地の中", bits = 512L)
#> [1] "e30cdc73f6575c40d55b5edc8eb4f97940f5ca491640b41612e02a05f3e59dd9c6c33f601d8d7a8e2ca0504b8c22f7bc69fa8f10d7c01aab392781ff4ae1e610"
```

#### SHA-256

``` r
sha256("secret base")
#> [1] "1951c1ca3d50e95e6ede2b1c26fefd0f0e8eba1e51a837f8ccefb583a2b686fe"
```

For HMAC, pass a character string or raw vector to `key`:

``` r
sha256("secret base", key = "秘密の基地の中")
#> [1] "ec58099ab21325e792bef8f1aafc0a70e1a7227463cfc410931112705d753392"
```

#### Keccak

``` r
keccak("secret base", bits = 384L)
#> [1] "c82bae24175676028e44aa08b9e2424311847adb0b071c68c7ea47edf049b0e935ddd2fc7c499333bccc08c7eb7b1203"
```

#### SHAKE256

An extendable-output function (XOF). Specify arbitrary `bits`. May be
used as deterministic random seeds for R’s pseudo random number
generators (RNGs) - use `convert = NA` for integer output:

``` r
shake256("秘密の基地の中", bits = 32L, convert = NA)
#> [1] 2000208511
```

For use in parallel computing, this is a valid method for reducing to a
negligible probability that RNGs in each process may overlap. This may
be especially suitable when first-best alternatives such as using
recursive streams are too expensive or unable to preserve
reproducibility. <sup>\[1\]</sup>

#### SipHash

SipHash-1-3 is a fast, keyed pseudo-random function. Pass to `key` up to
16 bytes (128 bits):

``` r
siphash13("secret base", key = "秘密の基地の中")
#> [1] "a1f0a751892cc7dd"
```

### Streaming

All hash functions above support streaming of R objects and files.

#### R Objects

Character strings and raw vectors are hashed directly. All other objects
are stream hashed using R serialization:

- memory-efficient as performed without allocation of the serialized
  object
- portable as uses serialization version 3, big-endian representation,
  skipping headers

``` r
sha3(data.frame(a = 1, b = 2), bits = 224L)
#> [1] "03778aad53bff7dd68caab94374bba6f07cea235fb97b3c52cf612e9"
sha3(NULL)
#> [1] "b3e37e4c5def1bfb2841b79ef8503b83d1fed46836b5b913d7c16de92966dcee"
```

#### Files

Files are read and hashed incrementally, accepting files larger than
memory:

``` r
file <- tempfile(); cat("secret base", file = file)
sha3(file = file)
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"
```

### Encoding

#### Base64

``` r
base64enc("secret base")
#> [1] "c2VjcmV0IGJhc2U="
base64dec(base64enc("secret base"))
#> [1] "secret base"
base64enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#> [1] 41 51 49 45
base64dec(base64enc(data.frame()), convert = NA)
#> data frame with 0 columns and 0 rows
```

#### Base58

Includes a 4-byte checksum (double SHA-256), verified on decode:

``` r
base58enc("secret base")
#> [1] "4EFRHUcj9ookBnv1yX9Gt"
base58dec(base58enc("secret base"))
#> [1] "secret base"
base58enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#> [1] 33 44 56 41 66 71 55 64 77
base58dec(base58enc(data.frame()), convert = NA)
#> data frame with 0 columns and 0 rows
```

### Serialization

#### CBOR

Encode R objects to CBOR (RFC 8949) - a compact binary format. Supports
integers, doubles, strings, raw vectors, logical, NULL, and lists (named
lists become maps):

``` r
cborenc(list(a = 1L, b = "hello", c = TRUE))
#>  [1] a3 61 61 01 61 62 65 68 65 6c 6c 6f 61 63 f5
cbordec(cborenc(list(a = 1L, b = "hello", c = TRUE)))
#> $a
#> [1] 1
#> 
#> $b
#> [1] "hello"
#> 
#> $c
#> [1] TRUE
```

### Implementation

The SHA-3 Secure Hash Standard was published by the National Institute
of Standards and Technology (NIST) in 2015 at
[doi:10.6028/NIST.FIPS.202](https://dx.doi.org/10.6028/NIST.FIPS.202).
SHA-3 is based on the Keccak algorithm, designed by G. Bertoni, J.
Daemen, M. Peeters and G. Van Assche.

The SHA-256 Secure Hash Standard was published by NIST in 2002 at
<https://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf>.

The SHA-256, SHA-3, Keccak, and base64 implementations are based on
those by the ‘Mbed TLS’ Trusted Firmware Project at
<https://www.trustedfirmware.org/projects/mbed-tls>.

The SipHash family of pseudo-random functions by Jean-Philippe Aumasson
and Daniel J. Bernstein was published in 2012 at
<https://ia.cr/2012/351>. <sup>\[2\]</sup>

The SipHash implementation is based on that of Daniele Nicolodi, David
Rheinsberg and Tom Gundersen at <https://github.com/c-util/c-siphash>,
which is in turn based on the reference implementation by Jean-Philippe
Aumasson and Daniel J. Bernstein released to the public domain at
<https://github.com/veorq/SipHash>.

The base58 implementation is based on ‘libbase58’ by Luke Dashjr at
<https://github.com/luke-jr/libbase58>.

The CBOR implementation follows RFC 8949, *“Concise Binary Object
Representation (CBOR)”*, available at
<https://www.rfc-editor.org/rfc/rfc8949>.

### References

\[1\] Pierre L’Ecuyer, David Munger, Boris Oreshkin and Richard Simard
(2017), *“Random numbers for parallel computers: Requirements and
methods, with emphasis on GPUs”*, Mathematics and Computers in
Simulation, Vol. 135, May 2017, pp. 3-17
[doi:10.1016/j.matcom.2016.05.00](https://doi.org/10.1016/j.matcom.2016.05.005).

\[2\] Jean-Philippe Aumasson and Daniel J. Bernstein (2012), *“SipHash:
a fast short-input PRF”*, Paper 2012/351, Cryptology ePrint Archive,
<https://ia.cr/2012/351>.

### Links

◈ secretbase R package: <https://shikokuchuo.net/secretbase/>

Mbed TLS website:
<https://www.trustedfirmware.org/projects/mbed-tls><br /> SipHash
streaming implementation: <https://github.com/c-util/c-siphash><br />
SipHash reference implementation:
<https://github.com/veorq/SipHash><br /> libbase58:
<https://github.com/luke-jr/libbase58><br /> CBOR RFC 8949:
<https://www.rfc-editor.org/rfc/rfc8949>

–

Please note that this project is released with a [Contributor Code of
Conduct](https://shikokuchuo.net/secretbase/CODE_OF_CONDUCT.html). By
participating in this project you agree to abide by its terms.
