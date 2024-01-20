
<!-- README.md is generated from README.Rmd. Please edit that file -->

# secretbase

<!-- badges: start -->

[![CRAN
status](https://www.r-pkg.org/badges/version/secretbase?color=42147b)](https://CRAN.R-project.org/package=secretbase)
[![secretbase status
badge](https://shikokuchuo.r-universe.dev/badges/secretbase?color=e4723a)](https://shikokuchuo.r-universe.dev/secretbase)
[![R-CMD-check](https://github.com/shikokuchuo/secretbase/workflows/R-CMD-check/badge.svg)](https://github.com/shikokuchuo/secretbase/actions)
[![codecov](https://codecov.io/gh/shikokuchuo/secretbase/graph/badge.svg)](https://app.codecov.io/gh/shikokuchuo/secretbase)
<!-- badges: end -->

Fast, dependency-free SHA-3 cryptographic hash and SHAKE256
extendable-output function (XOF) algorithms.

The SHA-3 Secure Hash Standard was published by NIST in 2015 at
[doi:10.6028/NIST.FIPS.202](https://dx.doi.org/10.6028/NIST.FIPS.202).

Uses the implementation by the ‘Mbed TLS’ library from the Trusted
Firmware Project <https://www.trustedfirmware.org/projects/mbed-tls/>.

### Installation

Install the latest release from CRAN:

``` r
install.packages("secretbase")
```

or the development version from rOpenSci R-universe:

``` r
install.packages("secretbase", repos = "https://shikokuchuo.r-universe.dev")
```

### Quick Start

`secretbase` offers one main function: `sha3()`

To use:

- SHA-3 cryptographic hash algorithm, specify ‘size’ as one of ‘224’,
  ‘256’, ‘384’ or ‘512’.
- SHAKE256 extendable-output function (XOF), specify any other arbitrary
  output size.

``` r
library(secretbase)

sha3("secret base")
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"

sha3("secret base", convert = FALSE)
#>  [1] a7 21 d5 75 70 e7 ce 36 6a de e2 fc cb e9 77 07 23 c6 e3 62 25 49 c3 1c 7c
#> [26] ab 9d bb 4a 79 55 20

sha3("秘密の基地の中", size = 224)
#> [1] "d9e291d0c9f3dc3007dc0c111aea0b6a938929c8b4766332d8ea791a"

sha3("", size = 512)
#> [1] "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
```

Hash arbitrary R objects:

- done in-place, in a ‘streaming’ fashion, by R serialization but
  without allocation of the serialized object
- ensures portability by always using R serialization version 3, big
  endian representation, skipping the headers

``` r
sha3(data.frame(a = 1, b = 2))
#> [1] "05d4308e79d029b4af5604739ecc6c4efa1f602a23add0ed2d247b7407d4832f"

sha3(NULL)
#> [1] "b3e37e4c5def1bfb2841b79ef8503b83d1fed46836b5b913d7c16de92966dcee"
```

To hash to an integer value:

- specify a size of ‘32’ and pass the resulting raw vector to
  `read_integer()`.

``` r
hash <- sha3("秘密の基地の中", size = 32, convert = FALSE)
hash
#> [1] 7f c2 38 77

read_integer(hash)
#> [1] 2000208511
```

This may be used to generate random seeds for R’s pseudo RNGs.

### Links

Links:

`secretbase` website: <https://shikokuchuo.net/secretbase/><br />
`secretbase` on CRAN:
<https://cran.r-project.org/package=secretbase><br />

Mbed TLS website:
<https://www.trustedfirmware.org/projects/mbed-tls/><br />

–

Please note that this project is released with a [Contributor Code of
Conduct](https://shikokuchuo.net/secretbase/CODE_OF_CONDUCT.html). By
participating in this project you agree to abide by its terms.
