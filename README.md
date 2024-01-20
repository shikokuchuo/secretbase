
<!-- README.md is generated from README.Rmd. Please edit that file -->

# secretbase

<!-- badges: start -->

[![CRAN
status](https://www.r-pkg.org/badges/version/secretbase?color=42147b)](https://CRAN.R-project.org/package=secretbase)
[![secretbase status
badge](https://shikokuchuo.r-universe.dev/badges/secretbase?color=e4723a)](https://shikokuchuo.r-universe.dev/secretbase)
[![R-CMD-check](https://github.com/shikokuchuo/secretbase/workflows/R-CMD-check/badge.svg)](https://github.com/shikokuchuo/secretbase/actions)
[![codecov](https://codecov.io/gh/shikokuchuo/secretbase/graph/badge.svg)](https://codecov.io/gh/shikokuchuo/secretbase)
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

`secretbase` offers one main function `sha3()`:

To use the SHA-3 cryptographic hash algorithm, specify argument ‘size’
as one of ‘224’, ‘256’, ‘384’ or ‘512’.

Specify an arbitrary output size to use the SHAKE256 algorithm as an
extendable-output function (XOF).

``` r
library(secretbase)

sha3("secret base")
#> [1] "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520"

sha3("secret base", convert = FALSE)
#>  [1] a7 21 d5 75 70 e7 ce 36 6a de e2 fc cb e9 77 07 23 c6 e3 62 25 49 c3 1c 7c
#> [26] ab 9d bb 4a 79 55 20

sha3("秘密の基地", size = 224)
#> [1] "df2b0bc4d37831d1ec6624312be9ab75e22e08eca52d059d184edf39"

sha3("秘密の基地", size = 512)
#> [1] "d9553a1e8d9ea1cf9d053f72c499d040a11724f32be6e568aba6b078950ae2679842806450bd62f97da8eca517a68c0aa386349140724968daceeac2eaa1340a"
```

To hash to an integer value (for example to generate random seeds for
R’s pseudo RNGs), specify a size of ‘32’ and pass the resulting raw
vector to `read_integer()`.

``` r
hash <- sha3("秘密の基地", size = 32, convert = FALSE)
hash
#> [1] 6a 92 94 19

read_integer(hash)
#> [1] 429167210
```

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
