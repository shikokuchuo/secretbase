# secretbase (development version)

* This package is re-licensed under the MIT licence. Dual-licensed code incorporated from external projects is taken under the Apache 2.0 licence.

# secretbase 1.0.4

* `base64dec()` now errors if `convert = TRUE` and conversion to a character string fails, no longer returning a raw vector (accompanied by a warning).

# secretbase 1.0.3

* `base64dec()` now emits a suppressable warning when failing to convert back to a character string.

# secretbase 1.0.2

* Improves hash performance in most situations, especially for large files, by optimizing buffer sizes.

# secretbase 1.0.1

* Improved error message if argument 'convert' is not of logical type.

# secretbase 1.0.0

* Adds base64 encoding and decoding.
* `sha3()` restricts 'bit' argument to one of 224, 256, 384 or 512.

# secretbase 0.5.0

* Adds Keccak cryptographic hash algorithm.
* Adds `shake256()` to delineate from `sha3()`.
* Use of `sha3()` supplying 'bit' argument other than 224, 256, 384 or 512 is deprecated.

# secretbase 0.4.0

* Adds HMAC generation to `sha256()`.
* Adds SipHash pseudo-random function (PRF) as a fast, cryptographically-strong keyed hash.

# secretbase 0.3.0.1

* CRAN release correcting for Clang-UBSAN checks.

# secretbase 0.3.0

* Adds SHA-256 cryptographic hash algorithm.
* Folds file hashing into the 'file' argument of the main hash function.

# secretbase 0.2.0

* Adds file hashing interface.

# secretbase 0.1.0

* Initial CRAN release.

# secretbase 0.0.1

* Initial release to rOpenSci R-universe and Github.
