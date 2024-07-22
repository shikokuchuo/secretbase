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
