# Copyright (C) 2024 Hibiki AI Limited <info@hibiki-ai.com>
#
# This file is part of secretbase.
#
# secretbase is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# secretbase is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# secretbase. If not, see <https://www.gnu.org/licenses/>.

# secretbase - Package Documentation -------------------------------------------

#' secretbase: Cryptographic Hash and Extendable-Output Functions
#'
#' SHA-3 cryptographic hash and SHAKE256 extendable-output functions (XOF). Fast
#'     and memory-efficient implementation using the core algorithm from 'Mbed
#'     TLS' under the Trusted Firmware Project
#'     <https://www.trustedfirmware.org/projects/mbed-tls/>. The SHA-3
#'     cryptographic hash functions are SHA3-224, SHA3-256, SHA3-384 and
#'     SHA3-512, each an instance of the Keccak algorithm. SHAKE256 is one of
#'     the two XOFs of the SHA-3 family, along with SHAKE128 (not implemented).
#'     
#' @references The SHA-3 Secure Hash Standard was published by the National
#'     Institute of Standards and Technology (NIST) in 2015 at
#'     \doi{doi:10.6028/NIST.FIPS.202}.
#'     
#'     The SHA-256 Secure Hash Standard was published by NIST in 2002 at
#'     \url{http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf}.
#'
#' @encoding UTF-8
#' @author Charlie Gao \email{charlie.gao@@shikokuchuo.net}
#'     (\href{https://orcid.org/0000-0002-0750-061X}{ORCID})
#'
#' @useDynLib secretbase, .registration = TRUE
#'
"_PACKAGE"

# secretbase - Main Functions --------------------------------------------------

#' Cryptographic Hashing Using the SHA-3 Algorithms
#'
#' Returns a SHA-3 hash of the supplied R object or file.
#'
#' @param x R object to hash. A character string or raw vector (without
#'     attributes) is hashed 'as is'. All other objects are hashed using R
#'     serialization in a memory-efficient 'streaming' manner, without
#'     allocation of the serialized object. To ensure portability, serialization
#'     v3 XDR is always used with headers skipped (as these contain R version
#'     and encoding information).
#' @param bits [default 256L] output size of the returned hash. If one of 224,
#'     256, 384 or 512, uses the relevant SHA-3 cryptographic hash function. For
#'     all other values, uses the SHAKE256 extendable-output function (XOF).
#'     Must be between 8 and 2^24 and coercible to integer.
#' @param convert [default TRUE] if TRUE, the hash is converted to its hex
#'     representation as a character string, if FALSE, output directly as a raw
#'     vector, or if NA, a vector of (32-bit) integer values.
#'
#' @return A character string, raw or integer vector depending on 'convert'.
#'
#' @details To produce single integer values suitable for use as random seeds
#'     for R's pseudo random number generators (RNGs), set 'bits' to 32 and
#'     'convert' to NA.
#'
#' @examples
#' # SHA3-256 hash as character string:
#' sha3("secret base")
#'
#' # SHA3-256 hash as raw vector:
#' sha3("secret base", convert = FALSE)
#' 
#' # SHA3-224 hash as character string:
#' sha3("secret base", bits = 224)
#' 
#' # SHA3-384 hash as character string:
#' sha3("secret base", bits = 384)
#' 
#' # SHA3-512 hash as character string:
#' sha3("secret base", bits = 512)
#' 
#' # SHAKE256 hash to integer:
#' sha3("secret base", bits = 32L, convert = NA)
#'
#' @export
#'
sha3 <- function(x, bits = 256L, convert = TRUE)
  .Call(secretbase_sha3, x, bits, convert)

#' @param file character file name / path. The file is hashed in a streaming
#'     fashion and may be larger than memory.
#' 
#' @examples
#' # SHA3-256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' sha3file(file)
#' unlink(file)
#'     
#' @rdname sha3
#' @export
#'
sha3file <- function(file, bits = 256L, convert = TRUE)
  .Call(secretbase_sha3_file, file, bits, convert)

#' Cryptographic Hashing Using the SHA-256 Algorithm
#'
#' Returns a SHA-256 hash of the supplied R object or file.
#'
#' @inheritParams sha3
#'
#' @return A character string, raw or integer vector depending on 'convert'.
#'
#' @examples
#' # SHA-256 hash as character string:
#' sha256("secret base")
#'
#' # SHA-256 hash as raw vector:
#' sha256("secret base", convert = FALSE)
#'
#' @export
#'
sha256 <- function(x, convert = TRUE)
  .Call(secretbase_sha256, x, convert)

#' @examples
#' # SHA-256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' sha256file(file)
#' unlink(file)
#'     
#' @rdname sha256
#' @export
#'
sha256file <- function(file, convert = TRUE)
  .Call(secretbase_sha256_file, file, convert)

#' Fast Non-Cryptographic Hashing Using xxHash64
#'
#' Returns the 'xxHash64' of the supplied R object or file. This is an extremely
#'     fast hash, processing at RAM speed limits.
#' 
#' @inheritParams sha3
#' 
#' @return A character string, raw or integer vector depending on 'convert'.
#' 
#' @details This implementation uses the algorithm released by Yann Collet at
#'     \url{https://xxhash.com/}.
#'     
#' @examples
#' # xxHash64 as character string:
#' xxh64("secret base")
#'
#' # xxHash64 as raw vector:
#' xxh64("secret base", convert = FALSE)
#' 
#' @export
#'
xxh64 <- function(x, convert = TRUE)
  .Call(secretbase_xxhash, x, convert)

#' @examples
#' # xxHash64 a file:
#' file <- tempfile(); cat("secret base", file = file)
#' xxh64file(file)
#' unlink(file)
#' 
#' @rdname xxh64
#' @export
#'
xxh64file <- function(file, convert = TRUE)
  .Call(secretbase_xxhash_file, file, convert)
