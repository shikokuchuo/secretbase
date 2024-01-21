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
#' @encoding UTF-8
#' @author Charlie Gao \email{charlie.gao@@shikokuchuo.net}
#'     (\href{https://orcid.org/0000-0002-0750-061X}{ORCID})
#'
#' @useDynLib secretbase, .registration = TRUE
#'
#' @docType package
#'
"_PACKAGE"

# secretbase - Main Functions --------------------------------------------------

#' Cryptographic Hashing Using the SHA-3 Algorithm
#'
#' Returns a SHA-3 hash of the supplied R object. Implementated from code used
#'     by the the 'Mbed TLS' library under the Trusted Firmware Project.
#'
#' @param x an object.
#' @param bits [default 256L] output size of the returned hash - uses the
#'     relevant SHA-3 hash function if one of 224, 256, 384 or 512, or
#'     else the SHAKE256 extendable-output function (XOF) for arbitrary values.
#'     The supplied value must be between 8 and 2^24, and is automatically
#'     coerced to integer.
#' @param convert [default TRUE] if TRUE, the hash is converted to its hex
#'     representation as a character string, if FALSE, output directly as a raw
#'     vector, or if NA, a vector of (32-bit) integer values.
#'
#' @return A character string, raw or integer vector depending on 'convert'.
#'
#' @details For argument 'x', a character string or raw vector (with no
#'     attributes) is hashed 'as is'.
#'     
#'     All other objects are hashed in-place, in a 'streaming' fashion, by R
#'     serialization but without allocation of the serialized object. To ensure
#'     portability, R serialization version 3, big-endian representation is
#'     always used, skipping the headers (as these contain the R version number
#'     and native encoding information).
#'
#'     The result of hashing is always a byte sequence, which is converted to a
#'     character string hex representation if 'convert' is TRUE, or returned as
#'     a raw vector if 'convert' is FALSE.
#'     
#'     To hash to integer values, set convert to NA. For a single integer value
#'     set 'bits' to 32. These values may be supplied as random seeds for R's
#'     pseudo random number generators (RNGs).
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
sha3 <- function(x, bits = 256L, convert = TRUE) .Call(secretbase_sha3, x, bits, convert)
