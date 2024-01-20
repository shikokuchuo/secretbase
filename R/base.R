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
#' Secure SHA-3 hash and SHAKE256 extendable-output functions (XOF) using the
#'     implementation by the Mbed TLS library from the Trusted Firmware Project.
#'     
#' @references The SHA-3 Secure Hash Standard was published by NIST in 2015 at
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
#' Returns a SHA-3 hash of the supplied R object. Uses the implementation by the
#'     'Mbed TLS' library from the Trusted Firmware Project.
#'
#' @param x an object.
#' @param size [default 256L] integer output size (bits) of the returned hash -
#'     uses the relevant SHA-3 algorithm if one of 224, 256, 384 or 512, or else
#'     the SHAKE256 algorithm as an extendable-output function (XOF) for
#'     arbitrary bit lengths. The supplied value must be between 8 and 2^24.
#' @param convert [default TRUE] whether to output the hash as a character
#'     string or, if FALSE, a raw vector.
#'
#' @return A raw vector or character string depending on 'convert'.
#'
#' @details For argument 'x', a scalar string or raw vector (with no attributes)
#'     is hashed 'as is'.
#'     
#'     All other objects are hashed in-place, in a 'streaming' fashion by R
#'     serialization but without allocation of the serialized object. To ensure
#'     portability, R serialization version 3, big-endian representation is
#'     always used, skipping the headers (as these contain the R version number
#'     and native encoding information).
#'
#'     The result of hashing is always a byte sequence, which is converted to a
#'     character string hex representation if 'convert' is TRUE, or returned as
#'     a raw vector if 'convert' is FALSE.
#'     
#'     To hash to an integer value, set 'size' to 32 and 'convert' to FALSE, and
#'     pass the resulting raw vector to \code{\link{read_integer}}. This may be
#'     used to generate random seeds for R's pseudo RNGs.
#'
#' @examples
#' # SHA3-256 hash as character string:
#' sha3("secret base")
#'
#' # SHA3-256 hash as raw vector:
#' sha3("secret base", convert = FALSE)
#' 
#' # SHA3-224 hash as character string:
#' sha3("secret base", size = 224)
#' 
#' # SHA3-384 hash as character string:
#' sha3("secret base", size = 384)
#' 
#' # SHA3-512 hash as character string:
#' sha3("secret base", size = 512)
#' 
#' # SHAKE256 hash to integer:
#' hash <- sha3("secret base", size = 32L, convert = FALSE)
#' hash
#' read_integer(hash)
#'
#' @export
#'
sha3 <- function(x, size = 256L, convert = TRUE) .Call(secretbase_sha3, x, size, convert)

#' Read Object as Integer
#'
#' Read any R object as an integer. This function dereferences the pointer to
#'     the R object and reads the value at the address as an integer. Useful for
#'     converting 32-bit (4-byte) raw vectors to the equivalent integer value.
#'
#' @param x an object.
#'
#' @return An integer.
#' 
#' @examples
#' # SHAKE256 hash to integer:
#' read_integer(sha3("secret base", size = 32L, convert = FALSE))
#'
#' @export
#'
read_integer <- function(x) .Call(secretbase_read_integer, x)
