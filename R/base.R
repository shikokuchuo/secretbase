# Copyright (C) 2024-2025 Hibiki AI Limited <info@hibiki-ai.com>
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

# secretbase - Base64 Functions ------------------------------------------------

#' Base64 Encode
#'
#' Encodes a character string, raw vector or other object to base64 encoding.
#' 
#' A character string or raw vector (with no attributes) is encoded as is,
#' whilst all other objects are first serialized (using R serialisation version
#' 3, big-endian representation).
#'
#' @param x an object.
#' @param convert logical `TRUE` to encode to a character string or `FALSE` to a
#'   raw vector.
#'
#' @return A character string or raw vector depending on the value of `convert`.
#'   
#' @references
#' This implementation is based that by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
#'     
#' @seealso [base64dec()]
#'
#' @examples
#' base64enc("secret base")
#' base64enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#' base64enc(data.frame())
#'
#' @export
#'
base64enc <- function(x, convert = TRUE) .Call(secretbase_base64enc, x, convert)

#' Base64 Decode
#'
#' Decodes a character string, raw vector or other object from base64 encoding.
#' 
#' The value of `convert` should be set to `TRUE`, `FALSE` or `NA` to be the
#' reverse of the 3 encoding operations (for strings, raw vectors and arbitrary
#' objects), in order to return the original object.
#'
#' @param x an object.
#' @param convert logical `TRUE` to convert back to a character string, `FALSE`
#'   to convert back to a raw vector or `NA` to decode and then unserialize back
#'   to the original object.
#'
#' @return A character string, raw vector, or other object depending on the
#'   value of `convert`.
#'   
#' @references
#' This implementation is based that by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
#'
#' @seealso [base64enc()]
#'
#' @examples
#' base64dec(base64enc("secret base"))
#' base64dec(base64enc(as.raw(c(1L, 2L, 4L))), convert = FALSE)
#' base64dec(base64enc(data.frame()), convert = NA)
#'
#' @export
#'
base64dec <- function(x, convert = TRUE) .Call(secretbase_base64dec, x, convert)
