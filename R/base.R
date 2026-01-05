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

#' Base58 Encode
#'
#' Encodes a character string, raw vector or other object to base58 encoding
#' with a 4-byte checksum suffix.
#'
#' Adds a 4-byte checksum suffix (double SHA-256) to the data before base58
#' encoding. Note: does not include a version byte prefix (unlike Bitcoin
#' Base58Check).
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
#' This implementation is based on 'libbase58' by Luke Dashjr under the MIT
#' licence at <https://github.com/luke-jr/libbase58>.
#'
#' @seealso [base58dec()]
#'
#' @examples
#' base58enc("secret base")
#' base58enc(as.raw(c(1L, 2L, 4L)), convert = FALSE)
#' base58enc(data.frame())
#'
#' @export
#'
base58enc <- function(x, convert = TRUE) .Call(secretbase_base58enc, x, convert)

#' Base58 Decode
#'
#' Decodes a character string or raw vector from base58 encoding with checksum.
#'
#' The 4-byte checksum suffix is verified using double SHA-256 and an error is
#' raised if validation fails. Note: does not expect a version byte prefix
#' (unlike Bitcoin Base58Check).
#'
#' The value of `convert` should be set to `TRUE`, `FALSE` or `NA` to be the
#' reverse of the 3 encoding operations (for strings, raw vectors and arbitrary
#' objects), in order to return the original object.
#'
#' @param x a character string or raw vector containing base58 encoded data.
#' @param convert logical `TRUE` to convert back to a character string, `FALSE`
#'   to convert back to a raw vector or `NA` to decode and then unserialize back
#'   to the original object.
#'
#' @return A character string, raw vector, or other object depending on the
#'   value of `convert`.
#'
#' @references
#' This implementation is based on 'libbase58' by Luke Dashjr under the MIT
#' licence at <https://github.com/luke-jr/libbase58>.
#'
#' @seealso [base58enc()]
#'
#' @examples
#' base58dec(base58enc("secret base"))
#' base58dec(base58enc(as.raw(c(1L, 2L, 4L))), convert = FALSE)
#' base58dec(base58enc(data.frame()), convert = NA)
#'
#' @export
#'
base58dec <- function(x, convert = TRUE) .Call(secretbase_base58dec, x, convert)
