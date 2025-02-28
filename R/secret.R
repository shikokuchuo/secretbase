# secretbase - Package Documentation -------------------------------------------

#' secretbase: Cryptographic Hash, Extendable-Output and Base64 Functions
#'
#' Fast and memory-efficient streaming hash functions and base64 encoding /
#' decoding. Hashes strings and raw vectors directly. Stream hashes files which
#' can be larger than memory, as well as in-memory objects through R's
#' serialization mechanism. Implementations include the SHA-256, SHA-3 and
#' 'Keccak' cryptographic hash functions, SHAKE256 extendable-output function
#' (XOF), and 'SipHash' pseudo-random function.
#'
#' @encoding UTF-8
#' @author Charlie Gao \email{charlie.gao@@shikokuchuo.net}
#'     ([ORCID](https://orcid.org/0000-0002-0750-061X))
#'
#' @useDynLib secretbase, .registration = TRUE
#'
"_PACKAGE"

# secretbase - Crypto Functions ------------------------------------------------

#' SHA-3 Cryptographic Hash Algorithms
#'
#' Returns a SHA-3 hash of the supplied object or file.
#'
#' @param x object to hash. A character string or raw vector (without
#'   attributes) is hashed as is. All other objects are stream hashed using
#'   native R serialization.
#' @param bits integer output size of the returned hash. Must be one of 224,
#'   256, 384 or 512.
#' @param convert logical `TRUE` to convert the hash to its hex representation
#'   as a character string, `FALSE` to return directly as a raw vector, or `NA`
#'   to return as a vector of (32-bit) integers.
#' @param file character file name / path. If specified, `x` is ignored. The
#'   file is stream hashed, and the file can be larger than memory.
#'
#' @return A character string, raw or integer vector depending on `convert`.
#'     
#' @section R Serialization Stream Hashing:
#' 
#' Where this is used, serialization is always version 3 big-endian
#' representation and the headers (containing R version and native encoding
#' information) are skipped to ensure portability across platforms.
#' 
#' As hashing is performed in a streaming fashion, there is no materialization
#' of, or memory allocation for, the serialized object.
#'     
#' @references
#' The SHA-3 Secure Hash Standard was published by the National Institute of
#' Standards and Technology (NIST) in 2015 at \doi{doi:10.6028/NIST.FIPS.202}.
#' 
#' This implementation is based on one by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
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
#' # SHA3-256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' sha3(file = file)
#' unlink(file)
#'
#' @export
#'
sha3 <- function(x, bits = 256L, convert = TRUE, file)
  if (missing(file)) .Call(secretbase_sha3, x, bits, convert) else
    .Call(secretbase_sha3_file, file, bits, convert)

#' SHAKE256 Extendable Output Function
#'
#' Returns a SHAKE256 hash of the supplied object or file.
#' 
#' To produce single integer values suitable for use as random seeds for R's
#' pseudo random number generators (RNGs), set \sQuote{bits} to 32 and
#' \sQuote{convert} to NA.
#'
#' @inheritParams sha3
#' @param bits integer output size of the returned hash. Value must be between 8
#'   and 2^24.
#'
#' @return A character string, raw or integer vector depending on `convert`.
#' 
#' @inheritSection sha3 R Serialization Stream Hashing
#'
#' @references
#' This implementation is based on one by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
#'
#' @examples
#' # SHAKE256 hash as character string:
#' shake256("secret base")
#'
#' # SHAKE256 hash as raw vector:
#' shake256("secret base", convert = FALSE)
#' 
#' # SHAKE256 hash to integer:
#' shake256("secret base", bits = 32L, convert = NA)
#'
#' # SHAKE256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' shake256(file = file)
#' unlink(file)
#'
#' @export
#'
shake256 <- function(x, bits = 256L, convert = TRUE, file)
  if (missing(file)) .Call(secretbase_shake256, x, bits, convert) else
    .Call(secretbase_shake256_file, file, bits, convert)

#' Keccak Cryptographic Hash Algorithms
#'
#' Returns a Keccak hash of the supplied object or file.
#'
#' @inheritParams sha3
#'
#' @return A character string, raw or integer vector depending on `convert`.
#'
#' @inheritSection sha3 R Serialization Stream Hashing
#' 
#' @references
#' Keccak is the underlying algorithm for SHA-3, and is identical apart from the
#' value of the padding parameter.
#' 
#' The Keccak algorithm was designed by G. Bertoni, J. Daemen, M. Peeters and G.
#' Van Assche.
#' 
#' This implementation is based on one by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
#'
#' @examples
#' # Keccak-256 hash as character string:
#' keccak("secret base")
#'
#' # Keccak-256 hash as raw vector:
#' keccak("secret base", convert = FALSE)
#' 
#' # Keccak-224 hash as character string:
#' keccak("secret base", bits = 224)
#' 
#' # Keccak-384 hash as character string:
#' keccak("secret base", bits = 384)
#' 
#' # Keccak-512 hash as character string:
#' keccak("secret base", bits = 512)
#' 
#' # Keccak-256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' keccak(file = file)
#' unlink(file)
#'
#' @export
#'
keccak <- function(x, bits = 256L, convert = TRUE, file)
  if (missing(file)) .Call(secretbase_keccak, x, bits, convert) else
    .Call(secretbase_keccak_file, file, bits, convert)

#' SHA-256 Cryptographic Hash Algorithm
#'
#' Returns a SHA-256 hash of the supplied object or file, or HMAC if a secret
#' key is supplied.
#'
#' @inheritParams sha3
#' @param key if `NULL`, the SHA-256 hash of `x` is returned. If a character
#'   string or raw vector, this is used as a secret key to generate an HMAC.
#'   Note: for character vectors, only the first element is used.
#'
#' @return A character string, raw or integer vector depending on `convert`.
#'     
#' @inheritSection sha3 R Serialization Stream Hashing
#' 
#' @references
#' The SHA-256 Secure Hash Standard was published by the National Institute of
#' Standards and Technology (NIST) in 2002 at
#' <https://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf>.
#' 
#' This implementation is based on one by 'The Mbed TLS Contributors' under the
#' 'Mbed TLS' Trusted Firmware Project at
#' <https://www.trustedfirmware.org/projects/mbed-tls>.
#'
#' @examples
#' # SHA-256 hash as character string:
#' sha256("secret base")
#'
#' # SHA-256 hash as raw vector:
#' sha256("secret base", convert = FALSE)
#' 
#' # SHA-256 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' sha256(file = file)
#' unlink(file)
#' 
#' # SHA-256 HMAC using a character string secret key:
#' sha256("secret", key = "base")
#' 
#' # SHA-256 HMAC using a raw vector secret key:
#' sha256("secret", key = charToRaw("base"))
#'
#' @export
#'
sha256 <- function(x, key = NULL, convert = TRUE, file)
  if (missing(file)) .Call(secretbase_sha256, x, key, convert) else
    .Call(secretbase_sha256_file, file, key, convert)

#' SipHash Pseudorandom Function
#'
#' Returns a fast, cryptographically-strong SipHash keyed hash of the supplied
#' object or file. SipHash-1-3 is optimised for performance. Note: SipHash is
#' not a cryptographic hash algorithm.
#'
#' @inheritParams sha3
#' @param key a character string or raw vector comprising the 16 byte (128 bit)
#'   key data, or else `NULL` which is equivalent to '0'. If a longer vector is
#'   supplied, only the first 16 bytes are used, and if shorter, padded with
#'   trailing '0'. Note: for character vectors, only the first element is used.
#'
#' @return A character string, raw or integer vector depending on `convert`.
#'     
#' @inheritSection sha3 R Serialization Stream Hashing
#' 
#' @references
#' The SipHash family of cryptographically-strong pseudorandom functions (PRFs)
#' are described in 'SipHash: a fast short-input PRF', Jean-Philippe Aumasson
#' and Daniel J. Bernstein, Paper 2012/351, 2012, Cryptology ePrint Archive at
#' <https://ia.cr/2012/351>.
#' 
#' This implementation is based on the SipHash streaming implementation by
#' Daniele Nicolodi, David Rheinsberg and Tom Gundersen at
#' <https://github.com/c-util/c-siphash>. This is in turn based on the
#' SipHash reference implementation by Jean-Philippe Aumasson and Daniel J.
#' Bernstein released to the public domain at
#' <https://github.com/veorq/SipHash>.
#'
#' @examples
#' # SipHash-1-3 hash as character string:
#' siphash13("secret base")
#'
#' # SipHash-1-3 hash as raw vector:
#' siphash13("secret base", convert = FALSE)
#' 
#' # SipHash-1-3 hash using a character string key:
#' siphash13("secret", key = "base")
#' 
#' # SipHash-1-3 hash using a raw vector key:
#' siphash13("secret", key = charToRaw("base"))
#' 
#' # SipHash-1-3 hash a file:
#' file <- tempfile(); cat("secret base", file = file)
#' siphash13(file = file)
#' unlink(file)
#'
#' @export
#'
siphash13 <- function(x, key = NULL, convert = TRUE, file)
  if (missing(file)) .Call(secretbase_siphash13, x, key, convert) else
    .Call(secretbase_siphash13_file, file, key, convert)
