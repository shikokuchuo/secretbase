% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/secret.R
\name{sha256}
\alias{sha256}
\title{SHA-256 Cryptographic Hash Algorithm}
\usage{
sha256(x, key = NULL, convert = TRUE, file)
}
\arguments{
\item{x}{object to hash. A character string or raw vector (without
attributes) is hashed \sQuote{as is}. All other objects are stream hashed
using R serialization (but without allocation of the serialized object).}

\item{key}{[default NULL] If NULL, the SHA-256 hash of \sQuote{x} is
returned. Alternatively, supply a character string or raw vector as a
secret key to generate an HMAC. Note: for character vectors, only the
first element is used.}

\item{convert}{[default TRUE] if TRUE, the hash is converted to its hex
representation as a character string, if FALSE, output directly as a raw
vector, or if NA, a vector of (32-bit) integer values.}

\item{file}{character file name / path. If specified, \sQuote{x} is ignored.
The file is stream hashed, thus capable of handling files larger than
memory.}
}
\value{
A character string, raw or integer vector depending on
    \sQuote{convert}.
}
\description{
Returns a SHA-256 hash of the supplied object or file, or HMAC if a secret
    key is supplied.
}
\section{R Serialization Stream Hashing}{

    
    Where this is used, serialization is always version 3 big-endian
    represenation and the headers (containing R version and native encoding
    information) are skipped to ensure portability across platforms.
}

\examples{
# SHA-256 hash as character string:
sha256("secret base")

# SHA-256 hash as raw vector:
sha256("secret base", convert = FALSE)

# SHA-256 hash a file:
file <- tempfile(); cat("secret base", file = file)
sha256(file = file)
unlink(file)

# SHA-256 HMAC using a character string secret key:
sha256("secret", key = "base")

# SHA-256 HMAC using a raw vector secret key:
sha256("secret", key = charToRaw("base"))

}
\references{
The SHA-256 Secure Hash Standard was published by the National
    Institute of Standards and Technology (NIST) in 2002 at
    \url{https://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf}.
    
    This implementation is based on one by 'The Mbed TLS Contributors' under
    the 'Mbed TLS' Trusted Firmware Project at
    \url{https://www.trustedfirmware.org/projects/mbed-tls}.
}
