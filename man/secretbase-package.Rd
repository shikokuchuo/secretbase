% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/base.R
\docType{package}
\encoding{UTF-8}
\name{secretbase-package}
\alias{secretbase}
\alias{secretbase-package}
\title{secretbase: Cryptographic Hash and Extendable-Output Functions}
\description{
Fast and memory-efficient streaming hash functions. Performs direct hashing
    of strings, raw bytes, and files potentially larger than memory, as well
    as hashing in-memory objects through R's serialization mechanism, without
    requiring allocation of the serialized object. Implementations include
    the SHA-256 and SHA-3 cryptographic hash functions, SHAKE256
    extendable-output function (XOF), and 'SipHash' pseudo-random function.
}
\seealso{
Useful links:
\itemize{
  \item \url{https://shikokuchuo.net/secretbase/}
  \item \url{https://github.com/shikokuchuo/secretbase/}
  \item Report bugs at \url{https://github.com/shikokuchuo/secretbase/issues}
}

}
\author{
Charlie Gao \email{charlie.gao@shikokuchuo.net}
    (\href{https://orcid.org/0000-0002-0750-061X}{ORCID})
}
