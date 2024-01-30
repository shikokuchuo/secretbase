library(secretbase)
test_that <- function(x, f) invisible(f(x) || stop("expectation is not TRUE"))
test_equal <- function(x, y) invisible(x == y || stop("generated hash differs from known value"))
test_error <- function(x, e = "")
  invisible(grepl(e, tryCatch(x, error = identity)[["message"]], fixed = TRUE) || stop("expected error message '", e, "' not generated"))

# Known SHA-3 hashes from NIST:
test_equal(sha3("", 224), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")
test_equal(sha3("", 256), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
test_equal(sha3("", 384), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")
test_equal(sha3("", 512), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")
# SHA-3 tests:
test_equal(sha3("secret base"), "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520")
test_equal(sha3("secret base", bits = 224), "5511b3469d3f1a87b62ce8f0d2dc9510ec5e4547579b8afb32052f99")
test_equal(sha3("secret base", bits = 384L), "79e54f865df004dde10dc2f61baf47eb4637c68d87a2baeb7fe6bc0ac983c2154835ec7deb49b16c246c0dc1d43e32f9")
test_equal(sha3("secret base", bits = "512"), "31076b4690961320a761be0951eeaa9efd0c75c37137a2a50877cbebb8afcc6d7927c41a120ae8fa73fdce8fff726fcbc51d448d020240bc7455963a16e639b1")
test_that(sha3("secret base", convert = FALSE), is.raw)
# SHAKE256 tests:
test_equal(sha3("secret base", bits = 32), "995ebac1")
test_equal(sha3(sha3("secret base", bits = 32, convert = FALSE), bits = 32), "4d872090")
test_that(sha3(rnorm(1e5), bits = 8196), is.character)
test_equal(sha3("secret base", bits = 32, convert = NA), -1044750695L)
# Streaming serialization tests:
test_equal(sha3(data.frame(a = 1, b = 2)), "05d4308e79d029b4af5604739ecc6c4efa1f602a23add0ed2d247b7407d4832f")
test_equal(sha3(c("secret", "base")), "d906024c71828a10e28865a80f5e81d2cb5cd74067d44852d7039813ba62b0b6")
test_equal(sha3(NULL), "b3e37e4c5def1bfb2841b79ef8503b83d1fed46836b5b913d7c16de92966dcee")
test_equal(sha3(substitute()), "9d31eb41cfb721b8040c52d574df1aacfc381d371c2b933f90792beba5160a57")
test_equal(sha3(`class<-`(sha3(character(), bits = 192, convert = FALSE), "hash"), bits = "32", convert = NA), -111175135L)
# Error handling tests:
test_error(sha3("secret base", bits = 0), "'bits' outside valid range of 8 to 2^24")
test_error(sha3("secret base", bits = -1), "'bits' outside valid range of 8 to 2^24")
test_error(sha3("secret base", bits = 2^24 + 1), "'bits' outside valid range of 8 to 2^24")
# File interface tests:
hash_func <- function(file, string) {
  on.exit(unlink(file))
  cat(string, file = file)
  sha3file(file)
}
test_equal(hash_func(tempfile(), "secret base"), "a721d57570e7ce366adee2fccbe9770723c6e3622549c31c7cab9dbb4a795520")
test_error(hash_func("", ""), "file not found or no read permission")
if (.Platform[["OS.type"]] == "unix") test_error(sha3file("~/"), "file read error")
