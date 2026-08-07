# AGENTS.md

Guidance for AI coding agents working **on** the secretbase package.
secretbase provides fast, memory-efficient streaming hash functions,
binary/text encoding and serialization for R. R \>= 3.5, zero runtime
dependencies — all cryptography is vendored C in `src/`.

Claude Code users: add `.claude/CLAUDE.md` containing `@../AGENTS.md` to
import this file (`.claude/` is gitignored).

## Commands

``` r

source("tests/tests.R")         # run the full suite (single-file minitest)
devtools::document()            # roxygen2 -> man/, NAMESPACE
rmarkdown::render("README.Rmd") # rebuild README
```

``` bash
R CMD build .
R CMD check --no-manual --compact-vignettes=gs+qpdf secretbase_*.tar.gz   # matches CI
R CMD INSTALL .
```

## Formatter

Air, configured in `air.toml`: width 100, 2-space indent,
`persistent-line-breaks = false`. **`tests/` is excluded** — don’t
reformat `tests/tests.R`.

## Two-layer architecture

**R layer (`R/`)** — thin wrappers over
[`.Call()`](https://rdrr.io/r/base/CallExternal.html):

- `secret.R` — hash interfaces:
  [`sha3()`](https://shikokuchuo.net/secretbase/dev/reference/sha3.md),
  [`shake256()`](https://shikokuchuo.net/secretbase/dev/reference/shake256.md),
  [`keccak()`](https://shikokuchuo.net/secretbase/dev/reference/keccak.md),
  [`sha256()`](https://shikokuchuo.net/secretbase/dev/reference/sha256.md),
  [`siphash13()`](https://shikokuchuo.net/secretbase/dev/reference/siphash13.md)
- `base.R` — encoding / serialization interfaces: base64, base58, CBOR,
  JSON

**C layer (`src/`)**:

- `secret.h` — shared header: context structures, constants, utilities
- `init.c` — `.Call` registration
- `sha3.c` — SHA-3 / SHAKE256 / Keccak (Mbed TLS derived)
- `sha256.c` — SHA-256 (Mbed TLS derived)
- `siphash.c` — SipHash-1-3 (c-siphash derived)
- `base64.c` — base64, including URL-safe variant (Mbed TLS derived)
- `base58.c` — Base58Check: 4-byte double-SHA-256 checksum, no version
  byte (libbase58 derived)
- `cbor.c` — CBOR (RFC 8949)
- `json.c` — JSON (minimal; designed for HTTP API request/response
  bodies)

## Load-bearing implementation details

- **Streaming serialization**: hash functions serialize R objects
  directly into the hash context via custom callbacks — the serialized
  object is never materialized in memory. Always R serialization version
  3, big-endian; the first 6 header bytes are skipped for cross-platform
  portability.
- **File hashing**: files are read in 65536-byte chunks (`SB_BUF_SIZE`),
  so files larger than RAM can be hashed.
- **`convert` argument** controls output format: `TRUE` = character
  string (hex for hashes, base64/base58 for encoding), `FALSE` = raw
  vector, `NA` = integer vector (SHAKE256) or unserialized object
  (base64/base58 decoding).
- C style: defensive programming, explicit error checking, early returns
  on error.

## Testing

Single-file custom “minitest” framework defined at the top of
`tests/tests.R`: `test_library()`, `test_true()`, `test_null()`,
`test_type()`, `test_equal()`, `test_identical()`, `test_error()` (with
`containing =` for fixed-string message matching).

Test vectors: NIST known answers for the SHA functions; Bitcoin test
vectors for Base58Check. All parameter combinations, error handling,
serialization, and file operations are covered. Platform-specific tests
(e.g. Unix file permissions) run conditionally. `R CMD check` runs the
suite automatically.

## Packaging notes

- roxygen2 with markdown (8.0.0); `NAMESPACE` is generated — never
  hand-edit.
- Version is `major.minor.patch.dev` (current dev tag `.9000`).
- `AGENTS.md`, `.claude/`, and `.posit/` are in `.Rbuildignore` and
  don’t ship to CRAN.
- `Config/build/compilation-database: true` in DESCRIPTION makes R emit
  `compile_commands.json` (gitignored) for clangd-based C tooling.
- PR-comment commands (`.github/workflows/pr-commands.yaml`) —
  commenting `/document` runs `roxygen2::roxygenise()`; `/style` runs
  `styler::style_pkg()`. Both commit back to the PR branch.
