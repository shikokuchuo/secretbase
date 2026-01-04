# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Package Overview

secretbase is an R package providing fast, memory-efficient streaming hash functions and encoding/decoding. It implements:
- SHA-256, SHA-3, and Keccak cryptographic hash functions
- SHAKE256 extendable-output function (XOF)
- SipHash-1-3 pseudo-random function
- Base64 encoding/decoding
- Base58 encoding/decoding with 4-byte double SHA-256 checksum (no version byte prefix)

All hash functions support both direct hashing of strings/raw vectors and streaming hashing of files and R objects through serialization.

## Development Commands

### Building and Testing
```bash
# Run tests (uses minitest framework in tests/tests.R)
Rscript tests/tests.R

# Build and check package
R CMD build .
R CMD check secretbase_*.tar.gz

# Install from source
R CMD INSTALL .
```

### Testing from R Console
```r
# Load package
library(secretbase)

# Run all tests
source("tests/tests.R")
```

### CI/CD
The package uses GitHub Actions workflows in `.github/workflows/`:
- `R-CMD-check.yaml` - Multi-platform R CMD check (Ubuntu, macOS, Windows with multiple R versions)
- `test-coverage.yaml` - Code coverage via codecov
- `pkgdown.yaml` - Build and deploy package documentation site

## Architecture

### Two-Layer Design

**R Layer (R/*.R)**:
- `R/secret.R` - Hash function interfaces (sha3, shake256, keccak, sha256, siphash13)
- `R/base.R` - Base64 and Base58Check encoding/decoding interfaces
- All R functions are thin wrappers that call C code via `.Call()`

**C Layer (src/*.c)**:
- `src/secret.h` - Header with context structures and constants
- `src/init.c` - Package registration for .Call interface
- `src/secret.c` - SHA-3/SHAKE256/Keccak implementations (Mbed TLS based)
- `src/secret2.c` - SHA-256 implementation (Mbed TLS based)
- `src/secret3.c` - SipHash implementation (c-siphash based)
- `src/base.c` - Base64 implementation (Mbed TLS based)
- `src/base2.c` - Base58Check implementation (libbase58 based)

### Key Implementation Details

**Streaming Serialization**:
All hash functions support streaming R object serialization without materializing the full serialized object in memory. This is achieved through:
- Custom serialization callbacks that feed data directly to hash contexts
- Always uses R serialization version 3, big-endian representation
- Skips headers (first 6 bytes) for portability across platforms

**File Hashing**:
Files are read and hashed in 65536-byte chunks (SB_BUF_SIZE), allowing files larger than available RAM to be hashed.

**Output Formats**:
The `convert` parameter controls output format:
- `TRUE` - character string (hex for hashes, base64/base58 for encoding)
- `FALSE` - raw vector
- `NA` - integer vector (for hashes with SHAKE256) or unserialized object (for base64/base58 decoding)

### Context Structures
- `mbedtls_sha3_context` - SHA-3/SHAKE256/Keccak state (25 × 64-bit words)
- `mbedtls_sha256_context` - SHA-256 state (8 × 32-bit words + 64-byte buffer)
- `CSipHash` - SipHash state (4 × 64-bit v-registers + padding tracking)
- `secretbase_context` - Wrapper for serialization streaming

## Testing Framework

The package uses a custom minimal testing framework called "minitest" (defined at the top of tests/tests.R):
- `test_library()` - Load package
- `test_type()` - Assert object type
- `test_equal()` - Assert equality
- `test_identical()` - Assert identical (stricter than equal)
- `test_error()` - Assert error with optional message matching

Tests validate against NIST known hashes and test all parameter combinations, error handling, serialization, and file operations. Base58Check tests use known Bitcoin test vectors.

## Code Style
- R code uses roxygen2 for documentation (RoxygenNote: 7.3.3)
- C code follows defensive programming with explicit error checking
- Platform-specific tests conditionally run (e.g., Unix-only file permission tests)
- All C functions use early returns for error cases
