// secretbase - package level registrations ------------------------------------

#include "secret.h"

SEXP secretbase_cborenc(SEXP);
SEXP secretbase_cbordec(SEXP);

static const R_CallMethodDef callMethods[] = {
  {"secretbase_cborenc", (DL_FUNC) &secretbase_cborenc, 1},
  {"secretbase_cbordec", (DL_FUNC) &secretbase_cbordec, 1},
  {"secretbase_base64enc", (DL_FUNC) &secretbase_base64enc, 2},
  {"secretbase_base64dec", (DL_FUNC) &secretbase_base64dec, 2},
  {"secretbase_base58enc", (DL_FUNC) &secretbase_base58enc, 2},
  {"secretbase_base58dec", (DL_FUNC) &secretbase_base58dec, 2},
  {"secretbase_sha3", (DL_FUNC) &secretbase_sha3, 3},
  {"secretbase_sha3_file", (DL_FUNC) &secretbase_sha3_file, 3},
  {"secretbase_shake256", (DL_FUNC) &secretbase_shake256, 3},
  {"secretbase_shake256_file", (DL_FUNC) &secretbase_shake256_file, 3},
  {"secretbase_keccak", (DL_FUNC) &secretbase_keccak, 3},
  {"secretbase_keccak_file", (DL_FUNC) &secretbase_keccak_file, 3},
  {"secretbase_sha256", (DL_FUNC) &secretbase_sha256, 3},
  {"secretbase_sha256_file", (DL_FUNC) &secretbase_sha256_file, 3},
  {"secretbase_siphash13", (DL_FUNC) &secretbase_siphash13, 3},
  {"secretbase_siphash13_file", (DL_FUNC) &secretbase_siphash13_file, 3},
  {NULL, NULL, 0}
};

void attribute_visible R_init_secretbase(DllInfo* dll) {
  R_registerRoutines(dll, NULL, callMethods, NULL, NULL);
  R_useDynamicSymbols(dll, FALSE);
  R_forceSymbols(dll, TRUE);
}
