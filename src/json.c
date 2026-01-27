// secretbase ------------------------------------------------------------------

#include "secret.h"

// minimal JSON parser ---------------------------------------------------------

static inline void json_skip_ws(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static SEXP json_parse_value(const char **p);

static SEXP json_parse_string(const char **p) {
  (*p)++; // skip opening "
  const char *start = *p;
  size_t len = 0;
  while (**p && **p != '"') {
    if (**p == '\\' && (*p)[1]) (*p)++;
    (*p)++;
    len++;
  }
  if (**p != '"') return R_NilValue;

  char *buf = (char *) R_alloc(len + 1, 1);
  const char *s = start;
  char *d = buf;
  while (s < *p) {
    if (*s == '\\' && s[1]) {
      s++;
      switch (*s) {
        case 'n': *d++ = '\n'; break;
        case 'r': *d++ = '\r'; break;
        case 't': *d++ = '\t'; break;
        default: *d++ = *s;
      }
      s++;
    } else {
      *d++ = *s++;
    }
  }
  *d = '\0';
  (*p)++; // skip closing "
  return Rf_mkString(buf);
}

static SEXP json_parse_number(const char **p) {
  char *end;
  double val = strtod(*p, &end);
  if (end == *p) return R_NilValue;
  *p = end;
  return Rf_ScalarReal(val);
}

static SEXP json_parse_array(const char **p) {
  (*p)++; // skip [
  json_skip_ws(p);

  if (**p == ']') { (*p)++; return Rf_allocVector(VECSXP, 0); }

  // First pass: count elements
  const char *scan = *p;
  int depth = 1, count = 1;
  while (*scan && depth > 0) {
    if (*scan == '"') {
      scan++;
      while (*scan && !(*scan == '"' && scan[-1] != '\\')) scan++;
    } else if (*scan == '[' || *scan == '{') {
      depth++;
    } else if (*scan == ']' || *scan == '}') {
      depth--;
    } else if (*scan == ',' && depth == 1) {
      count++;
    }
    if (*scan) scan++;
  }

  SEXP out = PROTECT(Rf_allocVector(VECSXP, count));
  for (int i = 0; i < count; i++) {
    json_skip_ws(p);
    SET_VECTOR_ELT(out, i, json_parse_value(p));
    json_skip_ws(p);
    if (**p == ',') (*p)++;
  }
  json_skip_ws(p);
  if (**p == ']') (*p)++;
  UNPROTECT(1);
  return out;
}

static SEXP json_parse_object(const char **p) {
  (*p)++; // skip {
  json_skip_ws(p);

  if (**p == '}') { (*p)++; return Rf_allocVector(VECSXP, 0); }

  // First pass: count pairs
  const char *scan = *p;
  int depth = 1, count = 1;
  while (*scan && depth > 0) {
    if (*scan == '"') {
      scan++;
      while (*scan && !(*scan == '"' && scan[-1] != '\\')) scan++;
    } else if (*scan == '[' || *scan == '{') {
      depth++;
    } else if (*scan == ']' || *scan == '}') {
      depth--;
    } else if (*scan == ',' && depth == 1) {
      count++;
    }
    if (*scan) scan++;
  }

  SEXP out = PROTECT(Rf_allocVector(VECSXP, count));
  SEXP names = PROTECT(Rf_allocVector(STRSXP, count));

  for (int i = 0; i < count; i++) {
    json_skip_ws(p);
    if (**p != '"') break;
    SEXP key = json_parse_string(p);
    SET_STRING_ELT(names, i, STRING_ELT(key, 0));
    json_skip_ws(p);
    if (**p == ':') (*p)++;
    json_skip_ws(p);
    SET_VECTOR_ELT(out, i, json_parse_value(p));
    json_skip_ws(p);
    if (**p == ',') (*p)++;
  }
  json_skip_ws(p);
  if (**p == '}') (*p)++;
  Rf_setAttrib(out, R_NamesSymbol, names);
  UNPROTECT(2);
  return out;
}

static SEXP json_parse_value(const char **p) {
  json_skip_ws(p);
  switch (**p) {
    case '{': return json_parse_object(p);
    case '[': return json_parse_array(p);
    case '"': return json_parse_string(p);
    case 't':
      if ((*p)[1] == 'r' && (*p)[2] == 'u' && (*p)[3] == 'e') {
        *p += 4; return Rf_ScalarLogical(1);
      }
      return R_NilValue;
    case 'f':
      if ((*p)[1] == 'a' && (*p)[2] == 'l' && (*p)[3] == 's' && (*p)[4] == 'e') {
        *p += 5; return Rf_ScalarLogical(0);
      }
      return R_NilValue;
    case 'n':
      if ((*p)[1] == 'u' && (*p)[2] == 'l' && (*p)[3] == 'l') {
        *p += 4; return R_NilValue;
      }
      return R_NilValue;
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return json_parse_number(p);
    default:
      return R_NilValue;
  }
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_jsondec(SEXP x) {

  const char *json;
  if (TYPEOF(x) == RAWSXP) {
    json = (const char *) RAW(x);
  } else if (TYPEOF(x) == STRSXP) {
    json = CHAR(STRING_ELT(x, 0));
  } else {
    return Rf_allocVector(VECSXP, 0);
  }
  json_skip_ws(&json);
  if (*json != '{') return Rf_allocVector(VECSXP, 0);
  return json_parse_object(&json);

}
