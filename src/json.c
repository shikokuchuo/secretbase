// secretbase ------------------------------------------------------------------

#include "Rinternals.h"
#include "secret.h"

// minimal JSON parser ---------------------------------------------------------

static inline void json_skip_ws(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static SEXP json_parse_value(const char **p);

static int json_count_elements(const char *scan) {
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
  return count;
}

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
        case 'b': *d++ = '\b'; break;
        case 'f': *d++ = '\f'; break;
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

  int count = (**p == ']') ? 0 : json_count_elements(*p);
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

  int count = (**p == '}') ? 0 : json_count_elements(*p);
  SEXP out, names;
  PROTECT(out = Rf_allocVector(VECSXP, count));
  if (count) {
    names = Rf_allocVector(STRSXP, count);
    Rf_namesgets(out, names);
  }

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
  UNPROTECT(1);
  return out;
}

static SEXP json_parse_value(const char **p) {
  json_skip_ws(p);
  switch (**p) {
    case '{': return json_parse_object(p);
    case '[': return json_parse_array(p);
    case '"': return json_parse_string(p);
    case 't':
      if (strncmp(*p, "true", 4) == 0) { *p += 4; return Rf_ScalarLogical(1); }
      return R_NilValue;
    case 'f':
      if (strncmp(*p, "false", 5) == 0) { *p += 5; return Rf_ScalarLogical(0); }
      return R_NilValue;
    case 'n':
      if (strncmp(*p, "null", 4) == 0) { *p += 4; return R_NilValue; }
      return R_NilValue;
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return json_parse_number(p);
    default:
      return R_NilValue;
  }
}

// minimal JSON encoder --------------------------------------------------------

static void json_encode_string(nano_buf *buf, const char *s) {
  nano_buf_char(buf, '"');
  while (*s) {
    switch (*s) {
      case '"':  nano_buf_str(buf, "\\\"", 2); break;
      case '\\': nano_buf_str(buf, "\\\\", 2); break;
      case '\n': nano_buf_str(buf, "\\n", 2); break;
      case '\r': nano_buf_str(buf, "\\r", 2); break;
      case '\t': nano_buf_str(buf, "\\t", 2); break;
      case '\b': nano_buf_str(buf, "\\b", 2); break;
      case '\f': nano_buf_str(buf, "\\f", 2); break;
      default:
        if ((unsigned char) *s < 0x20) {
          char esc[7];
          snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char) *s);
          nano_buf_str(buf, esc, 6);
        } else {
          nano_buf_char(buf, *s);
        }
    }
    s++;
  }
  nano_buf_char(buf, '"');
}

static void json_encode_value(nano_buf *buf, SEXP x);

static void json_encode_object(nano_buf *buf, SEXP x) {
  nano_buf_char(buf, '{');
  R_xlen_t n = XLENGTH(x);
  SEXP names;
  PROTECT(names = Rf_getAttrib(x, R_NamesSymbol));
  for (R_xlen_t i = 0; i < n; i++) {
    if (i > 0) nano_buf_char(buf, ',');
    json_encode_string(buf, CHAR(STRING_ELT(names, i)));
    nano_buf_char(buf, ':');
    json_encode_value(buf, VECTOR_ELT(x, i));
  }
  UNPROTECT(1);
  nano_buf_char(buf, '}');
}

static void json_encode_array(nano_buf *buf, SEXP x) {
  nano_buf_char(buf, '[');
  R_xlen_t n = XLENGTH(x);
  for (R_xlen_t i = 0; i < n; i++) {
    if (i > 0) nano_buf_char(buf, ',');
    json_encode_value(buf, VECTOR_ELT(x, i));
  }
  nano_buf_char(buf, ']');
}

#define JSON_ARRAY_OPEN(buf, n) if (n != 1) nano_buf_char(buf, '[')
#define JSON_ARRAY_CLOSE(buf, n) if (n != 1) nano_buf_char(buf, ']')

static void json_encode_value(nano_buf *buf, SEXP x) {
  switch (TYPEOF(x)) {
    case NILSXP:
      nano_buf_str(buf, "null", 4);
      break;
    case LGLSXP: {
      R_xlen_t n = XLENGTH(x);
      const int *p = (const int *) DATAPTR_RO(x);
      JSON_ARRAY_OPEN(buf, n);
      for (R_xlen_t i = 0; i < n; i++) {
        if (i > 0) nano_buf_char(buf, ',');
        if (p[i] == NA_LOGICAL)
          nano_buf_str(buf, "null", 4);
        else if (p[i])
          nano_buf_str(buf, "true", 4);
        else
          nano_buf_str(buf, "false", 5);
      }
      JSON_ARRAY_CLOSE(buf, n);
      break;
    }
    case INTSXP: {
      R_xlen_t n = XLENGTH(x);
      const int *p = (const int *) DATAPTR_RO(x);
      JSON_ARRAY_OPEN(buf, n);
      for (R_xlen_t i = 0; i < n; i++) {
        if (i > 0) nano_buf_char(buf, ',');
        if (p[i] == NA_INTEGER) {
          nano_buf_str(buf, "null", 4);
        } else {
          char tmp[32];
          int len = snprintf(tmp, sizeof(tmp), "%d", p[i]);
          nano_buf_str(buf, tmp, len);
        }
      }
      JSON_ARRAY_CLOSE(buf, n);
      break;
    }
    case REALSXP: {
      R_xlen_t n = XLENGTH(x);
      const double *p = (const double *) DATAPTR_RO(x);
      JSON_ARRAY_OPEN(buf, n);
      for (R_xlen_t i = 0; i < n; i++) {
        if (i > 0) nano_buf_char(buf, ',');
        if (ISNA(p[i]) || ISNAN(p[i])) {
          nano_buf_str(buf, "null", 4);
        } else {
          char tmp[32];
          int len = snprintf(tmp, sizeof(tmp), "%.15g", p[i]);
          nano_buf_str(buf, tmp, len);
        }
      }
      JSON_ARRAY_CLOSE(buf, n);
      break;
    }
    case STRSXP: {
      R_xlen_t n = XLENGTH(x);
      JSON_ARRAY_OPEN(buf, n);
      for (R_xlen_t i = 0; i < n; i++) {
        if (i > 0) nano_buf_char(buf, ',');
        SEXP s = STRING_ELT(x, i);
        if (s == NA_STRING)
          nano_buf_str(buf, "null", 4);
        else
          json_encode_string(buf, CHAR(s));
      }
      JSON_ARRAY_CLOSE(buf, n);
      break;
    }
    case VECSXP: {
      SEXP names = Rf_getAttrib(x, R_NamesSymbol);
      if (names == R_NilValue)
        json_encode_array(buf, x);
      else
        json_encode_object(buf, x);
      break;
    }
    default:
      nano_buf_str(buf, "null", 4);
  }
}

// secretbase - exported functions ---------------------------------------------

SEXP secretbase_jsonenc(SEXP x) {

  if (TYPEOF(x) != VECSXP ||
      (XLENGTH(x) > 0 && Rf_getAttrib(x, R_NamesSymbol) == R_NilValue))
    Rf_error("'x' must be a named list");

  nano_buf buf;
  NANO_ALLOC(&buf, SB_INIT_BUFSIZE);
  json_encode_object(&buf, x);

  SEXP out;
  PROTECT(out = Rf_allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE((char *) buf.buf, buf.cur, CE_UTF8));
  NANO_FREE(buf);
  UNPROTECT(1);

  return out;

}

SEXP secretbase_jsondec(SEXP x) {

  const char *json;
  if (TYPEOF(x) == RAWSXP) {
    json = CHAR(Rf_mkCharLenCE((const char *) DATAPTR_RO(x), XLENGTH(x), CE_UTF8));
  } else if (TYPEOF(x) == STRSXP) {
    json = CHAR(STRING_ELT(x, 0));
  } else {
    return Rf_allocVector(VECSXP, 0);
  }
  json_skip_ws(&json);
  
  if (*json != '{') return Rf_allocVector(VECSXP, 0);
  return json_parse_object(&json);

}
