// secretbase ------------------------------------------------------------------

#include "Rinternals.h"
#include "secret.h"

// minimal JSON parser ---------------------------------------------------------

#define JSON_MAX_DEPTH 512

static inline void json_skip_ws(const char **p) {
  while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static inline int json_hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int json_parse_hex4(const char *s, unsigned int *cp) {
  *cp = 0;
  for (int i = 0; i < 4; i++) {
    int d = json_hex_digit(s[i]);
    if (d < 0) return 0;
    *cp = (*cp << 4) | d;
  }
  return 1;
}

static inline char *utf8_encode_cp(char *d, unsigned int cp) {
  if (cp < 0x80) {
    *d++ = (char) cp;
  } else if (cp < 0x800) {
    *d++ = (char) (0xC0 | (cp >> 6));
    *d++ = (char) (0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    *d++ = (char) (0xE0 | (cp >> 12));
    *d++ = (char) (0x80 | ((cp >> 6) & 0x3F));
    *d++ = (char) (0x80 | (cp & 0x3F));
  } else {
    *d++ = (char) (0xF0 | (cp >> 18));
    *d++ = (char) (0x80 | ((cp >> 12) & 0x3F));
    *d++ = (char) (0x80 | ((cp >> 6) & 0x3F));
    *d++ = (char) (0x80 | (cp & 0x3F));
  }
  return d;
}

static SEXP json_parse_value_depth(const char **p, int depth);

static int json_count_elements(const char *scan) {
  int depth = 1, count = 1;
  const char *string_start = NULL;
  while (*scan && depth > 0) {
    if (*scan == '"') {
      string_start = scan;
      scan++;
      while (*scan) {
        if (*scan == '"') {
          // Count preceding backslashes to handle escaped quotes correctly
          // e.g., "test\\" ends at second quote (backslash is escaped)
          // while "test\"" does not end at second quote (quote is escaped)
          int slashes = 0;
          const char *check = scan - 1;
          while (check > string_start && *check == '\\') {
            slashes++;
            check--;
          }
          // Quote is real (not escaped) only if even number of backslashes precede it
          if (slashes % 2 == 0) break;
        }
        scan++;
      }
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
  
  // Find end of string
  while (**p && **p != '"') {
    if (**p == '\\' && (*p)[1]) (*p)++;
    (*p)++;
  }
  if (**p != '"') return R_MissingArg;
  
  // Allocate buffer: input length is sufficient since escape sequences
  // (\uXXXX = 6 chars -> 1-4 bytes, surrogate pairs = 12 chars -> 4 bytes)
  // always shrink or stay same size when decoded
  size_t buf_size = (size_t)(*p - start) + 1;
  char *buf = R_alloc(buf_size, 1);
  const char *s = start;
  char *d = buf;
  
  while (s < *p) {
    if (*s == '\\' && s[1]) {
      s++;
      switch (*s) {
        case 'n': *d++ = '\n'; s++; break;
        case 'r': *d++ = '\r'; s++; break;
        case 't': *d++ = '\t'; s++; break;
        case 'b': *d++ = '\b'; s++; break;
        case 'f': *d++ = '\f'; s++; break;
        case 'u': {
          // Parse \uXXXX Unicode escape
          unsigned int cp;
          if (s + 5 <= *p && json_parse_hex4(s + 1, &cp)) {
            s += 5; // skip 'u' and 4 hex digits
            
            // Check for UTF-16 surrogate pair (high surrogate: D800-DBFF)
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              // Expect \uXXXX low surrogate (DC00-DFFF)
              if (s + 6 <= *p && s[0] == '\\' && s[1] == 'u') {
                unsigned int low;
                if (json_parse_hex4(s + 2, &low) && low >= 0xDC00 && low <= 0xDFFF) {
                  // Combine surrogate pair into codepoint
                  cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                  s += 6; // skip second \uXXXX
                }
              }
              // If no valid low surrogate follows, cp remains as-is (invalid but tolerated)
            }
            
            d = utf8_encode_cp(d, cp);
          } else {
            // Invalid \u sequence, output literally
            *d++ = 'u';
            s++;
          }
          break;
        }
        default: *d++ = *s++;
      }
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
  if (end == *p) return R_MissingArg;
  *p = end;
  return Rf_ScalarReal(val);
}

static SEXP json_parse_array_depth(const char **p, int depth) {
  if (depth > JSON_MAX_DEPTH)
    Rf_error("JSON nesting too deep (maximum depth: %d)", JSON_MAX_DEPTH);

  (*p)++; // skip [
  json_skip_ws(p);

  int count = (**p == ']') ? 0 : json_count_elements(*p);
  SEXP out;
  PROTECT(out = Rf_allocVector(VECSXP, count));
  for (int i = 0; i < count; i++) {
    SEXP val = json_parse_value_depth(p, depth);
    if (val == R_MissingArg) { UNPROTECT(1); return R_MissingArg; }
    SET_VECTOR_ELT(out, i, val);
    json_skip_ws(p);
    if (**p == ',') (*p)++;
  }
  if (**p == ']') (*p)++;
  UNPROTECT(1);
  return out;
}

static SEXP json_parse_object_depth(const char **p, int depth) {
  if (depth > JSON_MAX_DEPTH)
    Rf_error("JSON nesting too deep (maximum depth: %d)", JSON_MAX_DEPTH);

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
    if (**p != '"') { UNPROTECT(1); return R_MissingArg; }
    SEXP key = json_parse_string(p);
    if (key == R_MissingArg) { UNPROTECT(1); return R_MissingArg; }
    SET_STRING_ELT(names, i, STRING_ELT(key, 0));
    json_skip_ws(p);
    if (**p == ':') (*p)++;
    SEXP val = json_parse_value_depth(p, depth);
    if (val == R_MissingArg) { UNPROTECT(1); return R_MissingArg; }
    SET_VECTOR_ELT(out, i, val);
    json_skip_ws(p);
    if (**p == ',') (*p)++;
  }
  if (**p == '}') (*p)++;
  UNPROTECT(1);
  return out;
}

static SEXP json_parse_value_depth(const char **p, int depth) {
  json_skip_ws(p);
  switch (**p) {
    case '{': return json_parse_object_depth(p, depth + 1);
    case '[': return json_parse_array_depth(p, depth + 1);
    case '"': return json_parse_string(p);
    case 't':
      if (strncmp(*p, "true", 4) == 0) { *p += 4; return Rf_ScalarLogical(1); }
      return R_MissingArg;
    case 'f':
      if (strncmp(*p, "false", 5) == 0) { *p += 5; return Rf_ScalarLogical(0); }
      return R_MissingArg;
    case 'n':
      if (strncmp(*p, "null", 4) == 0) { *p += 4; return R_NilValue; }
      return R_MissingArg;
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return json_parse_number(p);
    default:
      return R_MissingArg;
  }
}

// minimal JSON encoder --------------------------------------------------------

#define JSON_VEC_LOOP(buf, n, encode_elem) do { \
  if (n != 1) nano_buf_char(buf, '['); \
  for (R_xlen_t i = 0; i < n; i++) { \
    if (i > 0) nano_buf_char(buf, ','); \
    encode_elem; \
  } \
  if (n != 1) nano_buf_char(buf, ']'); \
} while(0)

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

static void json_encode_value(nano_buf *buf, SEXP x) {
  R_xlen_t n;
  char tmp[32];
  int len;
  switch (TYPEOF(x)) {
    case NILSXP:
      nano_buf_str(buf, "null", 4);
      break;
    case LGLSXP: {
      n = XLENGTH(x);
      const int *p = (const int *) DATAPTR_RO(x);
      JSON_VEC_LOOP(buf, n,
        nano_buf_str(buf, p[i] == NA_LOGICAL ? "null" : p[i] ? "true" : "false",
                     p[i] == NA_LOGICAL ? 4 : p[i] ? 4 : 5));
      break;
    }
    case INTSXP: {
      n = XLENGTH(x);
      const int *p = (const int *) DATAPTR_RO(x);
      JSON_VEC_LOOP(buf, n,
        if (p[i] == NA_INTEGER) nano_buf_str(buf, "null", 4);
        else { len = snprintf(tmp, sizeof(tmp), "%d", p[i]); nano_buf_str(buf, tmp, len); });
      break;
    }
    case REALSXP: {
      n = XLENGTH(x);
      const double *p = (const double *) DATAPTR_RO(x);
      JSON_VEC_LOOP(buf, n,
        if (ISNA(p[i]) || ISNAN(p[i])) nano_buf_str(buf, "null", 4);
        else { len = snprintf(tmp, sizeof(tmp), "%.15g", p[i]); nano_buf_str(buf, tmp, len); });
      break;
    }
    case STRSXP: {
      n = XLENGTH(x);
      JSON_VEC_LOOP(buf, n, {
        SEXP s = STRING_ELT(x, i);
        if (s == NA_STRING) nano_buf_str(buf, "null", 4);
        else json_encode_string(buf, CHAR(s)); });
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

  nano_buf buf;
  NANO_ALLOC(&buf, SB_INIT_BUFSIZE);
  json_encode_value(&buf, x);

  SEXP out;
  PROTECT(out = Rf_allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE((char *) buf.buf, buf.cur, CE_UTF8));
  NANO_FREE(buf);
  UNPROTECT(1);

  return out;

}

SEXP secretbase_jsondec(SEXP x) {

  const char *json;
  switch (TYPEOF(x)) {
    case RAWSXP: {
      R_xlen_t xlen = XLENGTH(x);
      char *tmp = R_alloc(xlen + 1, 1);
      memcpy(tmp, DATAPTR_RO(x), xlen);
      tmp[xlen] = '\0';
      json = tmp;
      break;
    }
    case STRSXP:
      json = CHAR(STRING_ELT(x, 0));
      break;
    default:
      return Rf_allocVector(VECSXP, 0);
  }

  SEXP out = json_parse_value_depth(&json, 0);

  if (out == R_MissingArg)
    return Rf_allocVector(VECSXP, 0);

  return out;

}
