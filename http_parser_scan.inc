/* Bulk scans: the end of a line, the end of a header value and the end of a URL run (license: see http_parser.cc). */

const char* find_crlf(const char* p, const char* data, size_t len);
const char* find_value_end(const char* p, const char* data, size_t len);


// scan_crlf: the first CR or LF in [p, end), or end if there is none. Whole 16-byte
// blocks that lie inside [p, end) go through NEON or SSE2, then a byte loop takes
// the tail, so no byte outside [p, end) is ever read.
static inline const char* scan_crlf(const char* p, const char* end) {
#if defined(HTTP_PARSER_NEON)
  const uint8x16_t cr = vdupq_n_u8(CR);
  const uint8x16_t lf = vdupq_n_u8(LF);
  while (end - p >= 16) {
    const uint8x16_t v = vld1q_u8((const uint8_t*) p);
    const uint8x16_t m = vorrq_u8(vceqq_u8(v, cr), vceqq_u8(v, lf));
    /* narrow to 4 bits per input byte; the lowest set nibble is the first match */
    const uint64_t bits = vget_lane_u64(
        vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);
    if (bits) {
      return p + (__builtin_ctzll(bits) >> 2);
    }
    p += 16;
  }
#elif defined(HTTP_PARSER_SSE2)
  const __m128i cr = _mm_set1_epi8(CR);
  const __m128i lf = _mm_set1_epi8(LF);
  while (end - p >= 16) {
    const __m128i v = _mm_loadu_si128((const __m128i*) p);
    const unsigned bits = (unsigned) _mm_movemask_epi8(
        _mm_or_si128(_mm_cmpeq_epi8(v, cr), _mm_cmpeq_epi8(v, lf)));
    if (bits) {
      return p + __builtin_ctz(bits);
    }
    p += 16;
  }
#endif
  while (p < end) {
    if (*p == CR || *p == LF) {
      return p;
    }
    ++p;
  }
  return end;
}

// find_crlf: fast-forward to the next CR or LF (whichever comes first) within the
// header-size limit, or return data+len if neither is present. One pass over the
// bytes. It stays out of line: inlined into http_parser_execute() the vector code
// costs the state machine's registers and slows every other state down.
HTTP_PARSER_NOINLINE const char* find_crlf(const char* p, const char* data, size_t len) {
  size_t limit = data + len - p;
  const char* r;

  limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

  r = scan_crlf(p, p + limit);
  return r == p + limit ? data + len : r;
}

// scan_value_end: the first byte in [p, end) that a header value may not hold
// (IS_HEADER_CHAR: a control byte other than HT, or DEL), CR and LF included, or end.
// The same blocks and tail as scan_crlf.
static inline const char* scan_value_end(const char* p, const char* end) {
#if defined(HTTP_PARSER_NEON)
  const uint8x16_t sp = vdupq_n_u8(' ');
  const uint8x16_t ht = vdupq_n_u8('\t');
  const uint8x16_t del = vdupq_n_u8(127);
  while (end - p >= 16) {
    const uint8x16_t v = vld1q_u8((const uint8_t*) p);
    const uint8x16_t m = vorrq_u8(vbicq_u8(vcltq_u8(v, sp), vceqq_u8(v, ht)), vceqq_u8(v, del));
    const uint64_t bits = vget_lane_u64(
        vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);
    if (bits) {
      return p + (__builtin_ctzll(bits) >> 2);
    }
    p += 16;
  }
#elif defined(HTTP_PARSER_SSE2)
  const __m128i us = _mm_set1_epi8(0x1f);
  const __m128i ht = _mm_set1_epi8('\t');
  const __m128i del = _mm_set1_epi8(127);
  while (end - p >= 16) {
    const __m128i v = _mm_loadu_si128((const __m128i*) p);
    /* v <= 0x1f unsigned: min(v, 0x1f) == v */
    const __m128i ctl = _mm_cmpeq_epi8(_mm_min_epu8(v, us), v);
    const unsigned bits = (unsigned) _mm_movemask_epi8(_mm_or_si128(
        _mm_andnot_si128(_mm_cmpeq_epi8(v, ht), ctl), _mm_cmpeq_epi8(v, del)));
    if (bits) {
      return p + __builtin_ctz(bits);
    }
    p += 16;
  }
#endif
  while (p < end) {
    if (!IS_HEADER_CHAR(*p) || *p == CR || *p == LF) {
      return p;
    }
    ++p;
  }
  return end;
}

// find_value_end: find_crlf for a parser that is not lenient: it also stops at a byte
// a header value may not hold, which the loop in s_header_value then rejects.
HTTP_PARSER_NOINLINE const char* find_value_end(const char* p, const char* data, size_t len) {
  size_t limit = data + len - p;
  const char* r;

  limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

  r = scan_value_end(p, p + limit);
  return r == p + limit ? data + len : r;
}

/* skip_url_chars: the first byte in [q, e) that is not a URL character (see
 * IS_URL_CHAR), or e. In strict mode the URL characters are 0x21..0x7e except
 * '#' and '?', which vector code tests in 16-byte blocks that lie inside
 * [q, e); the table loop takes the tail, and every byte in non-strict mode.
 * Nothing outside [q, e) is read. */
HTTP_PARSER_NOINLINE static const char*
skip_url_chars(const char* q, const char* e)
{
#if HTTP_PARSER_STRICT && defined(HTTP_PARSER_NEON)
  const uint8x16_t lo = vdupq_n_u8(0x21);
  const uint8x16_t span = vdupq_n_u8(0x5d);
  const uint8x16_t hash = vdupq_n_u8('#');
  const uint8x16_t qm = vdupq_n_u8('?');
  while (e - q >= 16) {
    const uint8x16_t v = vld1q_u8((const uint8_t*) q);
    /* (v - 0x21) as unsigned is above 0x5d for bytes below 0x21 and above 0x7e */
    const uint8x16_t bad = vorrq_u8(
        vorrq_u8(vcgtq_u8(vsubq_u8(v, lo), span), vceqq_u8(v, hash)),
        vceqq_u8(v, qm));
    const uint64_t bits = vget_lane_u64(
        vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(bad), 4)), 0);
    if (bits) {
      return q + (__builtin_ctzll(bits) >> 2);
    }
    q += 16;
  }
#elif HTTP_PARSER_STRICT && defined(HTTP_PARSER_SSE2)
  const __m128i lo = _mm_set1_epi8(0x21);
  const __m128i flip = _mm_set1_epi8((char) 0x80);
  const __m128i span = _mm_set1_epi8((char) (0x5d ^ 0x80));
  const __m128i hash = _mm_set1_epi8('#');
  const __m128i qm = _mm_set1_epi8('?');
  while (e - q >= 16) {
    const __m128i v = _mm_loadu_si128((const __m128i*) q);
    /* SSE2 compares signed bytes: flip the sign bit to order them unsigned */
    const __m128i out = _mm_cmpgt_epi8(_mm_xor_si128(_mm_sub_epi8(v, lo), flip), span);
    const unsigned bits = (unsigned) _mm_movemask_epi8(_mm_or_si128(
        _mm_or_si128(out, _mm_cmpeq_epi8(v, hash)), _mm_cmpeq_epi8(v, qm)));
    if (bits) {
      return q + __builtin_ctz(bits);
    }
    q += 16;
  }
#endif
  while (q < e && IS_URL_CHAR(*q)) {
    ++q;
  }
  return q;
}
