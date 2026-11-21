/*
 * Based on src/http/ngx_http_parse.c from NGINX copyright Igor Sysoev
 *
 * Additional changes are licensed under the same terms as NGINX and
 * copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "http_parser_internal.h"
#include "http_parser_chars.h"
#include "http_parser_tables.h"

#define CURRENT_STATE() p_state
#define UPDATE_STATE(V) p_state = (enum state) (V);
#define RETURN(V)                                                    \
do {                                                                 \
  parser->state = CURRENT_STATE();                                   \
  return (V);                                                        \
} while (0);
#define REEXECUTE()                                                  \
  goto reexecute;                                                    \


/* Run the notify callback FOR, returning ER if it fails */
#define CALLBACK_NOTIFY_(FOR, ER)                                    \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if likely(settings->on_##FOR) {                                    \
    parser->state = CURRENT_STATE();                                 \
    if unlikely(0 != settings->on_##FOR(parser)) {                   \
      SET_ERRNO(HPE_CB_##FOR);                                       \
    }                                                                \
    UPDATE_STATE(parser->state);                                     \
                                                                     \
    /* We either errored above or got paused; get out */             \
    if unlikely(HTTP_PARSER_ERRNO(parser) != HPE_OK) {               \
      return (ER);                                                   \
    }                                                                \
  }                                                                  \
} while (0)

/* Run the notify callback FOR and consume the current byte */
#define CALLBACK_NOTIFY(FOR)            CALLBACK_NOTIFY_(FOR, p - data + 1)

/* Run the notify callback FOR and don't consume the current byte */
#define CALLBACK_NOTIFY_NOADVANCE(FOR)  CALLBACK_NOTIFY_(FOR, p - data)

/* Run data callback FOR with LEN bytes, returning ER if it fails */
#define CALLBACK_DATA_(FOR, LEN, ER)                                 \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (FOR##_mark) {                                                  \
    if likely(settings->on_##FOR) {                                  \
      parser->state = CURRENT_STATE();                               \
      if unlikely(0 !=                                               \
                   settings->on_##FOR(parser, FOR##_mark, (LEN))) {  \
        SET_ERRNO(HPE_CB_##FOR);                                     \
      }                                                              \
      UPDATE_STATE(parser->state);                                   \
                                                                     \
      /* We either errored above or got paused; get out */           \
      if unlikely(HTTP_PARSER_ERRNO(parser) != HPE_OK) {             \
        return (ER);                                                 \
      }                                                              \
    }                                                                \
    FOR##_mark = NULL;                                               \
  }                                                                  \
} while (0)

/* Run the data callback FOR and consume the current byte */
#define CALLBACK_DATA(FOR)                                           \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data + 1)

/* Run the data callback FOR and don't consume the current byte */
#define CALLBACK_DATA_NOADVANCE(FOR)                                 \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data)

/* Set the mark FOR; non-destructive if mark is already set */
#define MARK(FOR)                                                    \
do {                                                                 \
  if (!FOR##_mark) {                                                 \
    FOR##_mark = p;                                                  \
  }                                                                  \
} while (0)

/* Don't allow the total size of the HTTP headers (including the status
 * line) to exceed HTTP_MAX_HEADER_SIZE.  This check is here to protect
 * embedders against denial-of-service attacks where the attacker feeds
 * us a never-ending header that the embedder keeps buffering.
 *
 * This check is arguably the responsibility of embedders but we're doing
 * it on the embedder's behalf because most won't bother and this way we
 * make the web a little safer.  HTTP_MAX_HEADER_SIZE is still far bigger
 * than any reasonable request or response so this should never affect
 * day-to-day operation.
 */
#define COUNT_HEADER_SIZE(V)                                         \
do {                                                                 \
  parser->nread += (V);                                              \
  if unlikely(parser->nread > (HTTP_MAX_HEADER_SIZE)) {              \
    SET_ERRNO(HPE_HEADER_OVERFLOW);                                  \
    goto error;                                                      \
  }                                                                  \
} while (0)

#define PARSING_HEADER(state) (state <= s_headers_done)

#define NEXTHEADERCHAR() \
  if unlikely(p+1 == (data+len)) {                            \
    COUNT_HEADER_SIZE(0);                                     \
    break;                                                    \
  }                                                           \
  ch = *++p;                                                  \
  ++parser->nread;

/* Step to the next byte and count it as the top of the loop does, so that the
 * code can go straight to the state it has just set (goto) instead of through
 * the loop and the dispatch. With no next byte the switch is left and the loop
 * ends, as it does after any other state. */
#define NEXTCHAR_COUNTED() \
  if unlikely(p+1 == (data+len)) {                            \
    break;                                                    \
  }                                                           \
  ch = *++p;                                                  \
  COUNT_HEADER_SIZE(1);

/* The same for a state whose bytes are not counted against the header size. */
#define NEXTCHAR() \
  if unlikely(p+1 == (data+len)) {                            \
    break;                                                    \
  }                                                           \
  ch = *++p;


#define start_state (parser->type == HTTP_REQUEST ? s_start_req : s_start_res)

/* Unless lenient, the HTTP versions a message may carry (llhttp's: 0.9, 1.0, 1.1, 2.0) */
#define KNOWN_VERSION(major, minor)                                            \
  (((major) == 1 && (minor) <= 1) || ((major) == 2 && (minor) == 0) ||        \
   ((major) == 0 && (minor) == 9))
#define VERSION_KNOWN(parser) KNOWN_VERSION((parser)->http_major, (parser)->http_minor)

/* Unless lenient, a chunk extension is checked byte by byte; parser->index is
 * where in the grammar the last byte left it. */
enum chunk_ext_state {
  CHUNK_EXT_START = 0,   /* after ';': a name follows */
  CHUNK_EXT_NAME,        /* in the name */
  CHUNK_EXT_EQUALS,      /* after '=': a token or a quoted string follows */
  CHUNK_EXT_TOKEN,       /* in a token value */
  CHUNK_EXT_QUOTED,      /* in a quoted string */
  CHUNK_EXT_ESCAPE,      /* after a backslash in a quoted string */
  CHUNK_EXT_CLOSED       /* after the closing quote */
};

/* Takes one byte of a chunk-size line after the size; 0 if it may not come here. */
static int chunk_ext_char(http_parser *parser, char ch) {
  const unsigned char c = (unsigned char) ch;
  const int vchar = c > 0x20 && c != 0x7f;  /* VCHAR or obs-text */
  switch (parser->index) {
    case CHUNK_EXT_START:
      if (!STRICT_TOKEN(ch)) return 0;
      parser->index = CHUNK_EXT_NAME;
      return 1;
    case CHUNK_EXT_NAME:
    case CHUNK_EXT_TOKEN:
      if (STRICT_TOKEN(ch)) return 1;
      if (ch == '=' && parser->index == CHUNK_EXT_NAME) { parser->index = CHUNK_EXT_EQUALS; return 1; }
      if (ch == ';') { parser->index = CHUNK_EXT_START; return 1; }
      return ch == CR;
    case CHUNK_EXT_EQUALS:
      if (ch == '"') { parser->index = CHUNK_EXT_QUOTED; return 1; }
      if (!STRICT_TOKEN(ch)) return 0;
      parser->index = CHUNK_EXT_TOKEN;
      return 1;
    case CHUNK_EXT_QUOTED:
      if (ch == '"') { parser->index = CHUNK_EXT_CLOSED; return 1; }
      if (ch == '\\') { parser->index = CHUNK_EXT_ESCAPE; return 1; }
      return vchar || ch == ' ' || ch == '\t';
    case CHUNK_EXT_ESCAPE:
      parser->index = CHUNK_EXT_QUOTED;
      return vchar || ch == ' ' || ch == '\t';
    case CHUNK_EXT_CLOSED:
      if (ch == ';') { parser->index = CHUNK_EXT_START; return 1; }
      return ch == CR;
  }
  return 0;
}


#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    SET_ERRNO(HPE_STRICT);                                           \
    goto error;                                                      \
  }                                                                  \
} while (0)
# define NEW_MESSAGE() (should_keep_alive(parser) ? start_state : s_dead)
#else
# define STRICT_CHECK(cond)
# define NEW_MESSAGE() start_state
#endif

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
/* The parse loop, compiled twice: lenient_http_headers is a constant in each copy,
 * so the strict one carries no flag, and neither keeps it in a register. */
template <bool lenient>
HTTP_PARSER_NOINLINE static size_t execute(http_parser *parser,
                                           const http_parser_settings *settings,
                                           const char *data,
                                           size_t len)
{
  char c, ch;
  int8_t unhex_val;
  const char *p = data;
  const char *header_field_mark = 0;
  const char *header_value_mark = 0;
  const char *url_mark = 0;
  const char *body_mark = 0;
  const char *status_mark = 0;
  enum state p_state = (enum state) parser->state;

  /* We're in an error state. Don't bother doing anything. */
  if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
    return 0;
  }

  if (len == 0) {
    switch (CURRENT_STATE()) {
      case s_body_identity_eof:
        /* Use of CALLBACK_NOTIFY() here would erroneously return 1 byte read if
         * we got paused.
         */
        CALLBACK_NOTIFY_NOADVANCE(message_complete);
        return 0;

      case s_dead:
      case s_start_req_or_res:
      case s_start_res:
      case s_start_req:
        return 0;

      default:
        SET_ERRNO(HPE_INVALID_EOF_STATE);
        return 1;
    }
  }


  if (CURRENT_STATE() == s_header_field)
    header_field_mark = data;
  if (CURRENT_STATE() == s_header_value)
    header_value_mark = data;
  switch (CURRENT_STATE()) {
  case s_req_path:
  case s_req_schema:
  case s_req_schema_slash:
  case s_req_schema_slash_slash:
  case s_req_server_start:
  case s_req_server:
  case s_req_server_with_at:
  case s_req_query_string_start:
  case s_req_query_string:
  case s_req_fragment_start:
  case s_req_fragment:
    url_mark = data;
    break;
  case s_res_status:
    status_mark = data;
    break;
  default:
    break;
  }

  for (p=data; p != data + len; p++) {
    ch = *p;

    if (PARSING_HEADER(CURRENT_STATE()))
      COUNT_HEADER_SIZE(1);

reexecute:
    switch (CURRENT_STATE()) {

      case s_dead:
        /* this state is used after a 'Connection: close' message
         * the parser will error out if it reads another message
         */
        if likely(ch == CR || ch == LF)
          break;

        SET_ERRNO(HPE_CLOSED_CONNECTION);
        goto error;

      case s_start_req_or_res:
      {
        if (ch == CR || ch == LF)
          break;
        parser->flags = 0;
        parser->content_length = ULLONG_MAX;

        if (ch == 'H') {
          UPDATE_STATE(s_res_or_resp_H);

          CALLBACK_NOTIFY(message_begin);
        } else {
          parser->type = HTTP_REQUEST;
          UPDATE_STATE(s_start_req);
          REEXECUTE();
        }

        break;
      }

      case s_res_or_resp_H:
        if (ch == 'T') {
          parser->type = HTTP_RESPONSE;
          UPDATE_STATE(s_res_HT);
        } else {
          if unlikely(ch != 'E') {
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
          }

          parser->type = HTTP_REQUEST;
          parser->method = HTTP_HEAD;
          parser->index = 2;
          UPDATE_STATE(s_req_method);
        }
        break;

      case s_start_res:
      {
        parser->flags = 0;
        parser->extra_flags = 0;
        parser->content_length = ULLONG_MAX;

        switch (ch) {
          case 'H':
            UPDATE_STATE(s_res_H);
            break;

          case CR:
          case LF:
            break;

          default:
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
        }

        CALLBACK_NOTIFY(message_begin);
        break;
      }

      case s_res_H:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_res_HT);
        NEXTHEADERCHAR();

      case s_res_HT:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_res_HTT);
        NEXTHEADERCHAR();

      case s_res_HTT:
        STRICT_CHECK(ch != 'P');
        UPDATE_STATE(s_res_HTTP);
        NEXTHEADERCHAR();

      case s_res_HTTP:
        STRICT_CHECK(ch != '/');
        UPDATE_STATE(s_res_first_http_major);
        break;

      case s_res_first_http_major:
        if unlikely(ch < '0' || ch > '9') {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major = ch - '0';
        UPDATE_STATE(s_res_http_major);
        break;

      /* major HTTP version or dot */
      case s_res_http_major:
      {
        if (ch == '.') {
          UPDATE_STATE(s_res_first_http_minor);
          break;
        }

        /* Unless lenient: one digit (RFC 9112: HTTP/DIGIT.DIGIT) */
        if (!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if unlikely(parser->http_major > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      /* first digit of minor HTTP version */
      case s_res_first_http_minor:
        if unlikely(!IS_NUM(ch)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor = ch - '0';
        /* Unless lenient: the version is complete, and must be a known one */
        if (!lenient && !VERSION_KNOWN(parser)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }
        UPDATE_STATE(s_res_http_minor);
        break;

      /* minor HTTP version or end of request line */
      case s_res_http_minor:
      {
        if (ch == ' ') {
          UPDATE_STATE(s_res_first_status_code);
          break;
        }

        if unlikely(!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if unlikely(parser->http_minor > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      case s_res_first_status_code:
      {
        if (!IS_NUM(ch)) {
          /* Unless lenient: one space before the status (RFC 9112 section 4) */
          if (ch == ' ' && lenient) {
            break;
          }

          SET_ERRNO(HPE_INVALID_STATUS);
          goto error;
        }
        parser->status_code = ch - '0';
        UPDATE_STATE(s_res_status_code);
        break;
      }

      case s_res_status_code:
      {
        if (!IS_NUM(ch)) {
          /* Unless lenient: three digits (RFC 9112 section 4) */
          if (!lenient && parser->status_code < 100) {
            SET_ERRNO(HPE_INVALID_STATUS);
            goto error;
          }
          switch (ch) {
            case ' ':
              UPDATE_STATE(s_res_status_start);
              break;
            case CR:
              UPDATE_STATE(s_res_line_almost_done);
              break;
            case LF:
              if (!lenient) {
                SET_ERRNO(HPE_CR_EXPECTED);
                goto error;
              }
              UPDATE_STATE(s_header_field_start);
              break;
            default:
              SET_ERRNO(HPE_INVALID_STATUS);
              goto error;
          }
          break;
        }

        parser->status_code *= 10;
        parser->status_code += ch - '0';

        if unlikely(parser->status_code > 999) {
          SET_ERRNO(HPE_INVALID_STATUS);
          goto error;
        }

        break;
      }

      case s_res_status_start:
      {
        if (ch == CR) {
          UPDATE_STATE(s_res_line_almost_done);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_field_start);
          break;
        }

        MARK(status);
        UPDATE_STATE(s_res_status);
        parser->index = 0;
        break;
      }

      case s_res_status:
        if (ch == CR) {
          UPDATE_STATE(s_res_line_almost_done);
          CALLBACK_DATA(status);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_field_start);
          CALLBACK_DATA(status);
          break;
        }

        break;

      case s_res_line_almost_done:
        STRICT_CHECK(ch != LF);
        UPDATE_STATE(s_header_field_start);
        break;

      case s_start_req:
      {
        if (ch == CR || ch == LF)
          break;
        parser->flags = 0;
        parser->extra_flags = 0;
        parser->content_length = ULLONG_MAX;

        if unlikely(!IS_ALPHA(ch)) {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        parser->method = (enum http_method) 0;
        parser->index = 1;
        switch (ch) {
          case 'C': parser->method = HTTP_COUNT; /* or COPY, CONNECT, COMMIT, CLOSE, CHECK */ break;
          case 'D': parser->method = HTTP_DUMP; /* or DELETE */ break;
          case 'F': parser->method = HTTP_FLUSH; break;
          case 'G': parser->method = HTTP_GET; break;
          case 'H': parser->method = HTTP_HEAD; break;
          case 'I': parser->method = HTTP_INFO; break;
          case 'L': parser->method = HTTP_LOCK; /* or LINK */ break;
          case 'M': parser->method = HTTP_MOVE; break;
          case 'O': parser->method = HTTP_OPTIONS; /* or OPEN */ break;
          case 'P': parser->method = HTTP_PUT; /* or PURGE, POST, PATCH */ break;
          case 'Q': parser->method = HTTP_QUIT; break;
          case 'R': parser->method = HTTP_RESTORE; break;
          case 'S': parser->method = HTTP_SEARCH; /* or SEARCH */ break;
          case 'T': parser->method = HTTP_TRACE; break;
          case 'U': parser->method = HTTP_UNLOCK; /* or UNLINK, UPDATE, UPSERT */ break;
          case 'W': parser->method = HTTP_WAL; break;
          default:
            SET_ERRNO(HPE_INVALID_METHOD);
            goto error;
        }
        UPDATE_STATE(s_req_method);

        CALLBACK_NOTIFY(message_begin);

        break;
      }

      case s_req_method:
      {
        const char *matcher;
        if unlikely(ch == '\0') {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        matcher = method_strings[parser->method];
        if (ch == ' ' && matcher[parser->index] == '\0') {
          UPDATE_STATE(s_req_spaces_before_url);
        } else if (ch == matcher[parser->index]) {
          ; /* nada */
        } else if (IS_ALPHA(ch)) {

          switch (parser->method << 16 | parser->index << 8 | ch) {
#define XX(meth, pos, ch, new_meth) \
            case (HTTP_##meth << 16 | pos << 8 | ch): \
              parser->method = HTTP_##new_meth; break;

            XX(COUNT,     1, 'L', CLOSE)
            XX(COUNT,     1, 'H', CHECK)
            XX(COUNT,     2, 'M', COMMIT)
            XX(COUNT,     2, 'N', CONNECT)
            XX(COUNT,     2, 'P', COPY)
            XX(DUMP,      1, 'E', DELETE)
            XX(LOCK,      1, 'I', LINK)
            XX(OPTIONS,   2, 'E', OPEN)
            XX(PUT,       1, 'O', POST)
            XX(PUT,       1, 'A', PATCH)
            XX(PUT,       2, 'R', PURGE)
            XX(UNLOCK,    1, 'P', UPDATE)
            XX(UPDATE,    2, 'S', UPSERT)
            XX(UNLOCK,    3, 'I', UNLINK)
#undef XX

            default:
              SET_ERRNO(HPE_INVALID_METHOD);
              goto error;
          }
        } else {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        ++parser->index;
        break;
      }

      case s_req_spaces_before_url:
      {
        if (ch == ' ') break;

        MARK(url);
        if (parser->method == HTTP_CONNECT) {
          UPDATE_STATE(s_req_server_start);
        }

        UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
        if unlikely(CURRENT_STATE() == s_dead) {
          SET_ERRNO(HPE_INVALID_URL);
          goto error;
        }

        break;
      }

      case s_req_schema:
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      {
        switch (ch) {
          /* No whitespace allowed here */
          case ' ':
          case CR:
          case LF:
            SET_ERRNO(HPE_INVALID_URL);
            goto error;
          default:
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
            if unlikely(CURRENT_STATE() == s_dead) {
              SET_ERRNO(HPE_INVALID_URL);
              goto error;
            }
        }

        break;
      }

      case s_req_server:
      case s_req_server_with_at:
      case s_req_path:
      case s_req_query_string_start:
      case s_req_query_string:
      case s_req_fragment_start:
      case s_req_fragment:
      {
        switch (ch) {
          case ' ':
            UPDATE_STATE(s_req_http_start);
            CALLBACK_DATA(url);
            break;
          case LF:
            if (!lenient) {
              SET_ERRNO(HPE_CR_EXPECTED);
              goto error;
            }
            /* FALLTHROUGH */
          case CR:
            /* Unless lenient: a request line has a version. HTTP/0.9 has no
             * headers, and this would read them (RFC 9112 section 3) */
            if (!lenient) {
              SET_ERRNO(HPE_INVALID_VERSION);
              goto error;
            }
            parser->http_major = 0;
            parser->http_minor = 9;
            UPDATE_STATE((ch == CR) ?
              s_req_line_almost_done :
              s_header_field_start);
            CALLBACK_DATA(url);
            break;
          default:
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
            if unlikely(CURRENT_STATE() == s_dead) {
              SET_ERRNO(HPE_INVALID_URL);
              goto error;
            }

            switch (CURRENT_STATE()) {
              case s_req_path:
              case s_req_query_string:
              case s_req_fragment:
              {
                /* In these states every further URL character keeps the state
                 * as it is, so take the whole run at once. Each byte still
                 * counts against the header size, and the run stops short of
                 * the limit so that the byte which crosses it is handled (and
                 * reported) by the loop above. */
                const char* q = p + 1;
                size_t n = (size_t) ((data + len) - q);
                const size_t room = HTTP_MAX_HEADER_SIZE - parser->nread;

                if (n > room) n = room;
                q = skip_url_chars(q, q + n);
                parser->nread += (uint32_t) (q - (p + 1));
                p = q - 1;
                break;
              }
              default:
                break;
            }
        }
        break;
      }

      case s_req_http_start:
        switch (ch) {
          case 'H':
            /* The usual end of a request line, "HTTP/d.d" and its CRLF, in one
             * step: the same fields, state and header-size count as the
             * states below leave. Anything else takes the slow path. */
            if ((data + len) - p >= 10 &&
                parser->nread + 9 <= HTTP_MAX_HEADER_SIZE &&
                memcmp(p, "HTTP/", 5) == 0 && p[5] >= '1' && p[5] <= '9' &&
                p[6] == '.' && IS_NUM(p[7]) && p[8] == CR && p[9] == LF &&
                (lenient || KNOWN_VERSION(p[5] - '0', p[7] - '0'))) {
              parser->http_major = (unsigned short) (p[5] - '0');
              parser->http_minor = (unsigned short) (p[7] - '0');
              parser->nread += 9;
              p += 9;
              UPDATE_STATE(s_header_field_start);
              NEXTCHAR_COUNTED();
              goto header_field_start;
            }
            UPDATE_STATE(s_req_http_H);
            break;
          case ' ':
            break;
          default:
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
        }
        break;

      case s_req_http_H:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_req_http_HT);
        NEXTHEADERCHAR();

      case s_req_http_HT:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_req_http_HTT);
        NEXTHEADERCHAR();

      case s_req_http_HTT:
        STRICT_CHECK(ch != 'P');
        UPDATE_STATE(s_req_http_HTTP);
        NEXTHEADERCHAR();

      case s_req_http_HTTP:
        STRICT_CHECK(ch != '/');
        UPDATE_STATE(s_req_first_http_major);
        break;

      /* first digit of major HTTP version */
      case s_req_first_http_major:
        if unlikely(ch < '1' || ch > '9') {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major = ch - '0';
        UPDATE_STATE(s_req_http_major);
        break;

      /* major HTTP version or dot */
      case s_req_http_major:
      {
        if (ch == '.') {
          UPDATE_STATE(s_req_first_http_minor);
          break;
        }

        /* Unless lenient: one digit (RFC 9112: HTTP/DIGIT.DIGIT) */
        if unlikely(!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if unlikely(parser->http_major > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      /* first digit of minor HTTP version */
      case s_req_first_http_minor:
        if unlikely(!IS_NUM(ch)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor = ch - '0';
        /* Unless lenient: the version is complete, and must be a known one */
        if (!lenient && !VERSION_KNOWN(parser)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }
        UPDATE_STATE(s_req_http_minor);
        break;

      /* minor HTTP version or end of request line */
      case s_req_http_minor:
      {
        if (ch == CR) {
          UPDATE_STATE(s_req_line_almost_done);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_field_start);
          break;
        }

        /* XXX allow spaces after digit? */

        if unlikely(!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if unlikely(parser->http_minor > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      /* end of request line */
      case s_req_line_almost_done:
      {
        if unlikely(ch != LF) {
          SET_ERRNO(HPE_LF_EXPECTED);
          goto error;
        }

        UPDATE_STATE(s_header_field_start);
        break;
      }

      header_field_start:
      case s_header_field_start:
      {
        if (ch == CR) {
          UPDATE_STATE(s_headers_almost_done);
          NEXTCHAR_COUNTED();
          goto headers_almost_done;
        }

        if (ch == LF) {
          /* they might be just sending \n instead of \r\n so this would be
           * the second \n to denote the end of headers*/
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_headers_almost_done);
          goto headers_almost_done;
        }

        c = TOKEN(ch);

        if unlikely(!c) {
          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
          goto error;
        }

        MARK(header_field);

        parser->index = 0;
        UPDATE_STATE(s_header_field);

        switch (c) {
          case 'c':
            parser->header_state = h_C;
            break;

          case 'p':
            parser->header_state = h_matching_proxy_connection;
            break;

          case 't':
            parser->header_state = h_matching_transfer_encoding;
            break;

          case 'u':
            parser->header_state = h_matching_upgrade;
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        NEXTHEADERCHAR();
      }

      case s_header_field:
      {
        const char* start = p;
header_field_begin:
        if ( parser->header_state == h_general ) {
          for (; p != data + len; p++) {
            ch = *p;
            c = TOKEN(ch);

            if (!c)
              break;
          }
        } else {
          for (; p != data + len; p++) {
            ch = *p;
            c = TOKEN(ch);

            if (!c)
              break;

            /* One step of matching a special header name: h_C to h_matching_upgrade
             * compare the byte with the name at parser->index (a table, not a switch:
             * twelve cases make a chain of compares on AArch64, where a jump table needs
             * thirteen), h_connection to h_upgrade take only spaces after the name. */
            const unsigned hs = parser->header_state;
            if (likely(hs - (unsigned) h_C <= (unsigned) (h_matching_upgrade - h_C))) {
              const struct name_matcher &m = name_matchers[hs - h_C];
              parser->index++;
              if (c == m.name[parser->index]) {
                if (parser->index == m.last) {
                  parser->header_state = m.matched;
                }
              } else {
                /* h_CON forks: "con" + 'n' is connection, + 't' content-length */
                parser->header_state = hs == (unsigned) h_CON && c == 't' ? h_matching_content_length : h_general;
              }
            } else if (hs == h_general) {
              --p;
              goto header_field_begin;
            } else {
              assert(hs >= (unsigned) h_connection && hs <= (unsigned) h_upgrade);
              if (ch != ' ') parser->header_state = h_general;
            }
          }
        }
        COUNT_HEADER_SIZE(p - start);

        if (p == data + len) {
          --p;
          break;
        }

        if (ch == ':') {
          UPDATE_STATE(s_header_value_discard_ws);
          CALLBACK_DATA(header_field);
          NEXTCHAR_COUNTED();
          goto header_value_discard_ws;
        }

        SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
        goto error;
      }

      header_value_discard_ws:
      case s_header_value_discard_ws:
        if (ch == ' ' || ch == '\t') {
          NEXTCHAR_COUNTED();
          goto header_value_discard_ws;
        }

        if (ch == CR) {
          UPDATE_STATE(s_header_value_discard_ws_almost_done);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_value_discard_lws);
          break;
        }

        /* FALLTHROUGH */

      case s_header_value_start:
      {
        /* Unless lenient, every byte of a value is checked, the first one too */
        if (!lenient && !header_char.ok[(unsigned char) ch]) {
          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
          goto error;
        }

        MARK(header_value);

        UPDATE_STATE(s_header_value);
        parser->index = 0;

        c = LOWER(ch);

        switch (parser->header_state) {
          case h_upgrade:
            parser->flags |= F_UPGRADE;
            parser->header_state = h_general;
            break;

          case h_transfer_encoding:
            parser->extra_flags |= F_TRANSFER_ENCODING >> 8;
            /* looking for 'Transfer-Encoding: chunked' */
            if ('c' == c) {
              parser->header_state = h_matching_transfer_encoding_chunked;
            } else {
              parser->header_state = lenient ? h_general : h_transfer_encoding_other;
            }
            break;

          case h_content_length:
            /* Unless lenient: no Content-Length in a trailer section, where it
             * cannot frame the message (RFC 9110 section 6.5.1) */
            if unlikely(!IS_NUM(ch) || (!lenient && (parser->flags & F_TRAILING))) {
              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
              goto error;
            }

            if (parser->flags & F_CONTENTLENGTH) {
              SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);
              goto error;
            }

            parser->flags |= F_CONTENTLENGTH;
            parser->content_length = ch - '0';
            break;

          case h_connection:
            /* looking for 'Connection: keep-alive' */
            if (c == 'k') {
              parser->header_state = h_matching_connection_keep_alive;
            /* looking for 'Connection: close' */
            } else if (c == 'c') {
              parser->header_state = h_matching_connection_close;
            } else if (c == 'u') {
              parser->header_state = h_matching_connection_upgrade;
            } else {
              parser->header_state = h_matching_connection_token;
            }
            break;

          /* Multi-value `Connection` header */
          case h_matching_connection_token_start:
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        NEXTCHAR_COUNTED();
        /* FALLTHROUGH */
      }

      case s_header_value:
      {
        const char* start = p;
        enum header_states h_state = (enum header_states) parser->header_state;
        for (; p != data + len; p++) {
          ch = *p;
          if (ch == CR) {
            UPDATE_STATE(s_header_almost_done);
            parser->header_state = h_state;
            CALLBACK_DATA(header_value);
            break;
          }

          if (ch == LF) {
            if (!lenient) {
              parser->header_state = h_state;
              SET_ERRNO(HPE_CR_EXPECTED);
              goto error;
            }
            UPDATE_STATE(s_header_almost_done);
            COUNT_HEADER_SIZE(p - start);
            parser->header_state = h_state;
            CALLBACK_DATA_NOADVANCE(header_value);
            REEXECUTE();
          }

          if (!lenient && !header_char.ok[(unsigned char) ch]) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }

          c = LOWER(ch);

          switch (h_state) {
            case h_general:
            case h_transfer_encoding_other:
            {
              /* Unless lenient the run also stops at a byte a value may not
               * hold, which the check above then rejects. */
              p = lenient ? find_crlf(p, data, len) : find_value_end(p, data, len);
              --p;

              break;
            }

            case h_connection:
            case h_transfer_encoding:
              assert(0 && "Shouldn't get here.");
              break;

            case h_content_length:
            {
              uint64_t t;

              if (ch == ' ') {
                /* Unless lenient, only spaces may follow the digits
                 * (`Content-Length: 4 2` is not 42) */
                if (!lenient) h_state = h_content_length_ws;
                break;
              }

              if unlikely(!IS_NUM(ch)) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                parser->header_state = h_state;
                goto error;
              }

              t = parser->content_length;
              t *= 10;
              t += ch - '0';

              /* Overflow? Test against a conservative limit for simplicity. */
              if unlikely((ULLONG_MAX - 10) / 10 < parser->content_length) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                parser->header_state = h_state;
                goto error;
              }

              parser->content_length = t;
              break;
            }

            case h_content_length_ws:
              if (ch == ' ') break;
              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
              parser->header_state = h_state;
              goto error;

            /* Transfer-Encoding: chunked */
            case h_matching_transfer_encoding_chunked:
              parser->index++;
              if (parser->index > sizeof(CHUNKED)-1
                  || c != CHUNKED[parser->index]) {
                h_state = lenient ? h_general : h_transfer_encoding_other;
              } else if (parser->index == sizeof(CHUNKED)-2) {
                h_state = h_transfer_encoding_chunked;
              }
              break;

            case h_matching_connection_token_start:
              /* looking for 'Connection: keep-alive' */
              if (c == 'k') {
                h_state = h_matching_connection_keep_alive;
              /* looking for 'Connection: close' */
              } else if (c == 'c') {
                h_state = h_matching_connection_close;
              } else if (c == 'u') {
                h_state = h_matching_connection_upgrade;
              } else if (STRICT_TOKEN(c)) {
                h_state = h_matching_connection_token;
              } else if (c == ' ' || c == '\t') {
                /* Skip lws */
              } else {
                h_state = h_general;
              }
              break;

            /* looking for 'Connection: keep-alive' */
            case h_matching_connection_keep_alive:
              parser->index++;
              if (parser->index > sizeof(KEEP_ALIVE)-1
                  || c != KEEP_ALIVE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(KEEP_ALIVE)-2) {
                h_state = h_connection_keep_alive;
              }
              break;

            /* looking for 'Connection: close' */
            case h_matching_connection_close:
              parser->index++;
              if (parser->index > sizeof(CLOSE)-1 || c != CLOSE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(CLOSE)-2) {
                h_state = h_connection_close;
              }
              break;

            /* looking for 'Connection: upgrade' */
            case h_matching_connection_upgrade:
              parser->index++;
              if (parser->index > sizeof(UPGRADE) - 1 ||
                  c != UPGRADE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(UPGRADE)-2) {
                h_state = h_connection_upgrade;
              }
              break;

            case h_matching_connection_token:
              if (ch == ',') {
                h_state = h_matching_connection_token_start;
                parser->index = 0;
              }
              break;

            case h_transfer_encoding_chunked:
              if (ch != ' ') h_state = lenient ? h_general : h_transfer_encoding_other;
              break;

            case h_connection_keep_alive:
            case h_connection_close:
            case h_connection_upgrade:
              if (ch == ',') {
                if (h_state == h_connection_keep_alive) {
                  parser->flags |= F_CONNECTION_KEEP_ALIVE;
                } else if (h_state == h_connection_close) {
                  parser->flags |= F_CONNECTION_CLOSE;
                } else if (h_state == h_connection_upgrade) {
                  parser->flags |= F_CONNECTION_UPGRADE;
                }
                h_state = h_matching_connection_token_start;
                parser->index = 0;
              } else if (ch != ' ') {
                h_state = h_matching_connection_token;
              }
              break;

            default:
              UPDATE_STATE(s_header_value);
              h_state = h_general;
              break;
          }
        }
        parser->header_state = h_state;

        COUNT_HEADER_SIZE(p - start);

        if (p == data + len) {
          --p;
        } else if (CURRENT_STATE() == s_header_almost_done &&
                   (data + len) - p >= 3 &&
                   parser->nread + 2 <= HTTP_MAX_HEADER_SIZE &&
                   p[1] == LF) {
          /* The value ended at a CR (p) that is followed by LF and one more
           * byte: take both now and let s_header_value_lws look at that byte,
           * which is what s_header_almost_done and the next pass would do,
           * with the same header-size count. */
          parser->nread += 2;
          p += 2;
          ch = *p;
          UPDATE_STATE(s_header_value_lws);
          goto header_value_lws;
        }
        break;
      }

      case s_header_almost_done:
      {
        if unlikely(ch != LF) {
          SET_ERRNO(HPE_LF_EXPECTED);
          goto error;
        }

        UPDATE_STATE(s_header_value_lws);
        break;
      }

      header_value_lws:
      case s_header_value_lws:
      {
        if (ch == ' ' || ch == '\t') {
          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */
          if (!lenient) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }
          UPDATE_STATE(s_header_value_start);
          REEXECUTE();
        }

        /* finished the header */
        switch (parser->header_state) {
          case h_connection_keep_alive:
            parser->flags |= F_CONNECTION_KEEP_ALIVE;
            break;
          case h_connection_close:
            parser->flags |= F_CONNECTION_CLOSE;
            break;
          case h_transfer_encoding_chunked:
            /* Unless lenient, a request is chunked once and last: a second
             * Transfer-Encoding header would apply a coding after it. */
            if (!lenient && parser->type == HTTP_REQUEST && (parser->flags & F_CHUNKED)) {
              SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
              goto error;
            }
            parser->flags |= F_CHUNKED;
            break;
          case h_matching_transfer_encoding_chunked:
          case h_transfer_encoding_other:
            /* Unless lenient, a request's Transfer-Encoding is "chunked" and
             * nothing else: this parser decodes no other coding, and the body's
             * length would be unknown (RFC 9112 section 6.3). */
            if (!lenient && (parser->type == HTTP_REQUEST || (parser->flags & F_CHUNKED))) {
              /* nor, in a response, is there a coding after chunked: chunked
               * is the last one (RFC 9112 section 6.1) */
              SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
              goto error;
            }
            break;
          case h_connection_upgrade:
            parser->flags |= F_CONNECTION_UPGRADE;
            break;
          default:
            break;
        }

        UPDATE_STATE(s_header_field_start);
        goto header_field_start;
      }

      case s_header_value_discard_ws_almost_done:
      {
        STRICT_CHECK(ch != LF);
        UPDATE_STATE(s_header_value_discard_lws);
        break;
      }

      case s_header_value_discard_lws:
      {
        if (ch == ' ' || ch == '\t') {
          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */
          if (!lenient) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }
          UPDATE_STATE(s_header_value_discard_ws);
          break;
        } else {
          switch (parser->header_state) {
            case h_content_length:
              /* Unless lenient, an empty Content-Length is an error */
              if (!lenient) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                goto error;
              }
              break;
            case h_transfer_encoding:
              /* Unless lenient, so is an empty Transfer-Encoding */
              if (!lenient) {
                SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
                goto error;
              }
              break;
            case h_connection_keep_alive:
              parser->flags |= F_CONNECTION_KEEP_ALIVE;
              break;
            case h_connection_close:
              parser->flags |= F_CONNECTION_CLOSE;
              break;
            case h_connection_upgrade:
              parser->flags |= F_CONNECTION_UPGRADE;
              break;
            case h_transfer_encoding_chunked:
              parser->flags |= F_CHUNKED;
              break;
            default:
              break;
          }

          /* header value was empty */
          MARK(header_value);
          UPDATE_STATE(s_header_field_start);
          CALLBACK_DATA_NOADVANCE(header_value);
          REEXECUTE();
        }
      }

      headers_almost_done:
      case s_headers_almost_done:
      {
        STRICT_CHECK(ch != LF);

        if (parser->flags & F_TRAILING) {
          /* End of a chunked request */
          UPDATE_STATE(s_message_done);
          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);
          goto message_done;
        }

        /* Cannot use chunked encoding and a content-length header together
           per the HTTP specification. Unless lenient, nor any other
           Transfer-Encoding: it overrides Content-Length, and a response read
           by the length would leave the rest of its body to be read as the
           next response (RFC 9112 section 6.3; upstream 7d5c99d, llhttp). */
        if ((parser->flags & F_CONTENTLENGTH) &&
            ((parser->flags & F_CHUNKED) ||
             (!lenient && (parser->extra_flags & (F_TRANSFER_ENCODING >> 8))))) {
          SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);
          goto error;
        }

        UPDATE_STATE(s_headers_done);

        /* Set this here so that on_headers_complete() callbacks can see it */
        parser->upgrade =
          ((parser->flags & (F_UPGRADE | F_CONNECTION_UPGRADE)) ==
           (F_UPGRADE | F_CONNECTION_UPGRADE) ||
           parser->method == HTTP_CONNECT);
        /* Unless lenient: a response switches protocols only with a 101; in
         * any other, Upgrade announces what the server supports (RFC 9110
         * section 7.8) */
        if (!lenient && parser->type == HTTP_RESPONSE && parser->status_code != 101) {
          parser->upgrade = 0;
        }

        /* Here we call the headers_complete callback. This is somewhat
         * different than other callbacks because if the user returns 1, we
         * will interpret that as saying that this message has no body. This
         * is needed for the annoying case of recieving a response to a HEAD
         * request.
         *
         * We'd like to use CALLBACK_NOTIFY_NOADVANCE() here but we cannot, so
         * we have to simulate it by handling a change in errno below.
         */
        if (settings->on_headers_complete) {
          switch (settings->on_headers_complete(parser)) {
            case 0:
              break;

            case 2:
              parser->upgrade = 1;

            case 1:
              parser->flags |= F_SKIPBODY;
              break;

            default:
              SET_ERRNO(HPE_CB_headers_complete);
              RETURN(p - data); /* Error */
          }
        }

        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
          RETURN(p - data);
        }

        goto headers_done;
      }

      headers_done:
      case s_headers_done:
      {
        int hasBody, skipBody;
        STRICT_CHECK(ch != LF);

        parser->nread = 0;

        /* Unless lenient: a 1xx, 204 or 304 response ends with its header
         * section, whatever framing it names (RFC 9112 section 6.3) */
        skipBody = (parser->flags & F_SKIPBODY) ||
          (!lenient && parser->type == HTTP_RESPONSE &&
           (parser->status_code / 100 == 1 || parser->status_code == 204 ||
            parser->status_code == 304));
        hasBody = parser->flags & F_CHUNKED ||
          (parser->content_length > 0 && parser->content_length != ULLONG_MAX);
        if (parser->upgrade && (parser->method == HTTP_CONNECT ||
                                skipBody || !hasBody)) {
          /* Exit, the rest of the message is in a different protocol. */
          UPDATE_STATE(NEW_MESSAGE());
          CALLBACK_NOTIFY(message_complete);
          RETURN((p - data) + 1);
        }

        if (skipBody) {
          UPDATE_STATE(NEW_MESSAGE());
          CALLBACK_NOTIFY(message_complete);
        } else if (parser->flags & F_CHUNKED) {
          /* chunked encoding - ignore Content-Length header */
          UPDATE_STATE(s_chunk_size_start);
        } else {
          if (parser->content_length == 0) {
            /* Content-Length header given but zero: Content-Length: 0\r\n */
            UPDATE_STATE(NEW_MESSAGE());
            CALLBACK_NOTIFY(message_complete);
          } else if (parser->content_length != ULLONG_MAX) {
            /* Content-Length header given and non-zero */
            UPDATE_STATE(s_body_identity);
          } else {
            if (!message_needs_eof(parser)) {
              /* Assume content-length 0 - read the next */
              UPDATE_STATE(NEW_MESSAGE());
              CALLBACK_NOTIFY(message_complete);
            } else {
              /* Read body until EOF */
              UPDATE_STATE(s_body_identity_eof);
            }
          }
        }

        if (CURRENT_STATE() == s_body_identity) {
          NEXTCHAR();
          goto body_identity;
        }

        break;
      }

      body_identity:
      case s_body_identity:
      {
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* The difference between advancing content_length and p is because
         * the latter will automaticaly advance on the next loop iteration.
         * Further, if content_length ends up at 0, we want to see the last
         * byte again for our message complete callback.
         */
        MARK(body);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          UPDATE_STATE(s_message_done);

          /* Mimic CALLBACK_DATA_NOADVANCE() but with one extra byte.
           *
           * The alternative to doing this is to wait for the next byte to
           * trigger the data callback, just as in every other case. The
           * problem with this is that this makes it difficult for the test
           * harness to distinguish between complete-on-EOF and
           * complete-on-length. It's not clear that this distinction is
           * important for applications, but let's keep it for now.
           */
          CALLBACK_DATA_(body, p - body_mark + 1, p - data);
          goto message_done;
        }

        break;
      }

      /* read until EOF */
      case s_body_identity_eof:
        MARK(body);
        p = data + len - 1;

        break;

      message_done:
      case s_message_done:
        UPDATE_STATE(NEW_MESSAGE());
        CALLBACK_NOTIFY(message_complete);
        if (parser->upgrade) {
          /* Exit, the rest of the message is in a different protocol. */
          RETURN((p - data) + 1);
        }
        break;

      chunk_size_start:
      case s_chunk_size_start:
      {
        assert(parser->nread == 1);
        assert(parser->flags & F_CHUNKED);

        unhex_val = unhex[(unsigned char)ch];
        if unlikely(unhex_val == -1) {
          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
          goto error;
        }

        parser->content_length = unhex_val;
        UPDATE_STATE(s_chunk_size);
        NEXTCHAR_COUNTED();
        /* FALLTHROUGH */
      }

      chunk_size:
      case s_chunk_size:
      {
        uint64_t t;

        assert(parser->flags & F_CHUNKED);

        if (ch == CR) {
          UPDATE_STATE(s_chunk_size_almost_done);
          NEXTCHAR_COUNTED();
          goto chunk_size_almost_done;
        }

        unhex_val = unhex[(unsigned char)ch];

        if (unhex_val == -1) {
          /* Unless lenient: only ';' (an extension) after the size */
          if (ch == ';' || (ch == ' ' && lenient)) {
            parser->index = lenient ? parser->index : CHUNK_EXT_START;
            UPDATE_STATE(s_chunk_parameters);
            break;
          }

          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
          goto error;
        }

        t = parser->content_length;
        t *= 16;
        t += unhex_val;

        /* Overflow? Test against a conservative limit for simplicity. */
        if unlikely((ULLONG_MAX - 16) / 16 < parser->content_length) {
          SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
          goto error;
        }

        parser->content_length = t;
        NEXTCHAR_COUNTED();
        goto chunk_size;
      }

      case s_chunk_parameters:
      {
        assert(parser->flags & F_CHUNKED);
        if (!lenient) {
          /* chunk-ext = *( ";" chunk-ext-name [ "=" ( token / quoted-string ) ] )
           * (RFC 9112 section 7.1.1, without whitespace), parser->index the place
           * in it: a malformed extension, or a bare LF or another control byte in
           * one, is an error. */
          if (!chunk_ext_char(parser, ch)) {
            SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
            goto error;
          }
          if (ch == CR) {
            UPDATE_STATE(s_chunk_size_almost_done);
          }
          break;
        }
        /* just ignore this shit. TODO check for overflow */
        if (ch == CR) {
          UPDATE_STATE(s_chunk_size_almost_done);
          break;
        }
        break;
      }

      chunk_size_almost_done:
      case s_chunk_size_almost_done:
      {
        assert(parser->flags & F_CHUNKED);
        STRICT_CHECK(ch != LF);

        parser->nread = 0;

        if (parser->content_length == 0) {
          parser->flags |= F_TRAILING;
          UPDATE_STATE(s_header_field_start);
          CALLBACK_NOTIFY(chunk_header);
          break;
        }

        UPDATE_STATE(s_chunk_data);
        CALLBACK_NOTIFY(chunk_header);
        NEXTCHAR();
        goto chunk_data;
      }

      chunk_data:
      case s_chunk_data:
      {
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* See the explanation in s_body_identity for why the content
         * length and data pointers are managed this way.
         */
        MARK(body);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length != 0) {
          break;
        }

        UPDATE_STATE(s_chunk_data_almost_done);
        NEXTCHAR();
        /* FALLTHROUGH */
      }

      case s_chunk_data_almost_done:
        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length == 0);
        STRICT_CHECK(ch != CR);
        UPDATE_STATE(s_chunk_data_done);
        CALLBACK_DATA(body);
        NEXTCHAR();
        /* FALLTHROUGH */

      case s_chunk_data_done:
        assert(parser->flags & F_CHUNKED);
        STRICT_CHECK(ch != LF);
        parser->nread = 0;
        UPDATE_STATE(s_chunk_size_start);
        CALLBACK_NOTIFY(chunk_complete);
        NEXTCHAR_COUNTED();
        goto chunk_size_start;

      default:
        assert(0 && "unhandled state");
        SET_ERRNO(HPE_INVALID_INTERNAL_STATE);
        goto error;
    }
  }

  /* Run callbacks for any marks that we have leftover after we ran our of
   * bytes. There should be at most one of these set, so it's OK to invoke
   * them in series (unset marks will not result in callbacks).
   *
   * We use the NOADVANCE() variety of callbacks here because 'p' has already
   * overflowed 'data' and this allows us to correct for the off-by-one that
   * we'd otherwise have (since CALLBACK_DATA() is meant to be run with a 'p'
   * value that's in-bounds).
   */

  assert(((header_field_mark ? 1 : 0) +
          (header_value_mark ? 1 : 0) +
          (url_mark ? 1 : 0)  +
          (body_mark ? 1 : 0) +
          (status_mark ? 1 : 0)) <= 1);

  CALLBACK_DATA_NOADVANCE(header_field);
  CALLBACK_DATA_NOADVANCE(header_value);
  CALLBACK_DATA_NOADVANCE(url);
  CALLBACK_DATA_NOADVANCE(body);
  CALLBACK_DATA_NOADVANCE(status);

  RETURN(len);

error:
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK) {
    SET_ERRNO(HPE_UNKNOWN);
  }

  RETURN(p - data);
}

size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len)
{
  return parser->lenient_http_headers ? execute<true>(parser, settings, data, len)
                                      : execute<false>(parser, settings, data, len);
}

