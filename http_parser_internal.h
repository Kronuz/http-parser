/* Includes, SIMD selection and helpers shared by the http_parser sources (license: see http_parser.cc). */
#pragma once

#include "http_parser.h"

#include <assert.h>          // for assert
#include <stddef.h>          // for NULL, size_t
#include <ctype.h>
#include <string.h>          // for memset, memcmp
#include <limits.h>          // for ULLONG_MAX

#include "likely.h"          // for likely, unlikely

/* The bulk scans below (the URL run and the end of a header value) take 16
 * bytes at a time with NEON or SSE2, both baseline on arm64 and x86-64, and
 * never read outside the span they are given. Define HTTP_PARSER_NO_SIMD to
 * use the byte loops everywhere. */
#if !defined(HTTP_PARSER_NO_SIMD) && defined(__ARM_NEON) && !defined(__ARM_BIG_ENDIAN)
# include <arm_neon.h>
# define HTTP_PARSER_NEON 1
#elif !defined(HTTP_PARSER_NO_SIMD) && defined(__SSE2__)
# include <emmintrin.h>
# define HTTP_PARSER_SSE2 1
#endif

#if defined(__GNUC__) || defined(__clang__)
# define HTTP_PARSER_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
# define HTTP_PARSER_NOINLINE __declspec(noinline)
#else
# define HTTP_PARSER_NOINLINE
#endif


#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef BIT_AT
# define BIT_AT(a, i)                                                \
  (!!((unsigned int) (a)[(unsigned int) (i) >> 3] &                  \
   (1 << ((unsigned int) (i) & 7))))
#endif

#ifndef ELEM_AT
# define ELEM_AT(a, i, v) ((unsigned int) (i) < ARRAY_SIZE(a) ? (a)[(i)] : (v))
#endif

#define SET_ERRNO(e)                                                 \
do {                                                                 \
  parser->http_errno = (e);                                          \
} while(0)


static const char *method_strings[] =
  {
#define XX(num, name, string) #string,
  HTTP_METHOD_MAP(XX)
#undef XX
  };


#if defined(__GNUC__) || defined(__clang__)
# define HTTP_PARSER_ALWAYS_INLINE inline __attribute__((always_inline))
#elif defined(_MSC_VER)
# define HTTP_PARSER_ALWAYS_INLINE __forceinline
#else
# define HTTP_PARSER_ALWAYS_INLINE inline
#endif

/* http_message_needs_eof() and http_should_keep_alive(), also inlined where the
 * loop starts the next message (NEW_MESSAGE()). */

/* Does the parser need to see an EOF to find the end of the message? */
static HTTP_PARSER_ALWAYS_INLINE int
message_needs_eof (const http_parser *parser)
{
  if (parser->type == HTTP_REQUEST) {
    return 0;
  }

  /* See RFC 2616 section 4.4 */
  if (parser->status_code / 100 == 1 || /* 1xx e.g. Continue */
      parser->status_code == 204 ||     /* No Content */
      parser->status_code == 304 ||     /* Not Modified */
      parser->flags & F_SKIPBODY) {     /* response to a HEAD request */
    return 0;
  }

  if ((parser->flags & F_CHUNKED) || parser->content_length != ULLONG_MAX) {
    return 0;
  }

  return 1;
}

static HTTP_PARSER_ALWAYS_INLINE int
should_keep_alive (const http_parser *parser)
{
  if (parser->http_major > 0 && parser->http_minor > 0) {
    /* HTTP/1.1 */
    if (parser->flags & F_CONNECTION_CLOSE) {
      return 0;
    }
  } else {
    /* HTTP/1.0 or earlier */
    if (!(parser->flags & F_CONNECTION_KEEP_ALIVE)) {
      return 0;
    }
    /* Unless lenient: Transfer-Encoding before HTTP/1.1 is faulty framing, and the
     * connection closes after the message (RFC 9112 section 6.1) */
    if (!parser->lenient_http_headers && (parser->flags & F_CHUNKED) &&
        parser->http_major < 2) {
      return 0;
    }
  }

  return !message_needs_eof(parser);
}
