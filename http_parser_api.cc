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


/* Public helpers: names and descriptions, init, pause, version (the parse loop is http_parser.cc, URLs http_parser_url.cc). */

#include "http_parser_internal.h"

/* Map errno values to strings for human-readable output */
#define HTTP_STRERROR_GEN(n, s) { "HPE_" #n, s },
static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  HTTP_ERRNO_MAP(HTTP_STRERROR_GEN)
};
#undef HTTP_STRERROR_GEN


int
http_message_needs_eof (const http_parser *parser)
{
  return message_needs_eof(parser);
}


int
http_should_keep_alive (const http_parser *parser)
{
  return should_keep_alive(parser);
}


const char *
http_status_str (enum http_status s)
{
  switch (s) {
#define XX(num, name, string) case num : return #string;
      HTTP_STATUS_MAP(XX)
#undef XX
      default: return "<unknown>";
  }
}


const char *
http_method_str (enum http_method m)
{
  return ELEM_AT(method_strings, m, "<unknown>");
}


void
http_parser_init (http_parser *parser, enum http_parser_type t)
{
  void *data = parser->data; /* preserve application data */
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));
  parser->http_errno = HPE_OK;
}

void
http_parser_settings_init(http_parser_settings *settings)
{
  memset(settings, 0, sizeof(*settings));
}

const char *
http_errno_name(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].name;
}

const char *
http_errno_description(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].description;
}

void
http_parser_url_init(struct http_parser_url *u) {
  memset(u, 0, sizeof(*u));
}

void
http_parser_pause(http_parser *parser, int paused) {
  /* Users should only be pausing/unpausing a parser that is not in an error
   * state. In non-debug builds, there's not much that we can do about this
   * other than ignore it.
   */
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK ||
      HTTP_PARSER_ERRNO(parser) == HPE_PAUSED) {
    SET_ERRNO((paused) ? HPE_PAUSED : HPE_OK);
  } else {
    assert(0 && "Attempting to pause parser in error state");
  }
}

int
http_body_is_final(const struct http_parser *parser) {
    return parser->state == s_message_done;
}

unsigned long
http_parser_version(void) {
  return HTTP_PARSER_VERSION_MAJOR * 0x10000 |
         HTTP_PARSER_VERSION_MINOR * 0x00100 |
         HTTP_PARSER_VERSION_PATCH * 0x00001;
}
