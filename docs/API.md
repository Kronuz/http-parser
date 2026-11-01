# http-parser API reference

The core entry points (full declarations in `http_parser.h`):

- **`http_parser_init(http_parser* p, enum http_parser_type t)`** — reset a parser
  for `HTTP_REQUEST`, `HTTP_RESPONSE`, or `HTTP_BOTH`. Preserves `p->data`.
- **`http_parser_settings_init(http_parser_settings* s)`** — zero the callback
  table; set the callbacks you want afterward.
- **`http_parser_execute(p, settings, data, len) -> size_t`** — feed `len` bytes;
  returns the number consumed and sets `p->http_errno` on error. Call it as many
  times as you have data.
- **`http_should_keep_alive(const http_parser* p) -> int`** — nonzero if the
  connection should stay open after this message (HTTP/1.1 default, or explicit
  keep-alive).
- **`http_method_str(enum http_method) -> const char*`** and
  **`http_status_str(enum http_status)`** — names for a method / status.
- **`http_errno_name(enum http_errno)`** / **`http_errno_description(...)`** — the
  `HPE_*` token name and a human description for an error.
- **`http_body_is_final(const http_parser* p) -> int`** — whether the current body
  chunk is the last one.
- **`http_parser_pause(http_parser* p, int paused)`** — pause / resume mid-parse.
- **`http_parser_parse_url(...)`** — a standalone URL splitter into
  scheme/host/port/path/query/fragment.

Read parser fields after `http_parser_execute()`: `method`, `http_major`,
`http_minor`, `status_code` (responses), `content_length` (remaining body bytes,
counts down to zero), `upgrade`, and `http_errno` (via the `HTTP_PARSER_ERRNO`
macro).

The callbacks return non-zero to abort the parse. `on_headers_complete` is the
one exception: returning `1` tells the parser not to expect a body (used for HEAD
responses), `2` that there is no body and no further messages (used for CONNECT).

## Strictness and `lenient_http_headers`

The parser rejects what request smuggling relies on: a line ended by a bare LF
(`HPE_CR_EXPECTED`), obs-fold and control bytes in a header value
(`HPE_INVALID_HEADER_TOKEN`), a request `Transfer-Encoding` other than `chunked`
alone (`HPE_INVALID_TRANSFER_ENCODING`), a `Content-Length` with spaces inside or empty
(`HPE_INVALID_CONTENT_LENGTH`), a malformed chunk size line (`HPE_INVALID_CHUNK_SIZE`)
and an HTTP version other than 0.9, 1.0, 1.1 or 2.0 (`HPE_INVALID_VERSION`). Set
`p->lenient_http_headers = 1` after `http_parser_init()` to accept them as http_parser
2.7.1 did (it also skips the header-value byte check, as before). Reject a request the
parser rejects; do not forward it.

## Callback rules

- The data callbacks (`on_url`, `on_header_field`, `on_header_value`, `on_body`)
  can fire more than once for one logical value, so append rather than assign.
- A header-field callback after a value callback means the previous pair is
  complete.
- `parser->data` is a free `void*` for your own context.
