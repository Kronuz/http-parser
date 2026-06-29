# Architecture

The internals of `http-parser`: how a single streaming state machine turns raw
HTTP bytes into a sequence of callbacks without buffering or allocating, and how
the pieces fit together. For usage see `README.md`; for the repo map and
invariants see `AGENTS.md`.

## Shape

Two headers and one compiled state machine:

```
  http_parser.h        declares the API (init, execute, settings, helpers) and the parser/settings structs
  http_parser_enums.h  the method / status / errno / state / header-state enums, built with enum.h's ENUM()
  http_parser.cc       the state machine: http_parser_execute() plus the helpers
  likely.h             self-contained likely()/unlikely() branch hints (vendored, no config.h)
```

`http_parser.h` defines the two structs a consumer touches: `http_parser` (the
parser state, mostly private bitfields plus the read-only `method`,
`http_major/minor`, `status_code`, `http_errno`, and a public `data` pointer) and
`http_parser_settings` (the table of callback function pointers). Everything else
is a free function operating on those.

## The streaming state machine

The whole parser is one big function, `http_parser_execute()`, built as a state
machine over an `enum state` (defined in `http_parser_enums.h`: `s_start_req`,
`s_req_method`, `s_req_path`, `s_header_field`, `s_body_identity`,
`s_chunk_size`, and dozens more). Each call walks the bytes you hand it, one at a
time, advancing the state and firing callbacks at the right boundaries. The
current state lives in the `http_parser` struct between calls, which is what makes
the parse independent of how the input was framed: a byte-at-a-time feed and a
single full-buffer feed drive the same transitions and produce the same
callbacks.

It is zero-copy. The data callbacks (`on_url`, `on_header_field`,
`on_header_value`, `on_body`) are handed a pointer into your buffer and a length;
the parser marks the start of a run (e.g. `url_mark = p`) and emits the slice when
the run ends or the buffer does. Because a run can straddle a buffer boundary, a
single logical value can be reported in several callbacks, so a consumer appends
rather than assigns.

## Callbacks and message flow

A request drives the callbacks in this order: `on_message_begin`, then `on_url`,
then alternating `on_header_field` / `on_header_value` for each header, then
`on_headers_complete`, then `on_body` (zero or more times), then
`on_message_complete`. Chunked bodies add `on_chunk_header` / `on_chunk_complete`
around each chunk. The notify callbacks (no data) return non-zero to abort;
`on_headers_complete` additionally uses its return value to signal "no body"
(`1`, for HEAD) or "no body and no more messages" (`2`, for CONNECT).

Bodies come in two forms the machine handles distinctly. A `Content-Length` body
is identity-encoded: `content_length` is loaded from the header and counted down
as body bytes are delivered, reaching zero at `on_message_complete` (so reading
`content_length` after a complete parse gives `0`, not the header value). A
`Transfer-Encoding: chunked` body loops through `s_chunk_size` (hex length) ->
`s_chunk_data` -> back, reassembling the chunks into a continuous `on_body`
stream and terminating on the zero-length chunk.

## The enums

`http_parser_enums.h` is where this copy diverges most visibly from a stock
parser. The status codes, request methods, errno values, and the internal state
and header-state enums are all defined through the `ENUM()` macro from the sibling
[enum-reflection](https://github.com/Kronuz/enum-reflection) library, rather than
plain C enums. Compiled as C++ (which is how this library builds), `ENUM()`
expands to a real enum plus reflective `constexpr` accessors, so the dependency is
load-bearing: it is what makes `"enum.h"` a required include, not just a path
fixup. The method map also carries Xapiand's extra verbs (`CHECK`, `COMMIT`,
`COPY`, `SEARCH`, `UPDATE`, `UPSERT`, and the rest) appended after the standard
HTTP set.

`http_method_str()`, `http_status_str()`, `http_errno_name()`, and
`http_errno_description()` are plain table lookups built from the same X-macro
maps (`HTTP_METHOD_MAP`, `HTTP_STATUS_MAP`, `HTTP_ERRNO_MAP`) that define the
enums, so the names and the values cannot drift apart. `http_errno_name()` returns
the `HPE_`-prefixed token name (e.g. `"HPE_INVALID_METHOD"`), since the table is
generated as `"HPE_" #n`.

## Errors and pausing

On malformed input the machine sets `parser->http_errno` to the matching `HPE_*`
value and stops; `http_parser_execute()` returns the number of bytes consumed
before the stop, which is short of the input length. A consumer checks
`HTTP_PARSER_ERRNO(parser)` after every call. The parser can also be paused
mid-stream with `http_parser_pause()`, which sets `HPE_PAUSED` so the next
`execute()` knows to resume rather than treat the stop as an error.

## Why this shape

The design choice that drives everything is "parse off the wire without owning
the buffer." A streaming state machine with callbacks means the caller decides
what to keep and where to put it, the parser never allocates, and a message can be
processed as it arrives instead of after it is fully buffered. That is the right
shape for a server reading from a socket in arbitrary-sized reads, which is what
Xapiand uses it for. The cost is the callback-and-append contract: values can
arrive in pieces, and the consumer has to stitch them. The library keeps that
contract identical to upstream Joyent/Node so the parser can be reasoned about
against the large body of existing knowledge about it.
