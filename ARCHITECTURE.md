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

## Bulk scans and direct transitions

The main loop pays for every byte it dispatches: the loop head (load, header-size
count) and the indirect jump through the state table cost about a nanosecond a byte,
and a URL byte through `parse_url_char()` about three. Most of a message is bytes
that need no dispatch, so the paths below take a run of bytes, or the next state,
in one step. Each does exactly what the byte-at-a-time states do for the same
bytes: the same parser fields, the same state, the same callbacks and the same
`nread` (the header-size count). `test/diff.cc` holds them to that.

Runs of bytes:

- **URL run** (`skip_url_chars`). In `s_req_path`, `s_req_query_string` and
  `s_req_fragment` every further URL character leaves the state unchanged, so the
  loop takes the run at once: 16 bytes at a time with NEON or SSE2 in strict mode
  (0x21..0x7e except `#` and `?`), the `IS_URL_CHAR` table otherwise.
- **End of the request line.** At the `H` after the URL, a complete `HTTP/d.d`
  followed by CRLF sets `http_major`, `http_minor` and the state directly.
- **End of a header value.** `find_value_end` finds the first CR, LF or other byte a
  value may not hold (a control byte other than HT, or DEL) in one pass, 16 bytes at a
  time, and the loop rejects the latter; with `lenient_http_headers` set, `find_crlf`
  finds the first CR or LF only, as 2.7.1 did. Neither is inlined (inlined, the vector
  code costs the state machine's registers and slows every other state). After a CR
  that is followed by LF and one more byte, the loop takes the LF and that byte together.

Direct transitions. Where one state always follows another, the code steps to the
next byte, counts it as the loop head would, and jumps to the next state's label
(`NEXTCHAR_COUNTED()` and `goto`; `NEXTCHAR()` for the body states, whose bytes
`nread` does not count) instead of returning to the loop and its dispatch. The
state is set before every callback and every jump, so a callback that fails or
pauses leaves the same state and return value. A header line runs from its first
byte to the next line's first byte this way (name, `:`, blanks, first value byte,
value, CR LF, `s_header_value_lws`, `s_header_field_start`), the end of the headers
runs into the first body byte, and a chunk frame (size digits, CR LF, data, CR LF)
runs into the next one. The rare paths (folded values, chunk extensions, a buffer
that ends mid-sequence) leave through `break` into the loop.

Four rules hold every one of them. A run never reaches past the point where `nread`
would exceed `HTTP_MAX_HEADER_SIZE`: it stops short, and the byte-at-a-time path
reports the overflow at the same byte. A vector loop reads only whole 16-byte blocks
inside the span it was given (a byte loop takes the tail), so no read leaves the
caller's buffer. A fast path that does not apply falls back to the states, so
malformed input is reported where it always is. And a jump always goes through the
target state's own code, never a copy of it, so a rule added to a state applies on
every path into it. `HTTP_PARSER_NO_SIMD` turns the vector code off.

## Strictness

What the parser accepts follows llhttp's default, the reference its conformance test
(`test/conformance.cc`, llhttp's own suite) holds it to, on the points that decide
where a message ends: every line ends in CRLF, a header value holds no control byte
but HT and no obs-fold, a request's `Transfer-Encoding` is `chunked` alone and once,
`Content-Length` is digits (spaces after them only), a chunk size is followed by CRLF
or well-formed extensions, and the version is HTTP/0.9, 1.0, 1.1 or 2.0. Each rule is
one check in the state that sees the byte, under `!lenient`; two header states
(`h_transfer_encoding_other`, `h_content_length_ws`) carry a header's kind to the end of
its line, and `parser->index` the place in a chunk extension. With
`lenient_http_headers` set the checks are off and the parser is 2.7.1's again, which
`test/diff.cc` checks against the frozen copy.

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
