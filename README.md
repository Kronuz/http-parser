# http-parser

A streaming HTTP/1.x request and response parser for C++20. Extracted from
[Xapiand](https://github.com/Kronuz/Xapiand).

## What it is

The Joyent/Node.js `http_parser`: a callback-driven, zero-copy state machine for
HTTP/1.0 and HTTP/1.1. You feed it raw bytes, as many or as few as you have, and
it calls back into your code as it recognizes the request line (method and URL),
each header field and value, the body, and the message boundaries. It never
buffers the message or allocates for you; the data callbacks hand you slices of
your own input buffer.

It is streaming by design. A request can arrive split across any number of
`http_parser_execute()` calls (one byte at a time, or in TCP-sized chunks) and
the parser keeps its state across calls, so the parse is identical regardless of
how the bytes were framed on the wire. It handles `Content-Length` bodies,
`Transfer-Encoding: chunked` bodies, keep-alive, upgrades, and reports a typed
`http_errno` when the input is malformed.

This copy carries Xapiand's additions on top of upstream: the enums are defined
through the sibling [enum-reflection](https://github.com/Kronuz/enum-reflection)
library (so the method, status, and errno enums are reflective), and the method
table is extended with Xapiand's verbs (`SEARCH`, `COMMIT`, `UPDATE`, and so on)
alongside the standard set.

## Install

This is not header-only. It ships a compiled translation unit, `http_parser.cc`
(the ~2.4k-line state machine), plus the headers `http_parser.h` and
`http_parser_enums.h`. You build and link the `.cc`; the headers alone only
declare the API and the enums. It requires C++20.

It has one dependency:
[enum-reflection](https://github.com/Kronuz/enum-reflection), the sibling header
that provides the `ENUM()` macro the enums are built with. CMake pulls it in for
you.

With CMake `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(
  http_parser
  GIT_REPOSITORY https://github.com/Kronuz/http-parser.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(http_parser)

target_link_libraries(your_target PRIVATE http_parser::http_parser)
```

`CMakeLists.txt` requests `cxx_std_20` `PUBLIC` and links `enum-reflection`
`PUBLIC`, so `"enum.h"` resolves on the include path with no extra wiring on your
side. Then:

```cpp
#include "http_parser.h"
```

The headers keep their original filenames, so a codebase that already
`#include "http_parser.h"` just needs this repo on its include path. The
implementation file takes a `.cc` extension (upstream ships it as `.c`) so the
C++ compile is first-class rather than relying on the deprecated "compile a `.c`
as C++" path.

## Usage

You wire up a `http_parser_settings` with the callbacks you care about, init a
`http_parser`, and push bytes through `http_parser_execute()`. The callbacks see
slices of your buffer; you copy out what you want to keep.

```cpp
#include "http_parser.h"
#include <cstring>
#include <string>

std::string url, body;

int on_url(http_parser* p, const char* at, size_t n)  { url.append(at, n);  return 0; }
int on_body(http_parser* p, const char* at, size_t n) { body.append(at, n); return 0; }

http_parser parser;
http_parser_init(&parser, HTTP_REQUEST);   // or HTTP_RESPONSE / HTTP_BOTH

http_parser_settings settings;
http_parser_settings_init(&settings);
settings.on_url  = on_url;
settings.on_body = on_body;

const char* req =
    "POST /submit HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello";

size_t parsed = http_parser_execute(&parser, &settings, req, std::strlen(req));

// After a clean parse:
//   parser.method        == HTTP_POST
//   url                  == "/submit"
//   body                 == "hello"
//   parser.http_major/minor == 1 / 1
//   http_should_keep_alive(&parser) != 0
//   HTTP_PARSER_ERRNO(&parser) == HPE_OK
```

The data callbacks (`on_url`, `on_header_field`, `on_header_value`, `on_body`)
can fire more than once for a single logical value, so append rather than assign.
A header field callback after a value callback signals that the previous
field/value pair is complete and a new one is starting.

`parser->data` is a free `void*` you set to your own context (a connection
object, a collector struct) and read back inside the callbacks.

## API reference

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

## Build & test

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

The first configure fetches `enum-reflection` (and its transitive deps) over the
network. The test drives raw request bytes through the parser and checks the
parsed method, URL, headers, and body across a simple GET, a POST with a
Content-Length body, an incremental byte-by-byte feed (proving the streaming
state survives across calls), a two-buffer `Transfer-Encoding: chunked` body, a
malformed request (bad method -> `HPE_INVALID_METHOD`, parser halts short of the
input), and keep-alive for HTTP/1.1 vs HTTP/1.0. It prints
`all http-parser tests passed` and exits 0.

## Examples

[`examples/demo.cc`](examples/demo.cc) is a runnable tour. A top-level CMake build
produces it next to the test:

```sh
cmake -B build && cmake --build build && ./build/http_parser_demo
```

It parses a POST request and prints the method, URL, version, body, and
keep-alive flag from the callbacks; re-parses a request fed one byte at a time to
show the streaming parse is identical; and runs a malformed request to show the
reported `http_errno`.

## Provenance

Extracted from [Xapiand](https://github.com/Kronuz/Xapiand). `http_parser.h`,
`http_parser_enums.h`, and the implementation were copied from Xapiand's in-tree
copy of the Joyent/Node.js parser (which Xapiand had already adapted: the
`enum.h`-based enums, the extra request methods, the `std::format` support). The
standalone deltas on extraction are small and mechanical: the one local include
`"enum.h"` is resolved against the sibling
[enum-reflection](https://github.com/Kronuz/enum-reflection) library through
CMake, the implementation's `"likely.h"` include is satisfied by a self-contained
vendored copy (no `config.h` coupling), and the implementation file is renamed
`http_parser.c` -> `http_parser.cc` so the C++ build is first-class. No parser
logic was changed. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and
[AGENTS.md](AGENTS.md) for the repo map and invariants.

## License

MIT. The parser is based on NGINX (Copyright Igor Sysoev) with changes Copyright
Joyent, Inc. and other Node contributors; the Xapiand additions and the
extraction wiring are Copyright (c) 2015-2019 Dubalu LLC. See [LICENSE](LICENSE).
