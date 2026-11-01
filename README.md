# http-parser

Part of [Kronuz C++ Libraries](https://github.com/Kronuz/cpp-libraries), a collection of small, reusable C++ libraries.

[![CI](https://github.com/Kronuz/http-parser/actions/workflows/ci.yml/badge.svg)](https://github.com/Kronuz/http-parser/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)

A streaming HTTP/1.0 and HTTP/1.1 parser for C++20: feed it bytes in whatever
chunks they arrive, and it calls you back with the method, URL, headers, and
body as slices of your own buffer. The Joyent/Node.js `http_parser`, with
reflective enums and Xapiand's extra verbs.

![http-parser: bytes in any framing drive a state machine that calls back with slices of your buffer](docs/http-parser.svg)

## ✨ Highlights

- **Streaming.** A request split across any number of calls parses the same as
  one buffer, byte by byte included.
- **Zero copy, zero allocation.** Callbacks receive pointers into your input.
- **Complete HTTP/1.x framing.** `Content-Length` and chunked bodies, keep-alive,
  upgrades, and a typed error code for malformed input.
- **Strict where smuggling lives.** Bare LF, obs-fold, control bytes in values, a
  request `Transfer-Encoding` other than `chunked`, malformed `Content-Length` and chunk
  lines are errors, as in llhttp, whose own conformance suite runs in CI;
  `lenient_http_headers = 1` restores http_parser 2.7.1's behavior.
- **Reflective enums.** Methods, statuses, and errors are
  [enum-reflection](https://github.com/Kronuz/enum-reflection) enums, so they
  print and parse by name.
- **More verbs.** `SEARCH`, `COMMIT`, `UPDATE`, and others alongside the standard
  methods.

## 📦 Installation

Requires a C++20 compiler and CMake 3.14 or newer; it fetches enum-reflection.
It compiles one source file, `http_parser.cc`. CI builds it on Linux (x86_64,
arm64), macOS (arm64, x86_64), and FreeBSD, plus ASan, UBSan, and TSan builds, a
build without the vector code, a non-strict build, and a nightly fuzz run; the tests
include llhttp's conformance suite (`test/conformance.cc`).

```cmake
include(FetchContent)
FetchContent_Declare(http_parser
  GIT_REPOSITORY https://github.com/Kronuz/http-parser.git
  GIT_TAG        main)
FetchContent_MakeAvailable(http_parser)

target_link_libraries(my_app PRIVATE http_parser::http_parser)
```

## 🚀 Quick start

```cpp
#include "http_parser.h"

#include <cstring>
#include <string>

int main() {
	std::string url;
	http_parser_settings settings;
	http_parser_settings_init(&settings);
	settings.on_url = [](http_parser* p, const char* at, size_t n) {
		static_cast<std::string*>(p->data)->append(at, n);   // may arrive in pieces
		return 0;
	};

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	parser.data = &url;

	const char* req = "GET /search?q=x HTTP/1.1\r\nHost: example.com\r\n\r\n";
	http_parser_execute(&parser, &settings, req, std::strlen(req));
	// parser.method == HTTP_GET, url == "/search?q=x", HTTP_PARSER_ERRNO(&parser) == HPE_OK
}
```

[`examples/demo.cc`](examples/demo.cc) parses a POST, re-parses it byte by byte,
and shows the error for a malformed request.

## 🎯 When to use it

- ✅ An HTTP/1.x server or client loop that reads from sockets in arbitrary
  chunks.
- ❌ HTTP/2 or HTTP/3: it parses HTTP/1.x only.
- ❌ A new project with no ties to this API: upstream Node.js has replaced
  `http_parser` with [llhttp](https://github.com/nodejs/llhttp).

## ⚡ Performance

The parse loop dispatches on one state per byte, so the parser takes everything it
can in larger steps: a run of URL characters, the end of a request line, the end
of a header value (16 bytes at a time with NEON or SSE2), and the next state of a
header line or a chunk frame without going back through the dispatch. The results,
callbacks and offsets are those of the byte-at-a-time parser; `test/diff.cc`,
`test/fuzz.cc` and `tools/mutants.py` hold it to that.

`bench/bench.cc` times each workload against the frozen byte-at-a-time parser and
llhttp 9.4.3 (ns per message, `-O3`, interleaved trials, quiet machine):

| Workload | M4 Pro | llhttp | i9-9980HK | llhttp |
|---|---:|---:|---:|---:|
| GET, 3 headers | 78 | 75 | 175 | 185 |
| GET, 14 headers (browser) | 275 | 258 | 620 | 617 |
| GET, 64 custom headers | 1033 | 1046 | 2525 | 2346 |
| POST, 1 KB body | 98 | 89 | 241 | 237 |
| Chunked body, 16 x 256 B | 217 | 183 | 428 | 454 |
| Request line only | 38 | 35 | 75 | 83 |
| 125-byte URL | 65 | 75 | 130 | 147 |

Apple M4 Pro, Apple clang 17; Intel i9-9980HK, Apple clang 17, no `-march`.
Reproduce with:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DHTTP_PARSER_BUILD_BENCH=ON && cmake --build build
build/http_parser_bench 15 30
```

## 📚 Documentation

- [docs/API.md](docs/API.md): the entry points, the parser fields, and the
  callback rules.
- [ARCHITECTURE.md](ARCHITECTURE.md): the state machine and Xapiand's additions.
- [AGENTS.md](AGENTS.md): repository map, invariants, and traps.

## 🛠️ Building and testing

```sh
cmake -B build && cmake --build build && ctest --test-dir build
./build/http_parser_demo
```

## 🤝 Contributing

Issues and pull requests are welcome. Read [AGENTS.md](AGENTS.md) first. CI must
pass on every platform.

## 📄 License

MIT. Based on NGINX's parser (Copyright Igor Sysoev), with changes Copyright
Joyent, Inc. and other Node contributors; Xapiand's additions Copyright (c)
2015-2019 Dubalu LLC. See [LICENSE](LICENSE).
