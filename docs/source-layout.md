# Source layout

No source file is over 1,000 lines. `http_parser.h` is the include users name; the `.cc` files are
the library target's sources. The `.inc` files are not compiled alone: each is included at one
point of the file that names it, so the compiler sees the same translation unit as before. The
parse loop is a single function with `goto` between its states, so its states cannot be separate
functions; they are included inside it, which also keeps the inlining the loop relies on.

## Library

| File | Holds |
|---|---|
| `http_parser.h`, `http_parser_enums.h`, `likely.h` | The public API, its enums, `likely`/`unlikely`. |
| `http_parser.cc` | `http_parser_execute()` and the parse loop's frame: setup, the byte loop, the epilogue. |
| `http_parser_execute_response.inc` | Loop states for the response line (start, version, status code, reason). |
| `http_parser_execute_request.inc` | Loop states for the request line (method, URL, version). |
| `http_parser_execute_headers.inc` | Loop states for header fields and values and the end of the headers. |
| `http_parser_execute_body.inc` | Loop states for identity and chunked bodies and message completion. |
| `http_parser_macros.inc` | The loop's state, callback and byte-stepping macros. |
| `http_parser_tables.inc` | Header-name matchers, token and hex tables, the header character table, the chunk-extension grammar. |
| `http_parser_scan.inc` | The bulk scans (NEON/SSE2): end of line, end of header value, end of a URL run. |
| `http_parser_internal.h` | Includes, SIMD selection, small macros, `method_strings` and the inlined `message_needs_eof`/`should_keep_alive`. |
| `http_parser_chars.h` | Character classes, the URL character table and `parse_url_char()`. |
| `http_parser_api.cc` | `http_status_str`, `http_method_str`, `http_errno_*`, init, pause, version and the public wrappers. |
| `http_parser_url.cc` | `http_parser_parse_url()` and the host grammar. |

## Differential test

`test/diff.cc` holds `main()`; the rest is included inside its anonymous namespace.

| File | Holds |
|---|---|
| `test/diff.cc` | The file's overview, the sections of `main()`: corpus, prefixes, mutations, pauses, SIMD sweep, random messages. |
| `test/diff_harness.inc` | Snapshots, event recording, the driver, the comparison and the hardening-change rules. |
| `test/diff_corpus.inc` | The hand-written corpus and the 80 KB header-limit cases. |
| `test/diff_random.inc` | Random grammar-built messages and their mutations. |
| `test/diff_harden.inc` | The hardening sweep helper. |

`test/http_parser_old.cc` is the frozen reference and is never edited or split.
