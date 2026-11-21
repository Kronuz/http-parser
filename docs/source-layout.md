# Source layout

`http_parser.h` is the include users name. The `.cc` files are the library target's sources; the
`.h` files after it are internal and compile alone. Rules: cpp-libraries' `docs/SPLITTING.md`.

| File | Holds |
|---|---|
| `http_parser.h`, `http_parser_enums.h`, `likely.h` | The public API, its enums, `likely`/`unlikely`. |
| `http_parser.cc` | `http_parser_execute()`: the parse loop's macros, the bulk scans (NEON/SSE2) and the loop itself. |
| `http_parser_url.cc` | `http_parser_parse_url()` and the host grammar. |
| `http_parser_api.cc` | `http_status_str`, `http_method_str`, `http_errno_*`, init, pause, version and the public wrappers. |
| `http_parser_internal.h` | Includes, SIMD selection, small macros, `method_strings` and the inlined `message_needs_eof`/`should_keep_alive`. |
| `http_parser_chars.h` | Character classes, the URL character table and `parse_url_char()`, shared by the loop and the URL parser. |
| `http_parser_tables.h` | The token and hex tables, the header character table and the special header names the loop matches. |

## Kept whole

- `http_parser.cc` (about 2,000 lines): `execute<lenient>()` is one state machine, one function with
  `goto` between its states and locals every state reads, and the compiler inlines the scans
  and `parse_url_char()` into it. Its states are not units someone opens alone, and a cut
  inside the function cannot be read or compiled alone. The macros and the scans exist for the loop
  only and stay next to it.
- `test/diff.cc` (1,004 lines): one differential test of one subject: its harness, corpus,
  random messages and sweeps share the anonymous namespace's state, so topic files would need
  that state exported for no gain.
- `test/http_parser_old.cc` is the frozen reference and is never edited or split.
