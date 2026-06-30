# AGENTS.md

Working notes for agents modifying this repository. For the design read
`ARCHITECTURE.md`; for usage read `README.md`. This file covers the repo layout,
how to build and test, the invariants you must not break, and the traps that are
easy to fall into.

## Repo map

```
http_parser.h         Declares the API (init, settings, execute, helpers) and the http_parser / http_parser_settings structs. Header. Verbatim from Xapiand.
http_parser_enums.h   The method / status / errno / state / header-state enums, defined with enum.h's ENUM() macro. Includes "enum.h". Verbatim from Xapiand.
http_parser.cc        The streaming state machine: http_parser_execute() plus helpers. Verbatim from Xapiand except for the .c -> .cc rename. Includes "likely.h".
likely.h              Self-contained likely()/unlikely() branch hints. Vendored on extraction (no config.h coupling).
test/test.cc          Runnable smoke test: GET, POST+body, byte-by-byte streaming, chunked across two buffers, malformed method, keep-alive.
examples/demo.cc      A runnable tour (not a test).
CMakeLists.txt        STATIC library `http_parser` (+ alias http_parser::http_parser); FetchContent enum-reflection; CTest test `http_parser`.
LICENSE               MIT. NGINX/Joyent for the parser; Dubalu LLC for the Xapiand additions and extraction wiring.
README.md             What it is, install, usage, API.
ARCHITECTURE.md       Internal design of the streaming state machine, callbacks, body handling, enums.
```

This is not header-only. `http_parser.cc` must be compiled and linked; the
headers only declare the API and the enums. The CMake target is a `STATIC` library
that links `enum-reflection` so `"enum.h"` resolves.

## Build and run the test

```sh
cmake -B build && cmake --build build && ctest --test-dir build
```

Configure with the Homebrew LLVM compiler if you want the family's reference
toolchain:

```sh
cmake -B build -DCMAKE_CXX_COMPILER=$(brew --prefix llvm)/bin/clang++
```

The first configure fetches `enum-reflection` over the network (FetchContent,
`GIT_TAG main`), and that pulls its own transitive deps (perfect-hash, hashes,
static-string, char-classify). Expected output ends with
`all http-parser tests passed`, exit 0. The test target is `http_parser_test`; the
registered CTest name is `http_parser`. The test and demo are only added when this
repo is the top-level project (CMakeLists.txt), so consumers vendoring it via
`FetchContent` won't build them.

## Dependency

`http_parser_enums.h` includes `"enum.h"` and defines its enums with the `ENUM()`
macro. That header lives in the sibling
[enum-reflection](https://github.com/Kronuz/enum-reflection) library, pulled in by
CMake and linked `PUBLIC` so the include path resolves (the public header chain
`http_parser.h` -> `http_parser_enums.h` -> `"enum.h"` reaches consumers, hence
`PUBLIC`). We track its tip with `GIT_TAG main`, like the rest of the family. This
is the library's only external dependency. The implementation's other include,
`"likely.h"`, is satisfied by the vendored copy in this repo, not a dependency.

## Conventions

- **C++20.** The target requests `cxx_std_20` `PUBLIC` to stay uniform with the
  sibling libraries. Don't drop the target below it.
- **The implementation is compiled as C++.** That is deliberate: it is what makes
  `enum.h`'s C++ machinery (and so the enum-reflection dependency) load-bearing,
  and it matches the C++20 family. The file is named `http_parser.cc` rather than
  `.c` so the C++ compile is first-class, not the deprecated "treat .c as C++"
  path.
- **Header filenames are stable.** `http_parser.h` and `http_parser_enums.h` keep
  their original Xapiand names so a consumer that already `#include`s them just
  needs this repo on the include path. Don't rename the headers.
- Tabs for indentation in new code, double quotes in code, no em dashes in prose.
- MIT-licensed; keep the existing copyright headers on the source files (the
  NGINX/Joyent header on `http_parser.h` / `http_parser_enums.h` /
  `http_parser.cc`, the Dubalu header on `likely.h`).

## Load-bearing invariants

- **The data callbacks can fire more than once per logical value.** `on_url`,
  `on_header_field`, `on_header_value`, and `on_body` each deliver slices of the
  caller's buffer and may be called repeatedly as a run straddles buffer
  boundaries. Any consumer (including the test and demo here) must *append*, not
  assign, and treat a header-field callback after a header-value callback as the
  start of a new pair. Don't write a test that assumes a value arrives whole.
- **`content_length` counts down, it is not the header value.** It is loaded from
  `Content-Length` and decremented as body bytes are delivered, reaching `0` at
  `on_message_complete`. Reading it after a complete parse gives `0`. The test
  asserts exactly this; don't "fix" it to expect the header number.
- **`http_errno_name()` returns the `HPE_`-prefixed token.** The string table is
  generated as `"HPE_" #n`, so the name is e.g. `"HPE_INVALID_METHOD"`, not
  `"INVALID_METHOD"`. Assertions must match the prefixed form.
- **The parser is streaming; `execute()` returns bytes consumed.** On malformed
  input it stops and the return is short of the input length, with
  `HTTP_PARSER_ERRNO(parser)` set. Check the errno after every call, not just the
  return.
- **The enums come from `enum.h`'s `ENUM()` macro.** Don't replace them with plain
  C enums or you break the reflective accessors and the dependency's reason to
  exist. The X-macro maps (`HTTP_METHOD_MAP` etc.) feed both the enums and the
  string tables, so edit the map, not the two outputs separately.

## How to extend

- **Add a request method.** Append to `HTTP_METHOD_MAP` in `http_parser_enums.h`
  (the X-macro feeds both the `http_method` enum and `method_strings`). The
  parser's method-matching trie in `http_parser.cc` then needs the new verb wired
  into its character dispatch; this is the fiddly part, mirror an existing verb of
  the same first letters.
- **Always extend the smoke test.** `test/test.cc` is the only executable check.
  Add a case for any new behavior and assert the exact parsed method / url /
  headers / body, following the append-based collector already there.

## Traps

- **Compiling the implementation as C silently changes the enums.** `enum.h` gates
  its C++ machinery behind `#ifdef __cplusplus`; built as C, `ENUM()` collapses to
  a plain enum and the reflective accessors and the enum-reflection dependency
  vanish. Keep the source `.cc` and the target a CXX target.
- **`likely.h` is vendored, not the dependency.** It is a tiny self-contained
  branch-hint header. Don't try to resolve it against enum-reflection or reintroduce
  Xapiand's `config.h`-coupled version.
- **The headers still carry the C `extern "C"` and `<sys/types.h>` baggage** from
  upstream. That is intentional for ABI compatibility with the original; leave it.

## Standalone vs. Xapiand

This is a standalone extraction from
[Xapiand](https://github.com/Kronuz/Xapiand), which itself vendored and adapted
the Joyent/Node.js `http_parser`. The headers and the implementation were copied
from Xapiand's in-tree copy. The extraction deltas are small and mechanical: the
one local include `"enum.h"` is resolved against the sibling enum-reflection
library through CMake, the `"likely.h"` include is satisfied by a vendored
self-contained copy (dropping Xapiand's `config.h` coupling), and the
implementation file was renamed `http_parser.c` -> `http_parser.cc`. No parser
logic changed; any edit here should stay reconcilable with upstream as a plain
diff.

Consumed by [Kronuz/http](https://github.com/Kronuz/http) (the HTTP application
layer): it parses with this fork rather than a stricter parser like llhttp because
this one accepts arbitrary request methods, which Xapiand's custom REST verbs
(`COUNT`, `INFO`, `DUMP`, `RESTORE`, …) require.

**Planned refresh (separate commit):** the fork is pinned at version 2.7.1; the
Joyent upstream's final release is 2.9.4. A future change rebases the fork onto
2.9.4 to pick up ~2.5 years of security/correctness fixes, re-applying the small
extraction deltas above. Keep edits reconcilable so that rebase stays a plain diff.
