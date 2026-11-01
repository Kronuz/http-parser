> Status: CURRENT (2026-11-01) The evaluation behind keeping the engine. The owner's decision follows it: keep, harden, and run llhttp's suite (CHANGELOG.md, 2026-11-01). The prototype it measures is not in the repository; section 3 describes it.

# llhttp: swap the engine, or bring in pieces of it?

The owner's question: should http-parser swap its engine for llhttp, adding Xapiand's
verbs, or bring in pieces of llhttp? Conditions: this parser at 476ba60, before the
hardening; llhttp v9.4.3; the prototype built on 476ba60; the hardening as first reviewed
(its later rules, CHANGELOG.md, are not measured here).

## Answer

Keep the engine and harden it, and bring in llhttp's conformance suite as a test. Do not
swap.

- **Security gap.** The fork misses six of upstream's request-framing and memory-safety fixes
  after 2.7.1. llhttp's own suite finds 32 requests this parser frames differently from
  llhttp, nearly all request smuggling: a bare LF ends a header line, obs-fold is taken,
  `Transfer-Encoding: deflate, chunked` is read as no body, `Content-Length: 4 2` as 42, chunk
  extensions are not checked, and a control byte in a header value is accepted or rejected
  depending on where the TCP segment ends.
- **Hardening closes it.** The hardening (276 lines in http_parser.cc as first reviewed)
  rejects all of them by default; `lenient_http_headers = 1` gives back
  2.7.1's behavior. Afterwards no request case of the suite differs from llhttp in a way that
  matters for smuggling, and the bench stays at llhttp parity (0.98-1.06x of main on the M4).
- **The swap works but buys nothing.** llhttp regenerates with this parser's 30 methods and
  numbers from a 149-line patch, and a 321-line adapter puts it behind `http_parser.h`. It
  is not faster overall: 3-12% faster than this parser on most M4 workloads, 22% slower on a
  long URL, and slower on ten of thirteen on the i9 (section 3). Consumers would see API
  changes: a 128-byte struct, other error codes and offsets, fields reset at the end of a
  message, a header-size limit the adapter has to rebuild, and a Node.js toolchain for every
  method change.

## Findings

| # | Finding | Evidence |
|---|---|---|
| 1 | Missing upstream fixes: 01da95f (CVE-2018-7159), 3502589, 2a0d106, 7d5c99d (CVE-2019-15605), 9f489a4, 9ce7316; and six smaller ones | section 1 |
| 2 | llhttp's 253-case suite: this parser differs on 90; 32 are request framing (Transfer-Encoding 13, bare LF 7, chunk syntax 5, Content-Length 3, header value bytes 2, obs-fold 1, version 1) | `http_parser_conformance --report`; test/llhttp_divergences.txt |
| 3 | A control byte in a header value is accepted in one buffer and rejected when an `execute()` call starts at it: the verdict depends on segmentation | the suite's one-byte-at-a-time run |
| 4 | The harness is right: llhttp built from its release C reproduces 253 of its 253 logs through it | `-DHTTP_PARSER_LLHTTP_SOURCE_DIR` |
| 5 | The hardening: no request case of the suite is request smuggling any more (75 cases still differ, none of them request smuggling); its tests pass in CI and under ASan, UBSan and TSan; the mutants that remove a check are all killed | section 2 |
| 6 | The regenerated llhttp differs from llhttp only on the methods dropped (9 cases), the lenient flags the API cannot set (22) and a pause at the last chunk (2) | conformance `prototype` engine |
| 7 | Behind http_parser's API, 24% of the differential test's 2.15 million parses report something else at the public API, mostly llhttp's strictness, then error codes and offsets and field timing | `http_parser_llhttp_diff`, section 3 |
| 8 | Speed of the prototype against this parser: 0.88-1.22x on the M4, 0.96-1.64x on the i9 (baseline x86-64; Homebrew llhttp with SSE4.2: 0.92-1.30x) | section 3 |
| 9 | The reason given for the fork ("accepts arbitrary request methods", AGENTS.md, Kronuz/http's CMakeLists.txt) is not accurate: the method table is fixed (30 methods, Xapiand's included); llhttp regenerated with the same table accepts the same set | http_parser_enums.h, prototype |

## 1. Upstream fixes after 2.7.1

The fork is Joyent http_parser 2.7.1 (2016). Upstream released 2.8.0 to 2.9.4 (2018-2020) and
archived the repository. Every change to `http_parser.c` in `v2.7.1..main`:

| Upstream | Release | Change | Kind | In the fork | Hardening |
|---|---|---|---|---|---|
| 335850f | 2.8.0 | `HTTP_STATUS_MAP`, `enum http_status` | API | yes (from Xapiand) | |
| 9f489a4 | 2.8.0 | one digit each side of the HTTP version | strictness | no | yes, and only 0.9, 1.0, 1.1, 2.0 |
| 3b0da34 | 2.8.0 | `on_status` for a status line without a reason | response | no | no |
| 05525c5 | 2.8.0 | Upgrade only on a 101 response | response framing | no | no |
| 9ce7316 | 2.8.0 | `http_parser_parse_url`: `strtoul` reads past an unterminated buffer | memory safety | no | yes |
| 921d558, 4dae120 | 2.8.0, 2.9.0 | SOURCE method, ICE/1.x | methods | n/a, own table | |
| 01da95f | 2.8.1 | `Content-Length: 4 2` is an error, not 42 (CVE-2018-7159) | smuggling | no | yes |
| a7c2e86 | 2.9.0 | `nread` off by one at a buffer boundary | header limit | no | no |
| 2ed7527 | 2.9.0 | `http_status_str()` | API | yes | |
| 3123273 | 2.9.0 | `http_parser_parse_url("")` fails | URL | no | no |
| cf69c8e, c7d4925 | 2.9.0, 2.9.2 | faster main loop, and a fix to it | speed | n/a, own scans | |
| 25de6ed | 2.9.0 | one `on_message_begin` for a response after leading CRLF | response | no | no |
| 0ae8d93 | 2.9.0 | `http_parser_set_max_header_size()` | API | no | no |
| cd88eef | 2.9.0 | Content-Length with obs-fold | smuggling | not needed: 2.7.1 rejects it | |
| 3502589 | 2.9.0 | an empty Content-Length is an error | smuggling | no | yes |
| 2a0d106 | 2.9.1 | check every header value byte (a memchr skip let control bytes through) | smuggling | no: `find_crlf` skips them | yes |
| 7d5c99d, 714cbb2 | 2.9.3, 2.9.4 | Transfer-Encoding lists, `chunked` last; another coding in a request, or Transfer-Encoding with Content-Length, is an error (CVE-2019-15605) | smuggling | no | yes, stricter: `chunked` alone |
| e13b274 | after 2.9.4 | `allow_chunked_length` opt-in | API | no | no |

llhttp kept tightening after that, and its suite pins each step: a later Transfer-Encoding
header clears `chunked` (e9b36ea), versions are checked (#157), no whitespace after the start
line (#180), `;` before chunk extensions (#181) and their syntax (#193, #248, #253), obs-fold
off by default (#348), CRLF in the status line (#865), an empty Transfer-Encoding rejected
(#874).

## 2. llhttp's suite against this parser

`tools/llhttp_corpus.mjs` reads llhttp's `test/request/*.md` and `test/response/*.md` with
llhttp's own markdown reader and input transformations, and writes `test/llhttp_corpus.inc`:
253 cases, the input bytes and llhttp's expected log reduced to what http_parser's callbacks
report (`test/conformance.h`: URL, status, header pairs, headers complete with method or
status and version, chunk header and complete, body, message complete, pause, upgrade, error).
`test/conformance.cc` runs each case through this parser in one buffer and one byte at a time,
through llhttp built from its release C (it reproduces its own 253 logs, so the reduction and
the drivers are right), and once more through llhttp without the case's lenient flags. Every
case where this parser differs is listed with a category in `test/llhttp_divergences.txt`, and
the CTest test `http_parser_conformance` fails on any change to that list. On main:

| Category | Requests | Responses | What |
|---|---:|---:|---|
| S-te | 13 | 2 | Transfer-Encoding `deflate, chunked`, `chunked, deflate`, two headers, unknown or empty, with Content-Length |
| S-bare-lf | 7 | 3 | LF without CR ends the request line, a header line or the headers |
| S-chunk | 5 | 4 | a space after the chunk size, `2;`, an unbalanced quote, LF in an extension |
| S-cl | 3 | | `4 2`, `13 37`, empty |
| S-value-ctl | 2 | | `\f` in a value (and 2 more where the verdict depends on the split) |
| S-obs-fold | 1 | | ` Content-Length: 38` folded into the header above it |
| S-version | 1 | 4 | HTTP/5.6, HTTP/11.1, HTTP/1.01 |
| R-* | | 13 | response side: Upgrade outside 101, a body on 304, extra `on_message_begin` |
| B-method | 9 | 2 | REPORT, M-SEARCH, SOURCE, QUERY, PRI, RTSP/, ICE/: not in this parser's table |
| B-lenient | 10 | 3 | llhttp with a lenient flag; this parser rejects, as llhttp does without it |
| B-error, B-stricter, B-close-ows | 6 | 2 | same verdict, other callbacks before the error; tabs around Content-Length; `close\t` |

S is request smuggling: a front end and this parser disagree on where a request ends. The
three plainest, all accepted by main:

- `Dummy: x\nContent-Length: 23` (request/invalid.md:454). The bare LF ends the header, so the
  23 bytes after the blank line are a body, and the `GET /admin` hidden past them is parsed as
  the next request. A front end that ends lines only at CRLF sees one header and no body.
- `Foo: bar` then ` Content-Length: 38` (request/invalid.md:650): folded into `Foo`, so the
  request has no body and the `GET /bye` meant as its body is the next request.
- `Transfer-Encoding: deflate, chunked` (request/transfer-encoding.md:777): read as no body;
  the chunked body is parsed as the next request.

**The hardening.** One check per rule, in the state that sees the byte, under `!lenient`:
CRLF required (`HPE_CR_EXPECTED`, new), no obs-fold, no control byte but HT in a value (the
value scan `find_value_end` stops at them, so the verdict no longer depends on the split), a
request's Transfer-Encoding is `chunked` alone and once (`HPE_INVALID_TRANSFER_ENCODING`, new;
stricter than llhttp, which also takes `deflate, chunked` though this parser decodes no other
coding), Content-Length digits with spaces after them only, chunk extensions per RFC 9112
section 7.1.1, versions 0.9/1.0/1.1/2.0; and the `strtoul` over-read. `test/diff.cc` runs
every input lenient (equal to the frozen 2.7.1 parser in every event and field) and strict
(equal in events and public fields up to a hardening error); a sweep checks each rejection in
one call, byte by byte and at every split; `tools/mutants.py` removes each check and the sweep
must fail. After it the suite lists 0 request cases in an S category: the requests it now
rejects where llhttp also does are B-error (other callbacks before the error), and `deflate,
chunked` (two cases) B-stricter. The response-side cases (S-te 2, R-* 13) are left for a
response-side change.

Checks of the hardening as first reviewed: CI green on every job (Linux gcc and clang,
x86-64 and arm64, macOS arm64 and x86-64, FreeBSD, ASan+UBSan and TSan on Linux x86-64; the
scalar and the non-strict (`HTTP_PARSER_STRICT=0`) builds without sanitizers). On
the Linux VM (g++ 11, glibc): the default, scalar and non-strict builds pass, the tests pass
under ASan+UBSan, and under TSan with clang 12 (g++ 11's TSan does not start on that
kernel). Mutants: 64 of 64 killed on x86-64 (the two that survived the first run, a space
before a chunk extension and the second digit of a major version, led to two more sweep
cases and an offset check); on the M4 the NEON ones: 6 killed, the two that misplace the
match position do not finish (stopped after 11 minutes, where the others take seconds; `mutants.py` counts a hang as killed
at 15). Under ASan on the VM the three SSE2 over-read mutants are caught, two as a
heap-buffer-overflow and the URL one as a crash; the NEON over-read ones need ASan on arm64,
which hangs on the M4, and were not run. Kronuz/http's 12 tests pass against it.

## 3. The swap: llhttp regenerated with this parser's methods

llhttp's method table is TypeScript. The prototype's `methods.patch` (149 lines) gives it this
parser's 30 methods and numbers (DELETE=0 to WAL=29) and drops the RTSP, ICE and HTTP/2
preface methods; `regen.sh` runs llhttp v9.4.3's generator (llparse, Node.js 22, in a scratch
directory) and writes plain C (`generated/llhttp.c`, 9468 lines). Without the patch the same
script reproduces llhttp's release `llhttp.c` byte for byte; `regen.sh --check` holds the
committed output to the patch. `adapter.cc` (321 lines) replaces llhttp's `api.c`: the
generated parser's hooks call the `http_parser_settings` callbacks with the `http_parser*`
directly, one indirect call per event as in http_parser; the string tables and
`http_parser_parse_url()` stay http_parser.cc's. `test/test.cc` passes against it.

On llhttp's suite it behaves as llhttp except for the dropped methods (9 cases), the lenient
flags (22: the API has no way to set them) and pausing in the last `on_chunk_complete` (2).

Kronuz/http's tests (12, at c9777e4) pass with the prototype as its parser
(`-DHTTP_PARSER_ENGINE_LLHTTP=ON`), as they do with the hardening; they send well-formed
requests, so they show the API holds, not that behavior is unchanged.

What Kronuz/http and Xapiand would see. From `http_parser_llhttp_diff` (test/diff.cc against
the frozen parser, public fields compared where consumers read them, the first difference per
parse tallied): 526,593 of 2,154,218 parses differ.

- **Strictness** (most of them, by design): everything the hardening rejects, and more: a NUL
  or `\f` at the start of a value, `GET / HTTP/0.9`, any whitespace after the start line.
- **Error codes and offsets.** llhttp's codes map to the nearest `http_errno`, but for the
  same input it often stops elsewhere or for another reason (`HPE_STRICT` instead of
  `HPE_INVALID_CONSTANT`, `HPE_LF_EXPECTED` instead of `HPE_INVALID_HEADER_TOKEN`, ...), and
  `execute()` returns another count. Its own `HPE_INVALID_TRANSFER_ENCODING`,
  `HPE_CR_EXPECTED` and `HPE_UNEXPECTED_SPACE` have no 2.7.1 errno.
- **Fields reset at the end of a message.** After a message, llhttp clears `flags` and the
  method for the next one: read after `execute()` returns, `flags` (so
  `http_should_keep_alive()`) and `method` differ. In the callbacks they agree.
- **`content_length` at `on_headers_complete` of a chunked message** is 0, not `ULLONG_MAX`
  (an adapter detail, fixable).
- **Callback order on errors**: llhttp calls `on_message_begin` before it rejects a method;
  http_parser does not.
- **Header-size limit.** llhttp has none. The adapter counts the bytes from the start of a
  message to the end of its headers and checks at the end of the headers and of each call, not
  at the crossing byte, so callbacks run for the bytes before the check; chunk-size lines and
  trailers are not counted (2.7.1 counts them).
- **Pause** in the last `on_chunk_complete`: `on_message_complete` waits for the next call
  with data, since `execute(p, s, NULL, 0)` means EOF.
- **ABI**: `sizeof(http_parser)` 32 to 128 bytes; the private fields (`state`,
  `header_state`, `index`, `nread`) mean nothing.

Speed, `bench/bench.cc`: ns per message, median of 15 interleaved trials, `quiet strict`;
`llhttp-pr` is the prototype, `llhttp` the release library from Homebrew.

Hosts: Apple M4 Pro (arm64, Apple clang 17) and Intel i9-9980HK (x86_64, Apple clang), both
macOS, Release, `quiet strict`; three runs each (a smoke run, two of 15 trials at 30 ms), the
two confirming runs below. ns per message is their mean; the ratios are per run, both runs
shown as a range. `main` is this parser at 476ba60; the A/A
arm (the frozen parser twice) stays within 0.99-1.01 on the M4 and 0.97-1.03 on the i9.

| Workload | M4 main | M4 llhttp | M4 llhttp-pr | llhttp/main | llhttp-pr/main | i9 main | i9 llhttp | i9 llhttp-pr | llhttp/main | llhttp-pr/main |
|---|---:|---:|---:|---|---|---:|---:|---:|---|---|
| small GET (3 headers) | 77 | 74 | 74 | 0.95 | 0.96 | 179 | 190 | 181 | 1.05-1.07 | 0.99-1.04 |
| browser GET (14 headers) | 272 | 253 | 258 | 0.92-0.94 | 0.95 | 611 | 640 | 837 | 1.04-1.05 | 1.36-1.38 |
| 64 custom headers | 1005 | 1042 | 1064 | 1.01-1.06 | 1.05-1.06 | 2365 | 2428 | 2634 | 1.01-1.04 | 1.10-1.12 |
| POST 1KB body | 98 | 86 | 90 | 0.86-0.90 | 0.92 | 248 | 242 | 253 | 0.96-0.99 | 1.00-1.03 |
| POST 64KB body | 80 | 68 | 71 | 0.84-0.86 | 0.88-0.90 | 205 | 192 | 203 | 0.94 | 0.99-1.00 |
| chunked 16x256B | 221 | 178 | 210 | 0.80-0.82 | 0.95 | 452 | 459 | 552 | 1.01-1.02 | 1.22 |
| 32 pipelined small GET | 2264 | 2056 | 2206 | 0.89-0.93 | 0.97 | 5159 | 5473 | 4962 | 1.05-1.07 | 0.96 |
| browser GET, 64B segments | 371 | 328 | 339 | 0.88-0.90 | 0.91-0.92 | 804 | 741 | 936 | 0.92 | 1.15-1.18 |
| response 200 (8 headers) | 158 | 143 | 149 | 0.89-0.92 | 0.94-0.95 | 380 | 382 | 398 | 1.01 | 1.04-1.05 |
| request line only | 38 | 34 | 37 | 0.89 | 0.95-0.96 | 82 | 85 | 95 | 1.03-1.04 | 1.15-1.16 |
| 1 short header | 47 | 48 | 47 | 1.02-1.04 | 1.01-1.02 | 110 | 120 | 123 | 1.09 | 1.12 |
| 1 long header (117B) | 52 | 50 | 51 | 0.95-0.98 | 0.99-1.01 | 118 | 154 | 193 | 1.30 | 1.64 |
| long URL (125B) | 65 | 74 | 79 | 1.15-1.16 | 1.22 | 135 | 153 | 188 | 1.13-1.14 | 1.40 |

On the M4 the prototype is 3-12% faster than this parser on ten workloads (bodies most), 5%
slower with 64 headers and 22% slower on a long URL. On the i9 it is slower on ten of
thirteen, up to 1.64x: llhttp's vector paths there need SSE4.2 (`__SSE4_2__`, `pcmpestri`),
which a baseline x86-64 build leaves out; Homebrew's library has them, and is the better
bound for a prototype built with `-msse4.2`: 0.92-1.30x of this parser. On the M4 the
prototype is 0.98-1.09x of Homebrew's llhttp, and 1.18x on chunked bodies: the adapter's
hooks, and another build of the same generated code.

The hardening's cost, for the owner's decision (the lead's measurement on main replaces it):
the hardening's bench binary against 476ba60's, run alternately on the M4, two rounds each, is
0.98-1.06x of main per workload (64 custom headers 1.06x, the rest within 4%); llhttp is
0.84-1.14x of it, so the parity holds.

## 4. Pieces worth bringing

| Piece | Cost | Benefit | Where |
|---|---|---|---|
| llhttp's strict rules, default on, `lenient_http_headers` to opt out | 276 lines in http_parser.cc, two errnos, two header states; clients that send bare LF, obs-fold or other transfer codings get an error | every request smuggling divergence the suite finds closed | landed |
| llhttp's suite as a CTest test | regenerating the corpus needs Node.js and an llhttp checkout; the corpus is checked in and `--check`ed | each behavior the suite pins is held in CI; its one-byte run found the segmentation bug | both branches (shared commit 6f6cedb) |
| The generated state machine (llparse) | Node.js in the build of every method change; 9.5k lines of generated C; no header limit; a second method table to keep with `http_parser_enums.h` | the grammar is declarative and maintained upstream | prototype only |
| Span-complete callbacks (`on_header_value_complete`, ...) | additive fields in `http_parser_settings` (its size changes) | consumers stop pairing fields and values by transition (Kronuz/http's `reading_value_`) | not done |
| Separate lenient flags | no free bit in the struct: a new field | finer opt-outs than one switch | not done |

## Recommendation

**Keep and harden** (the owner's decision). The hardening and the conformance test are in;
the rest of upstream (`nread`, `parse_url("")`, the callback fixes) are separate small
changes. A swap is worth revisiting if llhttp's fixes arrive faster than the suite can carry
them over.

- Cost: the hardening, its reviews, and moving the pins of Kronuz/http and Xapiand.
- Risk: clients that send bare LF, obs-fold or other transfer codings get a 400. A consumer
  can set `lenient_http_headers` on its parser to take them again (Kronuz/http has no option
  for it yet).
- Cost of the swap instead: the adapter and its tests, Node.js for regeneration, the API
  changes above for both consumers; no speed gained. Its risk: the header limit and the
  field timing become the adapter's to get right.
