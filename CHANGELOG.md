# Changelog

Notable changes to http-parser, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); entries are dated because the
library has no releases. Nothing the parser reports changes in these entries: the
differential test (`test/diff.cc`) holds every callback, its bytes and offset, every
return of `http_parser_execute()` and every field of `struct http_parser` to the
frozen parser in `test/http_parser_old.cc`, on 1.9 million parses per run.

## 2026-10-31

### Changed

- **The parse loop takes runs of bytes, and the next state, in one step.** Each byte that
  goes through the loop costs about 1.2 ns for the loop head (load, header-size count) and
  the indirect jump of the dispatch, and a URL byte another 3 ns in `parse_url_char()`.
  A request is mostly bytes that need neither:
  - `skip_url_chars` takes a run of URL characters in `s_req_path`, `s_req_query_string`
    and `s_req_fragment` at once: 16 bytes at a time with NEON or SSE2 in strict mode, the
    `IS_URL_CHAR` table otherwise. A 125-byte URL goes from 415 ns to 63 ns.
  - `HTTP/d.d` and its CRLF, the end of a request line, are one step at the `H` after the
    URL (seven trips through the loop before).
  - After a header value, the CR, the LF and the next line's first byte are taken together.
  - `find_crlf` finds the end of a header value in one pass over 16-byte blocks. It called
    `memchr` twice per value, 3.4 ns together and 10% to 16% of a header-heavy request.
  - A header line, a chunk frame and the end of the headers continue in the next state's own
    code (`NEXTCHAR_COUNTED()` or `NEXTCHAR()`, then `goto`) instead of returning to the loop
    and its dispatch. A header line went through the dispatch six times, a 256-byte chunk
    eight.
- `HTTP_PARSER_NO_SIMD` selects the byte loops. The struct layout, the symbols and the
  public header are unchanged; `find_crlf` keeps its external name and signature.

Ablation, Apple M4 Pro (Apple clang 17, `quiet strict`, A/A 0.99 to 1.01), speedup over the
parser before these changes:

| Step | GET, 3 headers | Browser GET | POST, 1 KB | Chunked |
|---|---:|---:|---:|---:|
| URL run alone | 1.31x | 1.20x | 1.34x | 1.00x |
| + request-line tail | 1.36x | 1.22x | 1.37x | 1.00x |
| + CR LF and the next byte | 1.41x | 1.24x | 1.41x | 1.00x |
| + `find_crlf` in one pass | 1.51x | 1.35x | 1.45x | 0.98x |
| + direct transitions | 1.60x | 1.56x | 1.54x | 1.35x |

On the x86 laptop the request-line tail is worth as much as the URL run (1.13x for the
URL run alone, 1.28x with the tail, 1.34x with the CR LF path, 1.45x with `find_crlf`, all
on a GET with 3 headers, `-march=native`).

Result, ns per message, after the changes (`bench/bench.cc`, 15 trials of about 30 ms per
arm, median, interleaved with the old parser, an old-again A/A arm and llhttp 9.4.3; the
A/A ratio is 0.99 to 1.01 on every row of both machines):

Apple M4 Pro, Apple clang 17, `-O3 -DNDEBUG`:

| Workload | Before | After | Speedup | llhttp |
|---|---:|---:|---:|---:|
| GET, 3 headers | 125.5 | 78.2 | 1.60x | 74.8 |
| Browser GET, 14 headers | 429.2 | 275.4 | 1.56x | 257.6 |
| GET, 64 custom headers | 1525.8 | 1033.0 | 1.48x | 1045.6 |
| POST, 1 KB body | 150.1 | 97.6 | 1.54x | 88.6 |
| POST, 64 KB body | 107.6 | 79.7 | 1.35x | 69.6 |
| Chunked, 16 x 256 B | 293.6 | 216.9 | 1.35x | 183.3 |
| 32 pipelined GETs | 4090.9 | 2271.8 | 1.80x | 2073.9 |
| Browser GET, 64-byte segments | 523.8 | 376.6 | 1.39x | 328.0 |
| Response 200, 8 headers | 204.7 | 157.7 | 1.30x | 142.9 |
| Request line only | 67.4 | 38.2 | 1.76x | 34.5 |
| One short header | 53.4 | 47.0 | 1.14x | 48.3 |
| One long header (117 B) | 60.9 | 52.0 | 1.17x | 51.0 |
| Long URL (125 B) | 414.2 | 65.2 | 6.35x | 75.2 |

Intel i9-9980HK, Apple clang 17, `-O3 -DNDEBUG`, no `-march`:

| Workload | Before | After | Speedup | llhttp |
|---|---:|---:|---:|---:|
| GET, 3 headers | 342.8 | 175.0 | 1.96x | 185.1 |
| Browser GET, 14 headers | 1153.8 | 619.5 | 1.86x | 616.5 |
| GET, 64 custom headers | 4333.8 | 2524.6 | 1.72x | 2345.8 |
| POST, 1 KB body | 451.6 | 240.7 | 1.88x | 236.8 |
| POST, 64 KB body | 324.5 | 191.3 | 1.70x | 186.6 |
| Chunked, 16 x 256 B | 915.6 | 427.6 | 2.14x | 454.1 |
| 32 pipelined GETs | 10719.1 | 5165.1 | 2.08x | 5367.0 |
| Browser GET, 64-byte segments | 1362.4 | 833.0 | 1.64x | 737.7 |
| Response 200, 8 headers | 645.5 | 402.8 | 1.60x | 365.9 |
| Request line only | 170.0 | 74.8 | 2.27x | 83.1 |
| One short header | 162.6 | 102.6 | 1.59x | 117.1 |
| One long header (117 B) | 172.8 | 115.1 | 1.50x | 149.2 |
| Long URL (125 B) | 901.2 | 130.3 | 6.91x | 146.6 |

Instructions per message under callgrind (clang 18 on GitHub Linux runners; deterministic).
x86-64 / arm64:

| Workload | Before | After | llhttp |
|---|---:|---:|---:|
| GET, 3 headers | 2995 / 2926 | 2038 / 2208 | 1786 / 1790 |
| Browser GET | 9900 / 9933 | 7266 / 7352 | 7202 / 7794 |
| GET, 64 custom headers | 35340 / 38285 | 28285 / 28509 | 27470 / 30396 |
| Chunked, 16 x 256 B | 7016 / 7059 | 5110 / 5801 | 4418 / 4319 |
| Response 200 | 5390 / 5413 | 4491 / 4810 | 3786 / 3949 |
| POST, 1 KB body | 4014 / 3850 | 2828 / 2997 | 2249 / 2261 |

### Added

- `test/diff.cc` (CTest `http_parser_diff`) and `test/http_parser_old.cc`, a verbatim copy
  of `http_parser.cc` from before these changes with its symbols renamed. Every callback
  (kind, bytes, offset in the buffer given to `execute()`) and every return of `execute()`
  is recorded with a snapshot of every field of `struct http_parser`, and the two lists
  must match. Inputs: 616 corpus messages (all methods, URL forms, header kinds and
  near-miss names, folded and empty values, bare CR and LF, NUL and control bytes, chunked
  bodies, responses, pipelining, the 80 KB limit at +-24 bytes for each of URL, value, name,
  many headers, status, chunk size and chunk extension), each under 8 split plans, three
  parser types and three callback sets; every prefix; every single-byte substitution,
  insertion and deletion; every callback failing or pausing in turn; sweeps (every header
  value length 0 to 70 with each special byte at each position and alignment, every byte
  value at every position of a URL and of ` HTTP/d.d\r\n` and of a chunked body, a CR
  followed by every pair of bytes); and 20 000 random grammar-built messages with random
  mutations, splits, failing and pausing callbacks. Each chunk goes to the parser in its
  own exact-size heap block, so an out-of-bounds read is an AddressSanitizer report.
- `test/fuzz.cc`: the same comparison as a libFuzzer target and as a mutation-loop driver
  (CTest `http_parser_fuzz`), with every split point, pauses, failures and filler runs up to
  128 KB. Under ASan and UBSan on x86-64 and arm64 Linux, strict and non-strict, with and
  without the vector code, 3.3 million libFuzzer inputs (about 70 million comparisons) and
  150 000 mutation-loop inputs per configuration ran without a difference, and the
  differential test passed in every one of the eight configurations.
- `tools/mutants.py` breaks each fast path in about forty ways (a byte counted wrongly, a
  limit moved, a state skipped, a vector loop that reads past its span) and requires the
  differential test to fail on each one. Two mutants survived the first version of the test
  and led to changes: a redundant `p[2] != ' '` test in the CR LF path (the next state makes
  it) went away, and cases past the 80 KB limit with a span shorter than the buffer were
  added.
- `bench/bench.cc` (`-DHTTP_PARSER_BUILD_BENCH=ON`), `bench/loop.cc` (instructions per
  message under callgrind) and `bench/micro_*.cc` (the CR LF scan and the URL run alone).

### Notes

- Where the time goes (samples of the parser before these changes, small GET with 3 headers):
  70.6% the main loop, 14.9% `parse_url_char()`, 6.4% callbacks, 5.1% `memchr`; a browser GET
  with 14 headers: 73.6% loop, 11.0% `memchr`, 9.4% `parse_url_char()`; 64 custom headers:
  77.3% loop, 16.0% `memchr`. Per header the gap to llhttp was a steady 7.5 ns.
- Tried and not shipped: keeping `nread` in a local (no effect); the CR/LF scan inlined into
  the loop (slower on 12 of 13 workloads, up to 1.46x on a bare request line, because the
  vector code costs the loop its registers: `find_crlf` stays out of line); `find_crlf`
  alone without the other three (slower on arm64, a code-layout effect). The loop is one
  large function and its speed moves with small changes to it; measure on the compilers in
  use after touching it.
- Also tried: taking the part of a Connection, Content-Length, Transfer-Encoding, Upgrade or
  Proxy-Connection name that matches in one run, about 40 lines in the header-name states. The
  matcher changes state once per byte at about 25 instructions each, and callgrind puts the
  matching of those names at a sixth of the instructions of a POST. It was not shipped because
  its effect depends on the machine. On the M4 it was 0% to 8% faster on every row (parity with
  llhttp on a small GET, a browser GET and 64 headers). On the i9, over six interleaved rounds,
  POST and chunked rows were 4% to 9% faster and the header-heavy GET rows 4% to 10% slower (64
  custom headers +10%, small GET +7%, short header +6%); callgrind on x86-64 counts 1% to 1.6%
  more instructions on the GET rows and 5% fewer on a POST. Header-name matching remains the
  largest identifiable cost of a POST; a version that does not slow the GET rows is the next
  step toward llhttp.
- A refresh to Joyent 2.9.4 would not be faster: its header-name loop is the same token
  table loop, its header-value scan tests every byte (32 ns against 7 ns for a 117-byte
  value), and its URL states are the same `parse_url_char()` per byte.
- The vector scans read only whole blocks inside their span and every run stops short of
  `HTTP_MAX_HEADER_SIZE`, so the byte that crosses the limit is reported by the loop at the
  same offset as before. An earlier SSE2 `find_crlf` read a block that straddled the end of
  the buffer, which AddressSanitizer flags.
