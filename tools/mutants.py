#!/usr/bin/env python3
"""Mutation check of the bulk-scan paths and the hardening checks in http_parser.cc.

Each mutant breaks one rule of one fast path (a byte counted wrongly, a limit moved, a
flag dropped, a vector loop that reads past its span, ...) or takes out one check the
parser makes unless lenient_http_headers is set. The differential test (test/diff.cc) has
to fail on every one of them: a mutant that survives is a hole in the test. Run it after a
change to a fast path or a check, and when adding one, add its mutants here.

    tools/mutants.py BUILD_DIR [--cxx c++] [--sanitize address,undefined] [--only NAME] [-j N]

BUILD_DIR is a configured CMake build tree of this repo: the include paths of the fetched
libraries (enum-reflection and its own dependencies) are taken from its _deps directory.
Mutants of the NEON or SSE2 code run only where that code is compiled (not on the other
architecture, not with --cxxflags=-DHTTP_PARSER_NO_SIMD, which checks the byte loops instead);
the ones in the URL scan only in strict mode, and the over-read ones only with --sanitize
(an over-read is visible only to AddressSanitizer).
"""
import argparse
import concurrent.futures
import glob
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (name, applies to, old text, new text). "all" runs everywhere; "neon" and "sse2" only where that
# vector code is compiled, "_strict" only in the strict URL scan (not HTTP_PARSER_STRICT=0), "+san" only
# with --sanitize (an over-read is visible only to AddressSanitizer).
MUTANTS = [
    # URL run
    ("url-budget-off-by-one", "all", "if (n > room) n = room;", "if (n > room + 1) n = room + 1;"),
    ("url-no-budget", "all", "if (n > room) n = room;", ""),
    ("url-nread-short", "all", "parser->nread += (uint32_t) (q - (p + 1));", "parser->nread += (uint32_t) (q - (p + 1)) - (q > p + 1);"),
    ("url-resume-one-late", "all", "p = q - 1;\n", "p = q;\n"),
    ("url-tail-takes-space", "all", "while (q < e && IS_URL_CHAR(*q)) {", "while (q < e && (IS_URL_CHAR(*q) || *q == ' ')) {"),
    ("url-neon-takes-hash", "neon_strict", "vorrq_u8(vcgtq_u8(vsubq_u8(v, lo), span), vceqq_u8(v, hash))", "vcgtq_u8(vsubq_u8(v, lo), span)"),
    ("url-neon-takes-qm", "neon_strict", "      vceqq_u8(v, qm));", "      vdupq_n_u8(0));"),
    ("url-neon-high-bytes", "neon_strict", "const uint8x16_t span = vdupq_n_u8(0x5d);", "const uint8x16_t span = vdupq_n_u8(0xff);"),
    ("url-sse2-takes-hash", "sse2_strict", "_mm_or_si128(out, _mm_cmpeq_epi8(v, hash))", "out"),
    ("url-sse2-sign", "sse2_strict", "const __m128i flip = _mm_set1_epi8((char) 0x80);", "const __m128i flip = _mm_set1_epi8((char) 0x00);"),
    ("url-neon-overread", "neon_strict+san", "  while (e - q >= 16) {\n    const uint8x16_t v", "  while (e - q > 0) {\n    const uint8x16_t v"),
    ("url-sse2-overread", "sse2_strict+san", "  while (e - q >= 16) {\n    const __m128i v", "  while (e - q > 0) {\n    const __m128i v"),
    # the end of the request line
    ("http-accepts-0", "all", "p[5] >= '1' && p[5] <= '9'", "p[5] >= '0' && p[5] <= '9'"),
    ("http-nread-short", "all", "parser->nread += 9;", "parser->nread += 8;"),
    ("http-budget", "all", "parser->nread + 9 <= HTTP_MAX_HEADER_SIZE &&", ""),
    ("http-needs-lf", "all", "p[8] == CR && p[9] == LF", "p[8] == CR"),
    ("http-minor-from-major", "all", "parser->http_minor = (unsigned short) (p[7] - '0');", "parser->http_minor = (unsigned short) (p[5] - '0');"),
    # LF and the next byte after a header value
    ("crlf-nread-short", "all", "parser->nread += 2;", "parser->nread += 1;"),
    ("crlf-no-budget", "all", "parser->nread + 2 <= HTTP_MAX_HEADER_SIZE &&", ""),
    ("crlf-no-lf-check", "all", "                   p[1] == LF) {", "                   true) {"),
    ("crlf-needs-two-more", "all", "(data + len) - p >= 3 &&", "(data + len) - p >= 2 &&"),
    ("crlf-wrong-state", "all", "UPDATE_STATE(s_header_value_lws);\n          goto header_value_lws;", "UPDATE_STATE(s_header_field_start);\n          goto header_field_start;"),
    # find_crlf
    ("find-crlf-no-lf", "all", "if (*p == CR || *p == LF) {", "if (*p == CR) {"),
    ("find-crlf-limit", "all", "limit = MIN(limit, HTTP_MAX_HEADER_SIZE);\n\n  r = scan_crlf(", "limit = MIN(limit, HTTP_MAX_HEADER_SIZE + 1);\n\n  r = scan_crlf("),
    ("find-crlf-not-found", "all", "  r = scan_crlf(p, p + limit);\n  return r == p + limit ? data + len : r;", "  r = scan_crlf(p, p + limit);\n  return r;"),
    ("find-crlf-neon-nibble", "neon", "vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);\n    if (bits) {\n      return p + (__builtin_ctzll(bits) >> 2);\n    }\n    p += 16;\n  }\n#elif defined(HTTP_PARSER_SSE2)\n  const __m128i cr", "vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);\n    if (bits) {\n      return p + (__builtin_ctzll(bits) >> 3);\n    }\n    p += 16;\n  }\n#elif defined(HTTP_PARSER_SSE2)\n  const __m128i cr"),
    ("find-crlf-neon-no-lf", "neon", "vorrq_u8(vceqq_u8(v, cr), vceqq_u8(v, lf))", "vceqq_u8(v, cr)"),
    ("find-crlf-sse2-no-cr", "sse2", "_mm_or_si128(_mm_cmpeq_epi8(v, cr), _mm_cmpeq_epi8(v, lf))", "_mm_cmpeq_epi8(v, lf)"),
    ("find-crlf-neon-overread", "neon+san", "  while (end - p >= 16) {\n    const uint8x16_t v = vld1q_u8((const uint8_t*) p);\n    const uint8x16_t m = vorrq_u8(vceqq_u8", "  while (end - p > 0) {\n    const uint8x16_t v = vld1q_u8((const uint8_t*) p);\n    const uint8x16_t m = vorrq_u8(vceqq_u8"),
    ("find-crlf-sse2-overread", "sse2+san", "  while (end - p >= 16) {\n    const __m128i v = _mm_loadu_si128((const __m128i*) p);\n    const unsigned bits", "  while (end - p > 0) {\n    const __m128i v = _mm_loadu_si128((const __m128i*) p);\n    const unsigned bits"),
    # the header states that go straight to the next state
    ("next-char-uncounted", "all", "  COUNT_HEADER_SIZE(1);\n\n/* The same for a state", "\n\n/* The same for a state"),
    ("next-char-unchecked", "all", "  COUNT_HEADER_SIZE(1);\n\n/* The same for a state", "  ++parser->nread;\n\n/* The same for a state"),
    ("colon-skips-callback", "all", "          CALLBACK_DATA(header_field);\n          NEXTCHAR_COUNTED();", "          NEXTCHAR_COUNTED();"),
    ("discard-ws-space-only", "all", "        if (ch == ' ' || ch == '\\t') {\n          NEXTCHAR_COUNTED();", "        if (ch == ' ') {\n          NEXTCHAR_COUNTED();"),
    ("value-start-counts-twice", "all", "            break;\n        }\n        NEXTCHAR_COUNTED();\n        /* FALLTHROUGH */\n      }\n\n      case s_header_value:", "            break;\n        }\n        NEXTCHAR_COUNTED();\n        ++parser->nread;\n        /* FALLTHROUGH */\n      }\n\n      case s_header_value:"),
    # the chunk states that go straight to the next state
    ("chunk-first-digit-uncounted", "all", "        UPDATE_STATE(s_chunk_size);\n        NEXTCHAR_COUNTED();", "        UPDATE_STATE(s_chunk_size);\n        NEXTCHAR();"),
    ("chunk-digit-uncounted", "all", "        parser->content_length = t;\n        NEXTCHAR_COUNTED();", "        parser->content_length = t;\n        NEXTCHAR();"),
    ("chunk-cr-uncounted", "all", "          UPDATE_STATE(s_chunk_size_almost_done);\n          NEXTCHAR_COUNTED();", "          UPDATE_STATE(s_chunk_size_almost_done);\n          NEXTCHAR();"),
    ("chunk-header-state", "all", "        UPDATE_STATE(s_chunk_data);\n        CALLBACK_NOTIFY(chunk_header);", "        CALLBACK_NOTIFY(chunk_header);"),
    ("chunk-complete-state", "all", "        UPDATE_STATE(s_chunk_size_start);\n        CALLBACK_NOTIFY(chunk_complete);", "        UPDATE_STATE(s_chunk_size);\n        CALLBACK_NOTIFY(chunk_complete);"),
    ("chunk-data-falls-through", "all", "        if (parser->content_length != 0) {\n          break;\n        }\n", ""),
    ("chunk-size-start-uncounted", "all", "        CALLBACK_NOTIFY(chunk_complete);\n        NEXTCHAR_COUNTED();", "        CALLBACK_NOTIFY(chunk_complete);\n        NEXTCHAR();"),
    # the end of the headers and the start of the body
    ("headers-end-uncounted", "all", "          UPDATE_STATE(s_headers_almost_done);\n          NEXTCHAR_COUNTED();", "          UPDATE_STATE(s_headers_almost_done);\n          NEXTCHAR();"),
    ("body-first-byte-counted", "all", "          NEXTCHAR();\n          goto body_identity;", "          NEXTCHAR_COUNTED();\n          goto body_identity;"),
    ("body-done-skips-state", "all", "          CALLBACK_DATA_(body, p - body_mark + 1, p - data);\n          goto message_done;", "          CALLBACK_DATA_(body, p - body_mark + 1, p - data);\n          break;"),
    ("trailer-done-skips-state", "all", "          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);\n          goto message_done;", "          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);\n          break;"),
    # find_value_end (the value scan unless lenient)
    ("value-end-no-ctl", "all", "if (!IS_HEADER_CHAR(*p) || *p == CR || *p == LF) {", "if (*p == CR || *p == LF) {"),
    ("value-end-no-lf", "all", "if (!IS_HEADER_CHAR(*p) || *p == CR || *p == LF) {", "if ((!IS_HEADER_CHAR(*p) && *p != LF) || *p == CR) {"),
    ("value-end-neon-nibble", "neon", "      return p + (__builtin_ctzll(bits) >> 2);\n    }\n    p += 16;\n  }\n#elif defined(HTTP_PARSER_SSE2)\n  const __m128i us", "      return p + (__builtin_ctzll(bits) >> 3);\n    }\n    p += 16;\n  }\n#elif defined(HTTP_PARSER_SSE2)\n  const __m128i us"),
    ("value-end-not-found", "all", "  r = scan_value_end(p, p + limit);\n  return r == p + limit ? data + len : r;", "  r = scan_value_end(p, p + limit);\n  return r;"),
    ("value-end-strict-uses-crlf", "all", "p = lenient ? find_crlf(p, data, len) : find_value_end(p, data, len);", "p = find_crlf(p, data, len);"),
    ("value-end-neon-no-ctl", "neon", "vorrq_u8(vbicq_u8(vcltq_u8(v, sp), vceqq_u8(v, ht)), vceqq_u8(v, del))", "vorrq_u8(vceqq_u8(v, vdupq_n_u8(CR)), vceqq_u8(v, vdupq_n_u8(LF)))"),
    ("value-end-neon-takes-del", "neon", "vorrq_u8(vbicq_u8(vcltq_u8(v, sp), vceqq_u8(v, ht)), vceqq_u8(v, del))", "vbicq_u8(vcltq_u8(v, sp), vceqq_u8(v, ht))"),
    ("value-end-sse2-no-ctl", "sse2", "const __m128i ctl = _mm_cmpeq_epi8(_mm_min_epu8(v, us), v);", "const __m128i ctl = _mm_or_si128(_mm_cmpeq_epi8(v, _mm_set1_epi8(CR)), _mm_cmpeq_epi8(v, _mm_set1_epi8(LF)));"),
    ("value-end-sse2-takes-del", "sse2", "_mm_andnot_si128(_mm_cmpeq_epi8(v, ht), ctl), _mm_cmpeq_epi8(v, del)));", "_mm_andnot_si128(_mm_cmpeq_epi8(v, ht), ctl), _mm_setzero_si128()));"),
    ("value-end-neon-overread", "neon+san", "  while (end - p >= 16) {\n    const uint8x16_t v = vld1q_u8((const uint8_t*) p);\n    const uint8x16_t m = vorrq_u8(vbicq_u8", "  while (end - p > 0) {\n    const uint8x16_t v = vld1q_u8((const uint8_t*) p);\n    const uint8x16_t m = vorrq_u8(vbicq_u8"),
    ("value-end-sse2-overread", "sse2+san", "  while (end - p >= 16) {\n    const __m128i v = _mm_loadu_si128((const __m128i*) p);\n    /* v <= 0x1f", "  while (end - p > 0) {\n    const __m128i v = _mm_loadu_si128((const __m128i*) p);\n    /* v <= 0x1f"),
    # each hardening check (unless lenient), taken out: test/diff.cc's hardening sweep must fail
    ("harden-value-first-byte", "all", "        if (!lenient && !IS_HEADER_CHAR(ch)) {\n          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);\n          goto error;\n        }\n\n        MARK(header_value);", "        MARK(header_value);"),
    ("harden-lf-in-value", "all", "            if (!lenient) {\n              parser->header_state = h_state;\n              SET_ERRNO(HPE_CR_EXPECTED);", "            if (false) {\n              parser->header_state = h_state;\n              SET_ERRNO(HPE_CR_EXPECTED);"),
    ("harden-lf-empty-value", "all", "          if (!lenient) {\n            SET_ERRNO(HPE_CR_EXPECTED);\n            goto error;\n          }\n          UPDATE_STATE(s_header_value_discard_lws);", "          UPDATE_STATE(s_header_value_discard_lws);"),
    ("harden-lf-headers-end", "all", "          if (!lenient) {\n            SET_ERRNO(HPE_CR_EXPECTED);\n            goto error;\n          }\n          UPDATE_STATE(s_headers_almost_done);", "          UPDATE_STATE(s_headers_almost_done);"),
    ("harden-lf-request-line", "all", "          if (!lenient) {\n            SET_ERRNO(HPE_CR_EXPECTED);\n            goto error;\n          }\n          UPDATE_STATE(s_header_field_start);\n          break;\n        }\n\n        /* XXX", "          UPDATE_STATE(s_header_field_start);\n          break;\n        }\n\n        /* XXX"),
    ("harden-lf-http09", "all", "          case LF:\n            if (!lenient) {", "          case LF:\n            if (false) {"),
    ("harden-lf-status", "all", "          if (!lenient) {\n            SET_ERRNO(HPE_CR_EXPECTED);\n            goto error;\n          }\n          UPDATE_STATE(s_header_field_start);\n          CALLBACK_DATA(status);", "          UPDATE_STATE(s_header_field_start);\n          CALLBACK_DATA(status);"),
    ("harden-fold", "all", "          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */\n          if (!lenient) {\n            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);\n            goto error;\n          }\n          UPDATE_STATE(s_header_value_start);", "          UPDATE_STATE(s_header_value_start);"),
    ("harden-fold-empty", "all", "          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */\n          if (!lenient) {\n            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);\n            goto error;\n          }\n          UPDATE_STATE(s_header_value_discard_ws);", "          UPDATE_STATE(s_header_value_discard_ws);"),
    ("harden-te-other", "all", "            if (!lenient && parser->type == HTTP_REQUEST) {\n              SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);\n              goto error;\n            }\n            break;\n          case h_connection_upgrade:", "            break;\n          case h_connection_upgrade:"),
    ("harden-te-twice", "all", "if (!lenient && parser->type == HTTP_REQUEST && (parser->flags & F_CHUNKED)) {", "if (false) {"),
    ("harden-te-empty", "all", "              /* Unless lenient, so is a request's empty Transfer-Encoding */\n              if (!lenient && parser->type == HTTP_REQUEST) {", "              /* Unless lenient, so is a request's empty Transfer-Encoding */\n              if (false) {"),
    ("harden-cl-ws", "all", "if (!lenient) h_state = h_content_length_ws;", ""),
    ("harden-cl-empty", "all", "              /* Unless lenient, an empty Content-Length is an error */\n              if (!lenient) {", "              /* Unless lenient, an empty Content-Length is an error */\n              if (false) {"),
    ("harden-chunk-space", "all", "if (ch == ';' || (ch == ' ' && lenient)) {", "if (ch == ';' || ch == ' ') {"),
    ("harden-chunk-ext", "all", "          if (!chunk_ext_char(parser, ch)) {", "          if (!chunk_ext_char(parser, ch) && false) {"),
    ("harden-chunk-ext-quoted", "all", "      return vchar || ch == ' ' || ch == '\\t';\n    case CHUNK_EXT_ESCAPE:", "      return vchar || ch == ' ' || ch == '\\t' || ch == CR;\n    case CHUNK_EXT_ESCAPE:"),
    ("harden-version-digits", "all", "        if unlikely(!IS_NUM(ch) || !lenient) {\n          SET_ERRNO(HPE_INVALID_VERSION);\n          goto error;\n        }\n\n        parser->http_major *= 10;", "        if unlikely(!IS_NUM(ch)) {\n          SET_ERRNO(HPE_INVALID_VERSION);\n          goto error;\n        }\n\n        parser->http_major *= 10;"),
    ("harden-version-known-req", "all", "        parser->http_minor = ch - '0';\n        /* Unless lenient: the version is complete, and must be a known one */\n        if (!lenient && !VERSION_KNOWN(parser)) {\n          SET_ERRNO(HPE_INVALID_VERSION);\n          goto error;\n        }\n        UPDATE_STATE(s_req_http_minor);", "        parser->http_minor = ch - '0';\n        UPDATE_STATE(s_req_http_minor);"),
    ("harden-http10-te-close", "all", "    if (!parser->lenient_http_headers && (parser->flags & F_CHUNKED) &&\n        parser->http_major < 2) {", "    if (false) {"),
    ("harden-http10-te-close-version", "all", "    if (!parser->lenient_http_headers && (parser->flags & F_CHUNKED) &&\n        parser->http_major < 2) {", "    if (!parser->lenient_http_headers && (parser->flags & F_CHUNKED) &&\n        parser->http_major < 1) {"),
    ("harden-version-known-res", "all", "        parser->http_minor = ch - '0';\n        /* Unless lenient: the version is complete, and must be a known one */\n        if (!lenient && !VERSION_KNOWN(parser)) {\n          SET_ERRNO(HPE_INVALID_VERSION);\n          goto error;\n        }\n        UPDATE_STATE(s_res_http_minor);", "        parser->http_minor = ch - '0';\n        UPDATE_STATE(s_res_http_minor);"),
    ("harden-version-fast-path", "all", "                (lenient || KNOWN_VERSION(p[5] - '0', p[7] - '0'))) {", "                true) {"),
]


def deps_includes(build):
    return ["-I" + d for d in sorted(glob.glob(os.path.join(build, "_deps", "*-src")))]


def run_mutant(m, args, tmp, base_objs, includes):
    name, where, old, new = m
    src = open(os.path.join(ROOT, "http_parser.cc")).read()
    if src.count(old) != 1:
        return name, "BAD", "snippet found %d times" % src.count(old)
    d = os.path.join(tmp, name)
    os.makedirs(d)
    cc = os.path.join(d, "http_parser.cc")
    open(cc, "w").write(src.replace(old, new))
    exe = os.path.join(d, "diff")
    cmd = ([args.cxx, "-std=c++20", "-O1", "-g", "-I" + ROOT, "-I" + os.path.join(ROOT, "test")] + includes +
           args.flags + [cc] + base_objs + ["-o", exe])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return name, "BAD", "does not compile:\n" + r.stderr[-1500:]
    try:
        r = subprocess.run([exe, "300"], capture_output=True, text=True, timeout=args.timeout,
                           env=dict(os.environ, HTTP_PARSER_DIFF_STOP="1"))
    except subprocess.TimeoutExpired:
        return name, "KILLED", "timeout"
    out = (r.stdout + r.stderr).strip().splitlines()
    why = next((l for l in out if "MISMATCH" in l or "HARDENING" in l or "ERROR: AddressSanitizer" in l or "runtime error" in l), "exit %d" % r.returncode)
    return name, ("KILLED" if r.returncode != 0 else "SURVIVED"), why[:150]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("build")
    ap.add_argument("--cxx", default="c++")
    ap.add_argument("--sanitize", default="")
    ap.add_argument("--cxxflags", default="")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("-j", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()
    args.flags = args.cxxflags.split()
    if args.sanitize:
        args.flags += ["-fsanitize=" + args.sanitize, "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    includes = deps_includes(args.build)
    arch = platform.machine().lower()
    simd = "NO_SIMD" not in args.cxxflags
    strict = "HTTP_PARSER_STRICT=0" not in args.cxxflags
    san = bool(args.sanitize)
    have = {"all": True, "san": san, "neon": simd and arch in ("arm64", "aarch64"), "sse2": simd and arch in ("x86_64", "amd64")}
    for k in ("neon", "sse2"):
        have[k + "_strict"] = have[k] and strict
        have[k + "+san"] = have[k] and san
        have[k + "_strict+san"] = have[k] and strict and san

    tmp = tempfile.mkdtemp(prefix="hp-mutants-")
    try:
        base = []
        for f in ("test/diff.cc", "test/http_parser_old.cc"):
            o = os.path.join(tmp, os.path.basename(f) + ".o")
            cmd = [args.cxx, "-std=c++20", "-O1", "-g", "-c", "-I" + ROOT, "-I" + os.path.join(ROOT, "test")] + includes + args.flags + [os.path.join(ROOT, f), "-o", o]
            subprocess.run(cmd, check=True)
            base.append(o)
        todo = [m for m in MUTANTS if (not args.only or m[0] in args.only) and have[m[1]]]
        skipped = [m[0] for m in MUTANTS if not have[m[1]]]
        bad = 0
        with concurrent.futures.ThreadPoolExecutor(args.j) as ex:
            for name, verdict, why in ex.map(lambda m: run_mutant(m, args, tmp, base, includes), todo):
                print("%-28s %-8s %s" % (name, verdict, why), flush=True)
                if verdict != "KILLED":
                    bad += 1
        if skipped:
            print("skipped (not compiled here): " + ", ".join(skipped))
        print("%d mutants, %d not killed" % (len(todo), bad))
        return 1 if bad else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
