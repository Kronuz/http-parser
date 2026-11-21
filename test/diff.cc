// Differential test: the live http_parser_execute() against the frozen reference
// (test/http_parser_old.cc, a verbatim copy of http_parser.cc from before the
// header-scan change).
//
// Both parsers are driven by the same callbacks over the same bytes, split the
// same way. For every callback and every return of http_parser_execute() the
// test records the callback kind, the bytes and their offset in the buffer the
// parser was given, and a snapshot of every field of struct http_parser. The
// two event lists must be identical, so the callback fragmentation, the
// parser's return values, the error number and the parser's private counters
// (nread, index, header_state, flags, ...) all agree.
//
// Inputs: a hand-written corpus (all methods, URL forms, header kinds, chunked
// bodies, responses, pipelining, the 80 KB header limit), every prefix of it,
// every byte substitution / insertion / deletion at every position, callbacks
// that fail or pause at every event, a sweep of header values around the SIMD
// block boundaries, and random grammar-built messages with random mutations.
//
// Usage: http_parser_diff [rounds]   (rounds scales the random section, default 20000)
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <strings.h>

#include "http_parser.h"
#include "http_parser_old.h"

namespace {
#include "diff_harness.inc"
#include "diff_corpus.inc"
#include "diff_random.inc"
}  // namespace

#include "diff_harden.inc"

int main(int argc, char** argv) {
	long rounds = argc > 1 ? atol(argv[1]) : 20000;
	auto seeds = corpus();
	limit_cases([&](const std::string& name, const std::string& bytes, enum http_parser_type t) { seeds.push_back({ name, bytes, t }); });

	const std::vector<std::vector<size_t>> plans = { {}, { 1 }, { 3 }, { 7 }, { 16 }, { 17 }, { 64 }, { 4096 } };
	Mode dflt;

	// 1. Every seed, every plan, every parser type, every mode.
	for (const Seed& s : seeds) {
		bool big = s.bytes.size() > 4000;
		for (auto t : { s.type, HTTP_BOTH }) {
			for (const auto& plan : plans) {
				if (big && !plan.empty() && plan[0] < 64) continue;  // byte-by-byte over 80 KB: oneshot and 4096 only (below)
				Mode m;
				for (int hc : { 0, 1, 2 })
					for (bool eof : { false, true }) { m = dflt; m.hc_ret = hc; m.eof = eof; check(s.name, t, s.bytes, plan, m); }
				for (unsigned mask : { 0u, (1u << URL) | (1u << FIELD) | (1u << VALUE) | (1u << BODY) | (1u << STATUS), (1u << MSG_BEGIN) | (1u << MSG_DONE) | (1u << HDRS_DONE) }) {
					m = dflt; m.mask = mask; check(s.name + " mask", t, s.bytes, plan, m);
				}
			}
			if (big && t == s.type) { Mode m = dflt; check(s.name + " [1]", t, s.bytes, { 1 }, m); }
		}
	}
	printf("corpus: %zu seeds, %ld checks, %ld failures\n", seeds.size(), checks, failures);

	// 2. Every prefix of every small seed (the input ends mid-token), with and without EOF.
	for (const Seed& s : seeds) {
		if (s.bytes.size() > 4000) continue;
		for (size_t n = 0; n <= s.bytes.size(); ++n) {
			std::string cut = s.bytes.substr(0, n);
			Mode m = dflt;
			m.eof = true;
			check(s.name + " prefix", s.type, cut, {}, m);
			check(s.name + " prefix", s.type, cut, { 5 }, m);
		}
	}
	printf("prefixes: %ld checks, %ld failures\n", checks, failures);

	// 3. Every callback fails or pauses, one at a time, under two plans.
	for (const Seed& s : seeds) {
		if (s.bytes.size() > 4000) continue;
		for (int k = 0; k < 70; ++k)
			for (const auto& plan : { std::vector<size_t>{}, std::vector<size_t>{ 5 } }) {
				Mode m = dflt;
				m.fail_at = k; check(s.name + " fail", s.type, s.bytes, plan, m);
				m = dflt; m.pause_at = k; check(s.name + " pause", s.type, s.bytes, plan, m);
			}
	}
	printf("fail/pause: %ld checks, %ld failures\n", checks, failures);

	// 4. Single-byte substitutions, insertions and deletions at every position of every small seed.
	for (const Seed& s : seeds) {
		if (s.bytes.size() > 4000) continue;
		for (size_t i = 0; i < s.bytes.size(); ++i) {
			std::string d = s.bytes; d.erase(i, 1);
			check(s.name + " delete", s.type, d, {}, dflt);
			for (char b : interesting) {
				std::string sub = s.bytes; sub[i] = b;
				check(s.name + " subst", s.type, sub, {}, dflt);
				if ((i + (unsigned char) b) % 5 == 0) check(s.name + " subst", s.type, sub, random_plan(9), dflt);
				if ((i + (unsigned char) b) % 3 == 0) {
					std::string ins = s.bytes; ins.insert(ins.begin() + i, b);
					check(s.name + " insert", s.type, ins, {}, dflt);
				}
			}
		}
	}
	printf("mutations: %ld checks, %ld failures\n", checks, failures);

	// 5. Header values around the block boundaries of the scanner: every value length, every special byte at every
	// position, every alignment of the value start, with the buffer ending inside and right after the value.
	{
		const char specials[] = { '\r', '\n', 0, '\t', '\x7f', '\x80', ',', ' ', ':', '\0' };
		for (size_t shift = 0; shift < 18; ++shift) {
			std::string head = "GET / HTTP/1.1\r\n" + std::string(shift ? shift : 1, 'n') + ": ";
			for (size_t len = 0; len <= 70; ++len) {
				std::string value(len, 'v');
				for (size_t j = 0; j <= len; ++j) {
					for (char sp : specials) {
						std::string v = value; v.insert(v.begin() + j, sp);
						check("value-sweep", HTTP_REQUEST, head + v + "\r\n\r\n", {}, dflt);
					}
					if (len < 3 || j % 3 == 0) {
						Mode m = dflt; m.eof = true;
						check("value-cut", HTTP_REQUEST, (head + value).substr(0, head.size() + j), {}, m);
					}
				}
				check("value-sweep", HTTP_REQUEST, head + value + "\r\n\r\n", {}, dflt);
				check("value-sweep-lf", HTTP_REQUEST, head + value + "\n\n", {}, dflt);
				check("value-sweep-split", HTTP_REQUEST, head + value + "\r\n\r\n", { head.size() + len / 2 }, dflt);
				check("value-sweep-conn", HTTP_REQUEST, "GET / HTTP/1.1\r\nConnection: " + value + "\r\n\r\n", {}, dflt);
			}
		}
	}
	printf("value sweep: %ld checks, %ld failures\n", checks, failures);

	// 5b. URL runs: every byte value at every position of a URL, in the path, query and fragment states, with the
	// buffer ending inside the URL, at its end and after it. The vector scan must agree with the byte table for all 256.
	{
		const char* prefixes[] = { "/", "/a?", "/a?b#", "/a#", "http://h/p", "http://h", "*", "/%41" };
		for (const char* prefix : prefixes) {
			for (size_t len = 0; len <= 40; ++len) {
				std::string run(len, 'u');
				for (size_t j = 0; j <= len; ++j) {
					if (len > 8 && j % 5 != 0 && j != len && j != 15 && j != 16 && j != 17 && j != 31 && j != 32 && j != 33) continue;
					for (int c = 0; c < 256; ++c) {
						std::string url = std::string(prefix) + run;
						url.insert(url.begin() + (std::string(prefix).size() + j), (char) c);
						check("url-sweep", HTTP_REQUEST, "GET " + url + " HTTP/1.1\r\n\r\n", {}, dflt);
					}
				}
				check("url-sweep", HTTP_REQUEST, "GET " + std::string(prefix) + run + " HTTP/1.1\r\n\r\n", {}, dflt);
				Mode m = dflt; m.eof = true;
				check("url-cut", HTTP_REQUEST, "GET " + std::string(prefix) + run, {}, m);
				check("url-cut", HTTP_REQUEST, "GET " + std::string(prefix) + run, { 3 }, m);
				check("url-split", HTTP_REQUEST, "GET " + std::string(prefix) + run + " HTTP/1.1\r\n\r\n", { 4 + std::string(prefix).size() + len / 2 }, dflt);
			}
		}
	}
	printf("url sweep: %ld checks, %ld failures\n", checks, failures);

	// 5c. The end of the request line: every byte at every position of " HTTP/d.d\r\n", for several versions, and the
	// buffer ending at every position of it.
	{
		for (const char* ver : { "HTTP/1.1", "HTTP/1.0", "HTTP/9.9", "HTTP/0.9", "HTTP/2.0", "HTTP/1.10", "HTTP/12.3", "HTTP/1.", "HTTP/" }) {
			for (const char* eol : { "\r\n", "\n", "\r\r\n", "\r" }) {
				std::string tail = std::string(" ") + ver + eol + "Host: h\r\n\r\n";
				for (size_t i = 0; i < tail.size(); ++i) {
					for (int c = 0; c < 256; ++c) {
						std::string t = tail; t[i] = (char) c;
						check("version-sweep", HTTP_REQUEST, "GET /x" + t, {}, dflt);
					}
					Mode m = dflt; m.eof = true;
					check("version-cut", HTTP_REQUEST, "GET /x" + tail.substr(0, i), {}, m);
					check("version-split", HTTP_REQUEST, "GET /x" + tail, { 6 + i }, dflt);
				}
			}
		}
	}
	printf("version sweep: %ld checks, %ld failures\n", checks, failures);

	// 5d. The end of a header line: a value, CR, then every pair of following bytes.
	{
		for (const char* value : { "v", "value", "keep-alive", "close" }) {
			for (const char* name : { "X", "Connection", "Content-Length", "Transfer-Encoding", "Upgrade" }) {
				for (int x = 0; x < 256; ++x) {
					for (int y = 0; y < 256; y += (x == '\n' || x == '\r') ? 1 : 51) {
						std::string in = std::string("GET / HTTP/1.1\r\n") + name + ": " + (std::strcmp(name, "Content-Length") == 0 ? "5" : value) + "\r";
						in += (char) x; in += (char) y; in += "Z: 1\r\n\r\n";
						check("line-end-sweep", HTTP_REQUEST, in, {}, dflt);
					}
				}
			}
		}
	}
	printf("line-end sweep: %ld checks, %ld failures\n", checks, failures);

	// 5e. Chunk framing: every byte value at every position of a chunked body (size lines with and without
	// extensions, data, the CRLF after it, the last chunk and a trailer), the buffer ending at every position, and
	// the buffer cut in two at every position.
	{
		for (const char* eol : { "\r\n", "\n" }) {
			const std::string e = eol;
			const std::string head = "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
			const std::string frames = "5;e=1" + e + "hello\r\n" + "10" + e + "0123456789abcdef\r\n" + "A" + e + "0123456789\r\n" + "0" + e + "T: v\r\n\r\n";
			for (size_t i = 0; i < frames.size(); ++i) {
				for (int c = 0; c < 256; ++c) {
					std::string f = frames; f[i] = (char) c;
					check("chunk-sweep", HTTP_REQUEST, head + f, {}, dflt);
					if (c % 17 == 0) check("chunk-sweep", HTTP_REQUEST, head + f, { 1 }, dflt);
				}
				Mode m = dflt; m.eof = true;
				check("chunk-cut", HTTP_REQUEST, head + frames.substr(0, i), {}, m);
				check("chunk-split", HTTP_REQUEST, head + frames, { head.size() + i }, dflt);
				check("chunk-split-pause", HTTP_REQUEST, head + frames, { head.size() + i }, [&] { Mode p = dflt; p.pause_at = 3 + (int) (i % 12); return p; }());
			}
		}
	}
	printf("chunk sweep: %ld checks, %ld failures\n", checks, failures);

	// 5f. Header names the matcher knows (Connection, Proxy-Connection, Content-Length, Transfer-Encoding, Upgrade), which
	// it takes in runs: every byte value at every position of each name in several letter cases, a name followed by more
	// token bytes, the buffer cut at every position of the name, and each with the values the matcher acts on.
	{
		const char* names[] = { "Connection", "connection", "CONNECTION", "Proxy-Connection", "proxy-connection", "Content-Length", "CONTENT-LENGTH",
			"content-length", "Transfer-Encoding", "transfer-encoding", "Upgrade", "UPGRADE", "Content-Type", "Cookie", "Connectionx",
			"Content-Lengthx", "Upgradex", "Transfer-Encodingx", "Proxy-Connectionx", "Con", "Content-", "Transfer-", "Proxy-", "Upgrad" };
		const char* values[] = { ": keep-alive, Upgrade", ": 5", ": chunked", ": websocket", ": close", "" };
		for (const char* name : names) {
			const std::string nm = name;
			for (const char* value : values) {
				const std::string tail = std::string(value) + "\r\nX: y\r\n\r\n";
				const std::string head = "GET / HTTP/1.1\r\n";
				for (size_t i = 0; i < nm.size(); ++i) {
					for (int c = 0; c < 256; ++c) {
						std::string n = nm;
						n[i] = (char) c;
						check("name-sweep", HTTP_REQUEST, head + n + tail, {}, dflt);
					}
				}
				for (size_t cut = 1; cut <= nm.size() + 2; ++cut) check("name-split", HTTP_REQUEST, head + nm + tail, { head.size() + cut }, dflt);
				check("name-bytes", HTTP_REQUEST, head + nm + tail, { 1 }, dflt);
				Mode m = dflt;
				m.eof = true;
				for (size_t cut = 0; cut <= nm.size(); ++cut) check("name-cut", HTTP_REQUEST, (head + nm).substr(0, head.size() + cut), {}, m);
			}
		}
	}
	printf("name sweep: %ld checks, %ld failures\n", checks, failures);

	// 6. Hardening: what the parser rejects unless lenient_http_headers is set, each case in
	// one call, byte by byte and cut in two at every position (the old parser accepts all of
	// these, so the comparison above cannot tell a missing rejection).
	{
		const char* req = "GET / HTTP/1.1\r\n";
		auto hdr = [&](const std::string& h) { return std::string(req) + h + "\r\n\r\n"; };
		auto chunked = [&](const std::string& size_line) {
			return std::string("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n") + size_line + "\r\nhello\r\n0\r\n\r\n";
		};
		// Control bytes anywhere in a value, around the 16-byte blocks of the scan.
		const char ctl[] = { 0, 1, 8, 11, 12, 14, 31, 127 };
		for (size_t n = 1; n <= 40; ++n)
			for (size_t at = 0; at < n; ++at)
				for (char c : ctl) {
					std::string v(n, 'v');
					v[at] = c;
					harden(t_req, hdr("X: " + v), HPE_INVALID_HEADER_TOKEN, at < 3 || at + 3 > n);
				}
		for (size_t n = 1; n <= 40; ++n) harden(t_req, hdr("X: " + std::string(n, 'v') + "\tz\x80\xff"), HPE_OK, false);
		// A bare LF ends no line.
		harden(t_req, "GET / HTTP/1.1\nHost: x\r\n\r\n", HPE_CR_EXPECTED);
		harden(t_req, "GET /\n", HPE_CR_EXPECTED);
		harden(t_req, hdr("X: a\nContent-Length: 5"), HPE_CR_EXPECTED);
		harden(t_req, hdr("X:\nContent-Length: 5"), HPE_CR_EXPECTED);
		harden(t_req, std::string(req) + "X: a\r\n\n", HPE_CR_EXPECTED);
		harden(t_req, std::string(req) + "X: a\n\r\n", HPE_CR_EXPECTED);
		harden(t_res, "HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", HPE_CR_EXPECTED);
		harden(t_res, "HTTP/1.1 200\nContent-Length: 0\r\n\r\n", HPE_CR_EXPECTED);
		harden(t_res, "HTTP/1.1 200 \nContent-Length: 0\r\n\r\n", HPE_CR_EXPECTED);
		// obs-fold.
		harden(t_req, hdr("X: a\r\n b"), HPE_INVALID_HEADER_TOKEN);
		harden(t_req, hdr("X: a\r\n\tb"), HPE_INVALID_HEADER_TOKEN);
		harden(t_req, hdr("X:\r\n b"), HPE_INVALID_HEADER_TOKEN);
		harden(t_req, hdr("Foo: bar\r\n Content-Length: 38"), HPE_INVALID_HEADER_TOKEN);
		// Transfer-Encoding in a request: "chunked", once.
		for (const char* te : { "gzip", "identity", "gzip, chunked", "chunked, gzip", "chunk", "chunkedx", "chunked\t", "chunked ,", "chunkedchunked", "" })
			harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: " + std::string(te) + "\r\n\r\n0\r\n\r\n", HPE_INVALID_TRANSFER_ENCODING);
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", HPE_INVALID_TRANSFER_ENCODING);
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n", HPE_INVALID_TRANSFER_ENCODING);
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nhello", HPE_INVALID_TRANSFER_ENCODING);
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: gzip\r\n\r\nhello", HPE_INVALID_TRANSFER_ENCODING);
		for (const char* te : { "chunked", "Chunked", "CHUNKED  " })
			harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: " + std::string(te) + "\r\n\r\n0\r\n\r\n", HPE_OK);
		harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody", HPE_OK);  // read until EOF, as before
		// Content-Length: digits, then only spaces.
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n" + std::string(42, 'x'), HPE_INVALID_CONTENT_LENGTH);
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length: 13 37\r\n\r\n", HPE_INVALID_CONTENT_LENGTH);
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length:\r\n\r\n", HPE_INVALID_CONTENT_LENGTH);
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length: \r\n\r\n", HPE_INVALID_CONTENT_LENGTH);
		harden(t_req, "POST / HTTP/1.1\r\nContent-Length: 5  \r\n\r\nhello", HPE_OK);
		// The chunk size line: ';' and well-formed extensions only.
		for (const char* line : { "5 ", "5 ;a", "5 a", "5 a=b", "5;", "5;;a", "5;=b", "5;a=", "5;a=\"x", "5;a=\"x\\", "5;a b", "5;a\nb", "5;a=b\nc",
				"5;a\x01", "5;a=\"x\x7f\"", "5;a=\"x\"y", "5;a=b=c", "5\t" })
			harden(t_req, chunked(line), HPE_INVALID_CHUNK_SIZE);
		for (const char* line : { "5", "5;a", "5;a=b", "5;a;b=c", "5;a=\"x y\\\"z\\\\\"", "5;a=\"\t\x80\"", "5;a=\"\";b" })
			harden(t_req, chunked(line), HPE_OK);
		// Versions: one digit each, and 0.9, 1.0, 1.1 or 2.0.
		for (const char* v : { "1.2", "3.0", "9.9", "11.1", "1.10", "1.01", "2.1" }) {
			harden(t_req, "GET / HTTP/" + std::string(v) + "\r\n\r\n", HPE_INVALID_VERSION);
			harden(t_res, "HTTP/" + std::string(v) + " 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_INVALID_VERSION);
		}
		harden(t_res, "HTTP/01.1 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_INVALID_VERSION);
		// At the second digit of the major version, not at the minor one after it.
		harden(t_req, "GET / HTTP/11.1\r\n\r\n", HPE_INVALID_VERSION, true, 12);
		harden(t_res, "HTTP/11.1 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_INVALID_VERSION, true, 6);
		for (const char* v : { "1.0", "1.1", "2.0" }) {
			harden(t_req, "GET / HTTP/" + std::string(v) + "\r\n\r\n", HPE_OK);
			harden(t_res, "HTTP/" + std::string(v) + " 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_OK);
		}
		harden(t_res, "HTTP/0.9 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_OK);
		// No Content-Length in a trailer section (an empty one is an empty Content-Length).
		for (const char* cl : { "30", "0", "5" }) {
			harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nContent-Length: " + std::string(cl) + "\r\n\r\n",
				HPE_INVALID_CONTENT_LENGTH, true, 76);
			harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: y\r\ncontent-length: " + std::string(cl) + "\r\n\r\n",
				HPE_INVALID_CONTENT_LENGTH, true, 72);
		}
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Lengthx: 5\r\nExpires: 0\r\n\r\n", HPE_OK);
		// The status line: one space, three digits.
		for (const char* line : { "HTTP/1.1  200 OK", "HTTP/1.1 2 OK", "HTTP/1.1 20 OK", "HTTP/1.1 099 OK", "HTTP/1.1 20\r", "HTTP/1.1 \t200 OK" })
			harden(t_res, std::string(line) + "\r\nContent-Length: 0\r\n\r\n", HPE_INVALID_STATUS);
		for (const char* line : { "HTTP/1.1 200 OK", "HTTP/1.1 200", "HTTP/1.1 100 Continue", "HTTP/1.1 999 X" })
			harden(t_res, std::string(line) + "\r\nContent-Length: 0\r\n\r\n", HPE_OK);
		// A response's Transfer-Encoding: not empty, and no coding after chunked.
		harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello", HPE_INVALID_TRANSFER_ENCODING);
		harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\n\r\nhello", HPE_INVALID_TRANSFER_ENCODING);
		for (const char* te : { "identity", "gzip", "chunked, gzip", "chunk" })
			harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: " + std::string(te) + "\r\n\r\n0\r\n\r\n",
				HPE_INVALID_TRANSFER_ENCODING);
		harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", HPE_OK);
		harden(t_res, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nuntil EOF", HPE_OK);
		// Nor a Transfer-Encoding with a Content-Length, in either order and whatever the status:
		// read by the length, the rest of the body would be the next response (RFC 9112 section
		// 6.3). The error is at the LF that ends the header section, as for chunked.
		const std::string next_res = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext";
		for (const char* te : { "gzip", "identity", "gzip, chunked", "chunked, gzip", "x", "chunked" })
			for (const char* status : { "200 OK", "204 No Content", "101 Switching Protocols" }) {
				const std::string te_line = "Transfer-Encoding: " + std::string(te) + "\r\n", cl_line = "Content-Length: 5\r\n";
				for (const std::string& head : { "HTTP/1.1 " + std::string(status) + "\r\n" + te_line + cl_line + "\r\n",
						"HTTP/1.1 " + std::string(status) + "\r\n" + cl_line + "X: y\r\n" + te_line + "\r\n" })
					harden(t_res, head + "hello" + next_res, HPE_UNEXPECTED_CONTENT_LENGTH, true, (long) head.size() - 1);
			}
		harden(HTTP_BOTH, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello", HPE_UNEXPECTED_CONTENT_LENGTH,
			true, 62);
		// A field that is not Transfer-Encoding does not count, nor one from the message before.
		for (const char* name : { "Transfer-Encodingx", "X-Transfer-Encoding", "Transfer-Encodin" })
			harden(t_res, "HTTP/1.1 200 OK\r\n" + std::string(name) + ": gzip\r\nContent-Length: 5\r\n\r\nhello" + next_res, HPE_OK, true, -1, 2);
		harden(t_res, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n" + next_res, HPE_OK, true, -1, 2);
		harden(HTTP_BOTH, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n" + next_res, HPE_OK, true, -1, 2);
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nok", HPE_OK, true,
			-1, 2);
		// A 1xx, 204 or 304 response has no body, whatever framing it names; the next response
		// starts right after its header section. Only a 101 is an upgrade.
		for (const char* status : { "100 Continue", "103 Early Hints", "204 No Content", "304 Not Modified" })
			for (const char* framing : { "Content-Length: 10", "Transfer-Encoding: chunked", "Content-Length: 0", "X: y" }) {
				const std::string head = "HTTP/1.1 " + std::string(status) + "\r\n" + framing + "\r\n\r\n";
				harden(t_res, head + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", HPE_OK, true, -1, 2);
			}
		for (const char* framing : { "Content-Length: 4", "Transfer-Encoding: chunked", "X: y" }) {
			const std::string head = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n" + std::string(framing) + "\r\n\r\n";
			harden(t_res, head + "bodyproto", HPE_OK, true, (long) head.size(), 1, 1);
		}
		for (const char* framing : { "Content-Length: 4\r\n", "Transfer-Encoding: chunked\r\n", "" }) {
			const std::string body = framing[0] == 'T' ? "4\r\nbody\r\n0\r\n\r\n" : "body";
			harden(t_res, "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\n" + std::string(framing) + "\r\n" + body, HPE_OK, true, -1, 1, 0);
		}
		// A request line has a version: HTTP/0.9 requests have none, nor headers, so a header
		// section after such a line is not HTTP/0.9's (and HTTP/0.x is an error at the 0).
		harden(t_req, "GET /\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello", HPE_INVALID_VERSION, true, 5);
		harden(t_req, "GET /x?y\r\n\r\n", HPE_INVALID_VERSION, true, 8);
		harden(t_req, "GET / HTTP/0.9\r\nContent-Length: 0\r\n\r\n", HPE_INVALID_VERSION, true, 11);
#if HTTP_PARSER_STRICT
		// Transfer-Encoding before HTTP/1.1: the message is read, then the connection closes
		// (RFC 9112 section 6.1), whatever Connection says. (A non-strict build reads on after
		// any message; http_should_keep_alive() is 0 there, test/test.cc.)
		const std::string next = "GET /admin HTTP/1.1\r\nHost: a\r\n\r\n";
		for (const char* line : { "POST / HTTP/1.0", "POST / HTTP/1.0\r\nConnection: keep-alive" }) {
			const std::string msg = std::string(line) + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
			harden(t_req, msg + next, HPE_CLOSED_CONNECTION, true, (long) msg.size());
		}
		harden(t_res, "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", HPE_CLOSED_CONNECTION, true, 76);
		harden(t_req, "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" + next, HPE_OK);
		harden(t_req, "POST / HTTP/1.0\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello" + next, HPE_OK);
#endif
	}
	printf("hardening: %ld checks, %ld failures\n", checks, failures);

	// 7. Random messages, random mutations, random splits.
	for (long i = 0; i < rounds; ++i) {
		bool request = rnd(4) != 0;
		std::string msg = random_message(request);
		if (rnd(3) == 0) msg += random_message(request);
		if (rnd(2) == 0) msg = mutate(msg);
		Mode m = dflt;
		m.hc_ret = rnd(8) == 0 ? (int) rnd(3) : 0;
		m.eof = rnd(2);
		if (rnd(6) == 0) m.fail_at = (int) rnd(30);
		if (rnd(6) == 0) m.pause_at = (int) rnd(30);
		enum http_parser_type t = request ? HTTP_REQUEST : HTTP_RESPONSE;
		if (rnd(5) == 0) t = HTTP_BOTH;
		check("random", t, msg, rnd(3) == 0 ? std::vector<size_t>{} : random_plan(rnd(2) ? 8 : 80), m);
	}
	printf("random: %ld checks, %ld failures\n", checks, failures);

	for (const auto& c : changed) {
		printf("changed on purpose, %s: %ld differences\n", c.first, c.second);
		// A rule the inputs above never reach is not tested (a non-strict build never
		// refuses the bytes after a message).
		if (c.second == 0 && (HTTP_PARSER_STRICT || std::strcmp(c.first, "http10-te-close") != 0)) {
			printf("FAILED: no input reaches %s\n", c.first);
			++failures;
		}
	}
	printf("%s: %ld checks, %ld failures\n", failures ? "FAILED" : "all http-parser differential checks passed", checks, failures);
	return failures ? 1 : 0;
}
