// A/B benchmark: the live http_parser_execute() against the frozen reference
// (test/http_parser_old.cc), with llhttp as an optional extra column (-DHAVE_LLHTTP,
// link -lllhttp). Every workload runs the arms interleaved: trial after trial, each
// arm in turn, so drift on the machine hits every arm alike. "old#2" is the same
// code as "old" (the A/A row): the gap between the two is the noise floor, and a
// difference smaller than it is not a result.
//
//   c++ -std=c++20 -O3 -DNDEBUG -mcpu=native -I. -Itest -I<enum-reflection> \
//       bench/bench.cc http_parser.cc test/http_parser_old.cc [-DHAVE_LLHTTP -lllhttp] -o bench
//   run it under `quiet strict`.
//
// Usage: bench [trials] [target_ms] [workload-substring]
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "http_parser.h"
#include "http_parser_old.h"
#include "bench_shared.h"

namespace {

struct Impl {
	const char* name;
	bool (*run)(const char* data, size_t n, size_t chunk, bool response, Stats& st);
};

template <size_t (*Exec)(http_parser*, const http_parser_settings*, const char*, size_t),
	void (*Init)(http_parser*, enum http_parser_type), void (*SInit)(http_parser_settings*)>
bool run_hp(const char* data, size_t n, size_t chunk, bool response, Stats& st) {
	http_parser_settings s;
	SInit(&s);
	s.on_message_begin = on_begin<http_parser>; s.on_url = on_url<http_parser>; s.on_header_field = on_field<http_parser>;
	s.on_header_value = on_value<http_parser>; s.on_headers_complete = on_hdone<http_parser>; s.on_body = on_body<http_parser>;
	http_parser p;
	Init(&p, response ? HTTP_RESPONSE : HTTP_REQUEST);
	p.data = &st;
	if (!chunk) chunk = n;
	for (size_t off = 0; off < n; off += chunk) {
		size_t len = n - off < chunk ? n - off : chunk;
		if (Exec(&p, &s, data + off, len) != len) return false;
	}
	return true;
}

struct W {
	const char* name;
	std::string data;
	size_t chunk;
	bool response;
};

template <typename F> inline void use(const F& v) { asm volatile("" : : "r,m"(v) : "memory"); }

double time_ns(const Impl& im, const W& w, uint64_t n) {
	const char* d = w.data.data();
	size_t len = w.data.size();
	auto t0 = std::chrono::steady_clock::now();
	for (uint64_t i = 0; i < n; ++i) {
		Stats s;
		im.run(d, len, w.chunk, w.response, s);
		use(s);
	}
	return std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / double(n);
}

}  // namespace

int main(int argc, char** argv) {
	int trials = argc > 1 ? atoi(argv[1]) : 15;
	double target_ms = argc > 2 ? atof(argv[2]) : 30;
	const char* only = argc > 3 ? argv[3] : nullptr;

	std::vector<Impl> impls = {
		{ "old", run_hp<http_parser_old_execute, http_parser_old_init, http_parser_old_settings_init> },
		{ "new", run_hp<http_parser_execute, http_parser_init, http_parser_settings_init> },
		{ "old#2", run_hp<http_parser_old_execute, http_parser_old_init, http_parser_old_settings_init> },
#ifdef HAVE_LLHTTP
		{ "llhttp", run_llhttp },
#endif
	};

	std::string small = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4\r\nAccept: */*\r\n\r\n";
	std::string browser = "GET /search?q=kronuz&lang=en HTTP/1.1\r\nHost: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n"
		"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n"
		"Cookie: session=abcdef0123456789abcdef0123456789; theme=dark; tracking=1234567890abcdef\r\n"
		"Referer: https://www.example.com/previous/page?with=query\r\nUpgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\n\r\n";
	std::string post = "POST /api/v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n" + std::string(1024, 'x');
	std::string bigpost = "POST /upload HTTP/1.1\r\nHost: up.example.com\r\nContent-Length: 65536\r\n\r\n" + std::string(65536, 'y');
	std::string chunked = "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
	for (int i = 0; i < 16; ++i) chunked += "100\r\n" + std::string(256, 'z') + "\r\n";
	chunked += "0\r\n\r\n";
	std::string manyhdr = "GET / HTTP/1.1\r\nHost: h\r\n";
	for (int i = 0; i < 64; ++i) manyhdr += "X-Custom-Header-" + std::to_string(i) + ": value-number-" + std::to_string(i * 7919) + "\r\n";
	manyhdr += "\r\n";
	std::string pipelined;
	for (int i = 0; i < 32; ++i) pipelined += small;
	std::string response = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n"
		"ETag: \"34aa387-d-1568eb00\"\r\nAccept-Ranges: bytes\r\nContent-Length: 51\r\nVary: Accept-Encoding\r\nContent-Type: text/plain\r\n\r\n"
		"Hello World! My payload includes a trailing CRLF.\r\n";
	std::string longurl = "GET /static/assets/images/products/2024/summer/collection/item-123456789.jpg?width=640&height=480&quality=85&format=webp HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
	std::string reqline = "GET /index.html HTTP/1.1\r\n\r\n";
	std::string onehdr = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
	std::string longhdr = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n\r\n";

	std::vector<W> ws = {
		{ "small GET (3 hdr)", small, 0, false },
		{ "browser GET (14 hdr)", browser, 0, false },
		{ "64 custom headers", manyhdr, 0, false },
		{ "POST 1KB body", post, 0, false },
		{ "POST 64KB body", bigpost, 0, false },
		{ "chunked 16x256B", chunked, 0, false },
		{ "32 pipelined small GET", pipelined, 0, false },
		{ "browser GET, 64B segments", browser, 64, false },
		{ "response 200 (8 hdr)", response, 0, true },
		{ "request line only", reqline, 0, false },
		{ "1 short header", onehdr, 0, false },
		{ "1 long header (117B)", longhdr, 0, false },
		{ "long URL (125B)", longurl, 0, false },
	};

	printf("%-28s", "workload (ns/msg)");
	for (auto& im : impls) printf(" %9s", im.name);
	printf("  new/old  old#2/old  ");
#ifdef HAVE_LLHTTP
	printf("llhttp/new  ");
#endif
	printf("spread(max of arms)\n");

	for (auto& w : ws) {
		if (only && !strstr(w.name, only)) continue;
		// Identity check before timing: every arm must report the same parse statistics.
		Stats ref;
		bool ok = impls[0].run(w.data.data(), w.data.size(), w.chunk, w.response, ref);
		for (auto& im : impls) {
			Stats s;
			bool o = im.run(w.data.data(), w.data.size(), w.chunk, w.response, s);
			if (!o || !ok || !(s == ref)) { printf("MISMATCH %s on %s\n", im.name, w.name); ok = false; }
		}
		if (!ok) continue;

		// Calibrate the iteration count per arm to about target_ms.
		std::vector<uint64_t> n(impls.size());
		for (size_t a = 0; a < impls.size(); ++a) {
			uint64_t k = 1;
			for (;;) {
				double t = time_ns(impls[a], w, k) * double(k) / 1e6;
				if (t >= target_ms / 4 || k > (1ull << 30)) { n[a] = std::max<uint64_t>(1, uint64_t(double(k) * target_ms / std::max(t, 0.001))); break; }
				k *= 4;
			}
		}
		std::vector<std::vector<double>> v(impls.size());
		for (int t = 0; t < trials; ++t)
			for (size_t a = 0; a < impls.size(); ++a) v[a].push_back(time_ns(impls[a], w, n[a]));
		std::vector<double> med(impls.size());
		double worst = 0;
		for (size_t a = 0; a < impls.size(); ++a) {
			std::sort(v[a].begin(), v[a].end());
			med[a] = v[a][v[a].size() / 2];
			worst = std::max(worst, (v[a].back() - v[a].front()) / med[a]);
		}
		printf("%-28s", w.name);
		for (size_t a = 0; a < impls.size(); ++a) printf(" %9.1f", med[a]);
		printf("  %6.2fx  %8.2fx  ", med[1] / med[0], med[2] / med[0]);
#ifdef HAVE_LLHTTP
		printf("%8.2fx  ", med[3] / med[1]);
#endif
		printf("%5.1f%%\n", worst * 100);
		fflush(stdout);
	}
}
