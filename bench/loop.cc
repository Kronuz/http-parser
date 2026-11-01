// Runs one workload N times through one parser, for callgrind (instructions per message) or perf.
//
//   loop ARM WORKLOAD N      ARM: new, old or llhttp; WORKLOAD: small, browser, headers64, chunked, response, post
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "http_parser.h"
#include "http_parser_old.h"
#include "bench_shared.h"

template <size_t (*Exec)(http_parser*, const http_parser_settings*, const char*, size_t),
	void (*Init)(http_parser*, enum http_parser_type), void (*SInit)(http_parser_settings*)>
static bool run_hp(const char* data, size_t n, size_t chunk, bool response, Stats& st) {
	http_parser_settings s;
	SInit(&s);
	s.on_message_begin = on_begin<http_parser>; s.on_url = on_url<http_parser>; s.on_header_field = on_field<http_parser>;
	s.on_header_value = on_value<http_parser>; s.on_headers_complete = on_hdone<http_parser>; s.on_body = on_body<http_parser>;
	http_parser p;
	Init(&p, response ? HTTP_RESPONSE : HTTP_REQUEST);
	p.data = &st;
	(void) chunk;
	return Exec(&p, &s, data, n) == n;
}

int main(int argc, char** argv) {
	if (argc < 4) { fprintf(stderr, "usage: loop new|old|llhttp small|browser|headers64|chunked|response|post N\n"); return 2; }
	std::string arm = argv[1], w = argv[2];
	long n = atol(argv[3]);
	std::string data;
	bool response = false;
	if (w == "small") data = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4\r\nAccept: */*\r\n\r\n";
	else if (w == "browser") data = "GET /search?q=kronuz&lang=en HTTP/1.1\r\nHost: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n"
		"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n"
		"Cookie: session=abcdef0123456789abcdef0123456789; theme=dark; tracking=1234567890abcdef\r\n"
		"Referer: https://www.example.com/previous/page?with=query\r\nUpgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\n\r\n";
	else if (w == "headers64") {
		data = "GET / HTTP/1.1\r\nHost: h\r\n";
		for (int i = 0; i < 64; ++i) data += "X-Custom-Header-" + std::to_string(i) + ": value-number-" + std::to_string(i * 7919) + "\r\n";
		data += "\r\n";
	} else if (w == "chunked") {
		data = "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
		for (int i = 0; i < 16; ++i) data += "100\r\n" + std::string(256, 'z') + "\r\n";
		data += "0\r\n\r\n";
	} else if (w == "response") {
		response = true;
		data = "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n"
			"ETag: \"34aa387-d-1568eb00\"\r\nAccept-Ranges: bytes\r\nContent-Length: 51\r\nVary: Accept-Encoding\r\nContent-Type: text/plain\r\n\r\n"
			"Hello World! My payload includes a trailing CRLF.\r\n";
	} else if (w == "post") data = "POST /api/v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n" + std::string(1024, 'x');
	else { fprintf(stderr, "unknown workload\n"); return 2; }

	Stats st;
	bool ok = true;
	for (long i = 0; i < n; ++i) {
		if (arm == "new") ok &= run_hp<http_parser_execute, http_parser_init, http_parser_settings_init>(data.data(), data.size(), 0, response, st);
		else if (arm == "old") ok &= run_hp<http_parser_old_execute, http_parser_old_init, http_parser_old_settings_init>(data.data(), data.size(), 0, response, st);
#ifdef HAVE_LLHTTP
		else if (arm == "llhttp") ok &= run_llhttp(data.data(), data.size(), 0, response, st);
#endif
		else { fprintf(stderr, "unknown arm\n"); return 2; }
	}
	printf("%s %s: %ld messages, ok=%d, %llu url bytes, %llu value bytes\n", arm.c_str(), w.c_str(), n, (int) ok,
		(unsigned long long) st.url_bytes, (unsigned long long) st.value_bytes);
	return ok ? 0 : 1;
}
