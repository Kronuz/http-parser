// A runnable tour of http-parser.
//
// Build (when this repo is the top-level project):
//   cmake -B build && cmake --build build && ./build/http_parser_demo
//
// The one idea worth taking away: http_parser is a streaming HTTP/1.x parser.
// You hand it raw bytes (as many or as few as you have) and it calls back into
// your code as it recognizes the method, the URL, each header field/value, the
// body, and message boundaries. It never buffers or allocates for you; the
// callbacks see slices of your own buffer.
#include <cstdio>
#include <cstring>
#include <string>

#include "http_parser.h"

static void rule(const char* title) {
	std::printf("\n\033[1m── %s ──\033[0m\n", title);
}

// Minimal collector wired to parser->data, like a real consumer would do.
struct Demo {
	std::string url;
	std::string body;
	std::string last_field;
	bool reading_value = false;
};

static int on_url(http_parser* p, const char* at, size_t n) {
	static_cast<Demo*>(p->data)->url.append(at, n);
	return 0;
}
static int on_header_field(http_parser* p, const char* at, size_t n) {
	auto* d = static_cast<Demo*>(p->data);
	if (d->reading_value) {
		d->last_field.clear();
		d->reading_value = false;
	}
	d->last_field.append(at, n);
	return 0;
}
static int on_header_value(http_parser* p, const char* at, size_t n) {
	auto* d = static_cast<Demo*>(p->data);
	d->reading_value = true;
	std::printf("  header  : %s: %.*s\n", d->last_field.c_str(), (int)n, at);
	return 0;
}
static int on_body(http_parser* p, const char* at, size_t n) {
	static_cast<Demo*>(p->data)->body.append(at, n);
	return 0;
}

int main() {
	std::puts("http-parser demo");

	// --- 1. parse a request and watch the callbacks fire ---------------------
	rule("a raw request becomes method / url / headers / body via callbacks");
	const char* raw =
		"POST /search?q=kronuz HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: 13\r\n"
		"\r\n"
		"{\"ok\":true}\r\n";

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Demo d;
	parser.data = &d;

	http_parser_settings settings;
	http_parser_settings_init(&settings);
	settings.on_url = on_url;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
	settings.on_body = on_body;

	http_parser_execute(&parser, &settings, raw, std::strlen(raw));

	std::printf("  method  : %s\n", http_method_str((enum http_method)parser.method));
	std::printf("  url     : %s\n", d.url.c_str());
	std::printf("  version : HTTP/%u.%u\n", parser.http_major, parser.http_minor);
	std::printf("  body    : %s\n", d.body.c_str());
	std::printf("  keep-alive: %s\n", http_should_keep_alive(&parser) ? "yes" : "no");

	// --- 2. the parser is streaming: feed it one byte at a time --------------
	rule("streaming: the same request fed byte by byte parses identically");
	http_parser p2;
	http_parser_init(&p2, HTTP_REQUEST);
	Demo d2;
	p2.data = &d2;
	http_parser_settings s2;
	http_parser_settings_init(&s2);
	s2.on_url = on_url;
	s2.on_body = on_body;
	const char* req = "GET /a/b/c HTTP/1.1\r\nHost: x\r\n\r\n";
	for (size_t i = 0, len = std::strlen(req); i < len; ++i) {
		http_parser_execute(&p2, &s2, req + i, 1);
	}
	std::printf("  method  : %s\n", http_method_str((enum http_method)p2.method));
	std::printf("  url     : %s\n", d2.url.c_str());

	// --- 3. a malformed request sets http_errno ------------------------------
	rule("a bad request stops the parser and reports an errno");
	http_parser p3;
	http_parser_init(&p3, HTTP_REQUEST);
	http_parser_settings s3;
	http_parser_settings_init(&s3);
	const char* bad = "G@T / HTTP/1.1\r\n\r\n";
	http_parser_execute(&p3, &s3, bad, std::strlen(bad));
	enum http_errno err = HTTP_PARSER_ERRNO(&p3);
	std::printf("  errno   : %s (%s)\n", http_errno_name(err), http_errno_description(err));

	std::puts("\ndone.");
	return 0;
}
