// Smoke test for the standalone http-parser library.
//
// Drives raw HTTP/1.x request bytes through the callback-based parser and
// asserts the parsed method, URL, header fields/values, and body. Covers a
// simple GET, a POST with headers and a body, an incremental feed (the same
// request split byte by byte across http_parser_execute() calls, since the
// parser is streaming), and a malformed request (bad method) that sets
// http_errno. http_method_str() and http_errno_name() are checked too.
//
// Build via CMake: cmake -B build && cmake --build build && ctest --test-dir build
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "http_parser.h"


// ---------------------------------------------------------------------------
// A tiny collector that accumulates everything the parser reports. The data
// callbacks (on_url, on_header_field, on_header_value, on_body) can fire in
// several pieces for one logical value, so we append rather than assign and
// "close" a header field/value pair when the next field starts.
// ---------------------------------------------------------------------------

struct Collected {
	std::string url;
	std::string body;
	std::vector<std::pair<std::string, std::string>> headers;
	bool message_complete = false;
	bool headers_complete = false;

	// Track which half of a header pair we are currently building.
	bool reading_value = false;
};

static int on_url(http_parser* p, const char* at, size_t length) {
	auto* c = static_cast<Collected*>(p->data);
	c->url.append(at, length);
	return 0;
}

static int on_header_field(http_parser* p, const char* at, size_t length) {
	auto* c = static_cast<Collected*>(p->data);
	// A field after a value means the previous pair is done: start a new one.
	if (c->reading_value || c->headers.empty()) {
		c->headers.emplace_back(std::string(), std::string());
		c->reading_value = false;
	}
	c->headers.back().first.append(at, length);
	return 0;
}

static int on_header_value(http_parser* p, const char* at, size_t length) {
	auto* c = static_cast<Collected*>(p->data);
	c->reading_value = true;
	c->headers.back().second.append(at, length);
	return 0;
}

static int on_headers_complete(http_parser* p) {
	static_cast<Collected*>(p->data)->headers_complete = true;
	return 0;
}

static int on_body(http_parser* p, const char* at, size_t length) {
	static_cast<Collected*>(p->data)->body.append(at, length);
	return 0;
}

static int on_message_complete(http_parser* p) {
	static_cast<Collected*>(p->data)->message_complete = true;
	return 0;
}

static http_parser_settings make_settings() {
	http_parser_settings s;
	http_parser_settings_init(&s);
	s.on_url = on_url;
	s.on_header_field = on_header_field;
	s.on_header_value = on_header_value;
	s.on_headers_complete = on_headers_complete;
	s.on_body = on_body;
	s.on_message_complete = on_message_complete;
	return s;
}

// Look a header up case-sensitively (the values we test are exact).
static const std::string* find_header(const Collected& c, const std::string& name) {
	for (const auto& kv : c.headers) {
		if (kv.first == name) {
			return &kv.second;
		}
	}
	return nullptr;
}


// ---------------------------------------------------------------------------
// A simple GET with no body. Method, path, and a couple of headers come back.
// ---------------------------------------------------------------------------

static void test_simple_get() {
	const char* raw =
		"GET /index.html?q=1 HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: test/1.0\r\n"
		"\r\n";

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;

	http_parser_settings settings = make_settings();
	size_t len = std::strlen(raw);
	size_t parsed = http_parser_execute(&parser, &settings, raw, len);

	assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
	assert(parsed == len);
	assert(parser.method == HTTP_GET);
	assert(std::strcmp(http_method_str((enum http_method)parser.method), "GET") == 0);
	assert(c.url == "/index.html?q=1");
	assert(parser.http_major == 1 && parser.http_minor == 1);
	assert(c.headers_complete && c.message_complete);
	assert(c.body.empty());

	const std::string* host = find_header(c, "Host");
	assert(host && *host == "example.com");
	const std::string* ua = find_header(c, "User-Agent");
	assert(ua && *ua == "test/1.0");

	std::printf("http_parser simple GET OK: method, path, headers, no body\n");
}


// ---------------------------------------------------------------------------
// A POST with a Content-Length body. The body bytes arrive via on_body.
// ---------------------------------------------------------------------------

static void test_post_with_body() {
	const char* body = "{\"name\":\"kronuz\"}";
	std::string raw =
		"POST /submit HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: " + std::to_string(std::strlen(body)) + "\r\n"
		"\r\n" + body;

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;

	http_parser_settings settings = make_settings();
	size_t parsed = http_parser_execute(&parser, &settings, raw.data(), raw.size());

	assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
	assert(parsed == raw.size());
	assert(parser.method == HTTP_POST);
	assert(c.url == "/submit");
	assert(c.headers_complete && c.message_complete);
	assert(c.body == body);

	const std::string* ctype = find_header(c, "Content-Type");
	assert(ctype && *ctype == "application/json");
	const std::string* clen = find_header(c, "Content-Length");
	assert(clen && *clen == std::to_string(std::strlen(body)));
	// content_length tracks bytes still expected; the full body arrived, so it
	// has been counted down to zero by message-complete.
	assert(parser.content_length == 0);

	std::printf("http_parser POST OK: method, path, headers, JSON body\n");
}


// ---------------------------------------------------------------------------
// The parser is streaming: feed the exact same POST one byte at a time across
// many http_parser_execute() calls and get the identical parse. This is the
// "split across chunks" case for an incremental parser.
// ---------------------------------------------------------------------------

static void test_incremental_byte_by_byte() {
	std::string raw =
		"PUT /resource/42 HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"hello";

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;

	http_parser_settings settings = make_settings();

	// Feed one byte per call. The parser keeps its state across calls.
	for (size_t i = 0; i < raw.size(); ++i) {
		size_t parsed = http_parser_execute(&parser, &settings, raw.data() + i, 1);
		assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
		assert(parsed == 1);
	}

	assert(parser.method == HTTP_PUT);
	assert(c.url == "/resource/42");
	assert(c.headers_complete && c.message_complete);
	assert(c.body == "hello");
	const std::string* host = find_header(c, "Host");
	assert(host && *host == "example.com");

	std::printf("http_parser incremental OK: byte-by-byte feed parses identically\n");
}


// ---------------------------------------------------------------------------
// A chunked transfer-encoded body assembled across two buffers. The chunk
// sizes are hex; the parser reassembles the body and reports message complete
// after the terminating zero-length chunk.
// ---------------------------------------------------------------------------

static void test_chunked_across_buffers() {
	// "Wiki" + "pedia" in two chunks, then the 0 terminator.
	const char* part1 =
		"POST /upload HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n"
		"4\r\nWiki\r\n";
	const char* part2 =
		"5\r\npedia\r\n"
		"0\r\n\r\n";

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;

	http_parser_settings settings = make_settings();

	size_t len1 = std::strlen(part1);
	size_t p1 = http_parser_execute(&parser, &settings, part1, len1);
	assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
	assert(p1 == len1);
	assert(c.headers_complete);
	assert(!c.message_complete);  // body not done yet

	size_t len2 = std::strlen(part2);
	size_t p2 = http_parser_execute(&parser, &settings, part2, len2);
	assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
	assert(p2 == len2);

	assert(c.message_complete);
	assert(c.body == "Wikipedia");

	std::printf("http_parser chunked OK: two-buffer chunked body reassembles\n");
}


// ---------------------------------------------------------------------------
// A malformed request: an invalid method token. The parser stops and sets
// http_errno; the consumed count is short of the input.
// ---------------------------------------------------------------------------

static void test_malformed_request() {
	// A space inside the method (and an otherwise plausible line) is invalid.
	const char* raw = "G@T / HTTP/1.1\r\n\r\n";

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;

	http_parser_settings settings = make_settings();
	size_t len = std::strlen(raw);
	size_t parsed = http_parser_execute(&parser, &settings, raw, len);

	enum http_errno err = HTTP_PARSER_ERRNO(&parser);
	assert(err != HPE_OK);
	assert(err == HPE_INVALID_METHOD);
	// It halted before consuming the whole input.
	assert(parsed < len);
	assert(!c.message_complete);
	// The error name is reportable (the table prefixes the HPE_ token name).
	assert(std::strcmp(http_errno_name(err), "HPE_INVALID_METHOD") == 0);

	std::printf("http_parser malformed OK: bad method -> HPE_INVALID_METHOD, parser halts\n");
}


// ---------------------------------------------------------------------------
// Keep-alive: HTTP/1.1 without Connection: close should keep the connection
// alive after the message; HTTP/1.0 without keep-alive should not.
// ---------------------------------------------------------------------------

static void test_keep_alive() {
	{
		const char* raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
		http_parser parser;
		http_parser_init(&parser, HTTP_REQUEST);
		Collected c;
		parser.data = &c;
		http_parser_settings settings = make_settings();
		http_parser_execute(&parser, &settings, raw, std::strlen(raw));
		assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
		assert(http_should_keep_alive(&parser) != 0);
	}
	{
		const char* raw = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
		http_parser parser;
		http_parser_init(&parser, HTTP_REQUEST);
		Collected c;
		parser.data = &c;
		http_parser_settings settings = make_settings();
		http_parser_execute(&parser, &settings, raw, std::strlen(raw));
		assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
		assert(http_should_keep_alive(&parser) == 0);
	}
	std::printf("http_parser keep-alive OK: HTTP/1.1 persists, HTTP/1.0 closes\n");
}


// ---------------------------------------------------------------------------
// Header-value scan at the exact end of a heap buffer. The header-value parser
// fast-forwards through the value with find_crlf(); feeding a request in a
// buffer sized to the byte exactly (no trailing NUL, no slack) puts an ASAN
// redzone immediately after the last byte, so any read past data+len in that
// scan is caught. Guards the find_crlf out-of-bounds regression.
// ---------------------------------------------------------------------------

static void test_header_scan_at_buffer_end() {
	// A long header value so the value scan spans several words, with the
	// terminating CRLF (and the final blank line) landing at the buffer end.
	std::string req =
		"GET /x HTTP/1.1\r\n"
		"X-Long: ";
	req.append(64, 'a');
	req += "\r\n\r\n";

	char* buf = new char[req.size()];  // exact size: ASAN poisons right after
	std::memcpy(buf, req.data(), req.size());

	http_parser parser;
	http_parser_init(&parser, HTTP_REQUEST);
	Collected c;
	parser.data = &c;
	http_parser_settings settings = make_settings();
	size_t parsed = http_parser_execute(&parser, &settings, buf, req.size());

	assert(HTTP_PARSER_ERRNO(&parser) == HPE_OK);
	assert(parsed == req.size());
	assert(c.headers_complete && c.message_complete);
	const std::string* v = find_header(c, "X-Long");
	assert(v && *v == std::string(64, 'a'));

	delete[] buf;
	std::printf("http_parser header scan at buffer end OK: no over-read past data+len\n");
}


int main() {
	test_simple_get();
	test_post_with_body();
	test_incremental_byte_by_byte();
	test_chunked_across_buffers();
	test_malformed_request();
	test_keep_alive();
	test_header_scan_at_buffer_end();
	std::printf("all http-parser tests passed\n");
	return 0;
}
