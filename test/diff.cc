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

struct Snap {
	unsigned type, flags, state, header_state, index, lenient;
	uint32_t nread;
	uint64_t content_length;
	unsigned http_major, http_minor, status_code, method, http_errno, upgrade;
	bool operator==(const Snap& o) const {
		return type == o.type && flags == o.flags && state == o.state && header_state == o.header_state &&
			index == o.index && lenient == o.lenient && nread == o.nread && content_length == o.content_length &&
			http_major == o.http_major && http_minor == o.http_minor && status_code == o.status_code &&
			method == o.method && http_errno == o.http_errno && upgrade == o.upgrade;
	}
};

Snap snap(const http_parser* p) {
	Snap s;
	s.type = p->type; s.flags = p->flags; s.state = p->state; s.header_state = p->header_state;
	s.index = p->index; s.lenient = p->lenient_http_headers; s.nread = p->nread;
	s.content_length = p->content_length; s.http_major = p->http_major; s.http_minor = p->http_minor;
	s.status_code = p->status_code; s.method = p->method; s.http_errno = p->http_errno; s.upgrade = p->upgrade;
	return s;
}

enum Kind { MSG_BEGIN, URL, STATUS, FIELD, VALUE, HDRS_DONE, BODY, MSG_DONE, CHUNK_HDR, CHUNK_DONE, RET };
const char* kind_name[] = { "message_begin", "url", "status", "header_field", "header_value", "headers_complete",
	"body", "message_complete", "chunk_header", "chunk_complete", "execute_returned" };

struct Event {
	Kind kind;
	std::string data;  // callback bytes
	long off = -1;     // offset of the bytes in the buffer given to execute(); the return value for RET
	Snap snap;
};

struct Mode {
	int hc_ret = 0;      // value on_headers_complete returns (0, 1, 2)
	int fail_at = -1;    // the callback with this ordinal fails
	int pause_at = -1;   // the callback with this ordinal pauses the parser
	unsigned mask = ~0u; // bit k set: callback of Kind k is installed
	bool eof = false;    // call execute(.., 0) after the input
};

struct Impl {
	void (*init)(http_parser*, enum http_parser_type);
	size_t (*exec)(http_parser*, const http_parser_settings*, const char*, size_t);
	void (*pause)(http_parser*, int);
};

const Impl live = { http_parser_init, http_parser_execute, http_parser_pause };
const Impl old = { http_parser_old_init, http_parser_old_execute, http_parser_old_pause };

struct Ctx {
	std::vector<Event>* ev;
	Mode mode;
	int count = 0;
	const char* base = nullptr;
	void (*pause)(http_parser*, int) = nullptr;
};

int note(http_parser* p, Kind k, const char* at, size_t n) {
	Ctx* c = static_cast<Ctx*>(p->data);
	Event e;
	e.kind = k;
	if (at) { e.data.assign(at, n); e.off = at - c->base; }
	e.snap = snap(p);
	c->ev->push_back(std::move(e));
	int ord = c->count++;
	if (ord == c->mode.fail_at) return k == HDRS_DONE ? 3 : 1;
	if (ord == c->mode.pause_at) { c->pause(p, 1); return 0; }
	if (k == HDRS_DONE) return c->mode.hc_ret;
	return 0;
}

int cb_begin(http_parser* p) { return note(p, MSG_BEGIN, nullptr, 0); }
int cb_url(http_parser* p, const char* a, size_t n) { return note(p, URL, a, n); }
int cb_status(http_parser* p, const char* a, size_t n) { return note(p, STATUS, a, n); }
int cb_field(http_parser* p, const char* a, size_t n) { return note(p, FIELD, a, n); }
int cb_value(http_parser* p, const char* a, size_t n) { return note(p, VALUE, a, n); }
int cb_hdone(http_parser* p) { return note(p, HDRS_DONE, nullptr, 0); }
int cb_body(http_parser* p, const char* a, size_t n) { return note(p, BODY, a, n); }
int cb_done(http_parser* p) { return note(p, MSG_DONE, nullptr, 0); }
int cb_chdr(http_parser* p) { return note(p, CHUNK_HDR, nullptr, 0); }
int cb_cdone(http_parser* p) { return note(p, CHUNK_DONE, nullptr, 0); }

// Feeds `in` in chunks of `plan` sizes (cycled; empty plan = one call), each chunk in its own
// exactly-sized heap block so a read past the end is visible to AddressSanitizer.
void drive(const Impl& im, enum http_parser_type t, const std::string& in, const std::vector<size_t>& plan,
	const Mode& m, std::vector<Event>& out, bool lenient) {
	http_parser_settings s;
	memset(&s, 0, sizeof s);
	auto on = [&](Kind k) { return (m.mask >> k) & 1u; };
	if (on(MSG_BEGIN)) s.on_message_begin = cb_begin;
	if (on(URL)) s.on_url = cb_url;
	if (on(STATUS)) s.on_status = cb_status;
	if (on(FIELD)) s.on_header_field = cb_field;
	if (on(VALUE)) s.on_header_value = cb_value;
	if (on(HDRS_DONE)) s.on_headers_complete = cb_hdone;
	if (on(BODY)) s.on_body = cb_body;
	if (on(MSG_DONE)) s.on_message_complete = cb_done;
	if (on(CHUNK_HDR)) s.on_chunk_header = cb_chdr;
	if (on(CHUNK_DONE)) s.on_chunk_complete = cb_cdone;

	Ctx ctx;
	ctx.ev = &out; ctx.mode = m; ctx.pause = im.pause;
	http_parser p;
	memset(&p, 0, sizeof p);
	im.init(&p, t);
	p.data = &ctx;
	p.lenient_http_headers = lenient;

	auto record_ret = [&](size_t n) {
		Event e; e.kind = RET; e.off = (long) n; e.snap = snap(&p);
		out.push_back(std::move(e));
	};

	size_t pos = 0, pi = 0;
	bool stop = false;
	while (pos < in.size() && !stop) {
		size_t want = plan.empty() ? in.size() - pos : std::min(plan[pi++ % plan.size()], in.size() - pos);
		if (want == 0) want = 1;
		std::unique_ptr<char[]> buf(new char[want]);
		memcpy(buf.get(), in.data() + pos, want);
		size_t done = 0;
		for (int guard = 0; done < want && guard < 100000; ++guard) {
			ctx.base = buf.get() + done;
			size_t n = im.exec(&p, &s, ctx.base, want - done);
			record_ret(n);
			done += n;
			if (HTTP_PARSER_ERRNO(&p) == HPE_PAUSED) { im.pause(&p, 0); continue; }
			if (HTTP_PARSER_ERRNO(&p) != HPE_OK || p.upgrade || n == 0) { stop = true; break; }
		}
		pos += want;
	}
	if (m.eof && !stop) {
		char dummy = 0;
		ctx.base = &dummy;
		size_t n = im.exec(&p, &s, &dummy, 0);
		record_ret(n);
	}
}

std::string show(const std::string& s, size_t max = 160) {
	std::string r;
	for (size_t i = 0; i < s.size() && i < max; ++i) {
		unsigned char c = s[i];
		if (c == '\r') r += "\\r";
		else if (c == '\n') r += "\\n";
		else if (c == '\t') r += "\\t";
		else if (c >= 32 && c < 127 && c != '\\') r += (char) c;
		else { char b[8]; snprintf(b, sizeof b, "\\x%02x", c); r += b; }
	}
	if (s.size() > max) r += "...(" + std::to_string(s.size()) + " bytes)";
	return r;
}

std::string show(const Event& e) {
	char b[256];
	snprintf(b, sizeof b, "%s off=%ld st=%u hs=%u idx=%u fl=%u nread=%u cl=%llu errno=%u up=%u", kind_name[e.kind], e.off,
		e.snap.state, e.snap.header_state, e.snap.index, e.snap.flags, e.snap.nread,
		(unsigned long long) e.snap.content_length, e.snap.http_errno, e.snap.upgrade);
	return std::string(b) + " [" + show(e.data, 60) + "]";
}

long checks = 0, failures = 0;

// With lenient_http_headers unset the parser rejects what the frozen 2.7.1 parser
// let through (CHANGELOG.md, "Hardening"), and it may stop with one of these where
// the old parser went on.
bool hardening_errno(unsigned e) {
	return e == HPE_CR_EXPECTED || e == HPE_INVALID_HEADER_TOKEN || e == HPE_INVALID_TRANSFER_ENCODING ||
		e == HPE_INVALID_CONTENT_LENGTH || e == HPE_INVALID_CHUNK_SIZE || e == HPE_INVALID_VERSION || e == HPE_INVALID_STATUS;
}

// With lenient_http_headers unset, the inputs whose result changes on purpose beyond an early
// hardening error: given the first event at which the parsers differ, the rule that changes it
// (CHANGELOG.md, "Hardening"), or nullptr. Each rule's own cases, against its oracle, are in
// the hardening sweep (section 6); here only old != new is allowed, and only for these.
std::vector<std::pair<const char*, long>> changed = { { "http10-te-close", 0 }, { "response-upgrade-101", 0 }, { "response-no-body", 0 } };

const char* changed_class(const std::vector<Event>& a, const std::vector<Event>& b, size_t i) {
	const Snap* sa = i < a.size() ? &a[i].snap : nullptr;
	const Snap* sb = i < b.size() ? &b[i].snap : nullptr;
	if (sa && sa->type == HTTP_RESPONSE) {
		// RFC 9110 section 7.8: only a 101 switches protocols; the old parser took any
		// response with Upgrade and Connection: upgrade as an upgrade.
		if (sb && sa->status_code == sb->status_code && sa->upgrade && !sb->upgrade && sa->status_code != 101)
			return "response-upgrade-101";
		// RFC 9112 section 6.3: a 1xx, 204 or 304 response has no body; the old parser read
		// the one its Content-Length or Transfer-Encoding named. Either the old parser is in
		// that body, or the new one still holds the framing it did not read, or the bytes the
		// old parser took as that body are not a message and the new parser stops on them.
		auto no_body = [](unsigned st) { return st / 100 == 1 || st == 204 || st == 304; };
		const unsigned st = sa->status_code;
		const bool in_body = (sa->state >= s_chunk_size_start && sa->state <= s_chunk_size_almost_done) ||
			sa->state > s_headers_done || (sa->flags & (F_CHUNKED | F_TRAILING));
		const bool unread = sb && sb->type == HTTP_RESPONSE && sb->status_code == st &&
			((sb->flags & F_CHUNKED) || (sb->content_length > 0 && sb->content_length != ULLONG_MAX));
		if (no_body(st) && (in_body || unread)) return "response-no-body";
		if (sb && sb->type == HTTP_RESPONSE && no_body(sb->status_code) && i + 1 == b.size() && b[i].kind == RET &&
				sb->http_errno != HPE_OK && sb->http_errno != HPE_PAUSED)
			return "response-no-body";
	}
	if (i < b.size() && i + 1 == b.size() && b[i].kind == RET) {
		const Snap& s = b[i].snap;
		// RFC 9112 section 6.1: after an HTTP/1.0 message with Transfer-Encoding the connection
		// closes, and the next byte is an error where the old parser read another message.
		if (s.http_errno == HPE_CLOSED_CONNECTION && (s.flags & F_CHUNKED) && (s.flags & F_CONNECTION_KEEP_ALIVE) &&
				(s.http_major == 0 || (s.http_major == 1 && s.http_minor == 0)))
			return "http10-te-close";
	}
	return nullptr;
}

void count_changed(const char* name) {
	for (auto& c : changed)
		if (std::strcmp(c.first, name) == 0) ++c.second;
}

// What a consumer sees of the parser: the read-only fields and the flags.
bool public_equal(const Snap& a, const Snap& b) {
	return a.flags == b.flags && a.content_length == b.content_length && a.http_major == b.http_major &&
		a.http_minor == b.http_minor && a.status_code == b.status_code && a.method == b.method &&
		a.http_errno == b.http_errno && a.upgrade == b.upgrade;
}

// Runs both parsers; on a difference prints the first one and counts a failure. With
// HTTP_PARSER_DIFF_STOP set in the environment the first difference ends the run
// (tools/mutants.py does: a broken parser then fails in seconds).
//
// Each input runs twice. Lenient (lenient_http_headers set on both parsers): every event and
// every field equal. Strict (the default): the events and the public fields equal, except
// that the parser may stop early with a hardening error (hardening_errno).
bool check_mode(const std::string& what, enum http_parser_type t, const std::string& in, const std::vector<size_t>& plan, const Mode& m,
	bool lenient);

bool check(const std::string& what, enum http_parser_type t, const std::string& in, const std::vector<size_t>& plan, const Mode& m) {
	return check_mode(what, t, in, plan, m, true) && check_mode(what, t, in, plan, m, false);
}

bool check_mode(const std::string& what, enum http_parser_type t, const std::string& in, const std::vector<size_t>& plan, const Mode& m,
	bool lenient) {
	static const bool stop = getenv("HTTP_PARSER_DIFF_STOP") != nullptr;
	std::vector<Event> a, b;
	drive(old, t, in, plan, m, a, lenient);
	drive(live, t, in, plan, m, b, lenient);
	++checks;
	size_t n = std::min(a.size(), b.size()), i = 0;
	auto same = [&](const Event& x, const Event& y) {
		return x.kind == y.kind && x.data == y.data && x.off == y.off && (lenient ? x.snap == y.snap : public_equal(x.snap, y.snap));
	};
	while (i < n && same(a[i], b[i])) ++i;
	if (i == n && a.size() == b.size()) return true;
	if (!lenient && i + 1 == b.size() && b[i].kind == RET && hardening_errno(b[i].snap.http_errno)) return true;
	if (!lenient) {
		if (const char* name = changed_class(a, b, i)) {
			count_changed(name);
			return true;
		}
	}
	++failures;
	if (failures <= 10) {
		printf("MISMATCH %s%s type=%d plan=%s hc_ret=%d fail_at=%d pause_at=%d mask=%x eof=%d\n  input: %s\n", what.c_str(),
			lenient ? " [lenient]" : " [strict]", (int) t,
			plan.empty() ? "oneshot" : std::to_string(plan[0]).c_str(), m.hc_ret, m.fail_at, m.pause_at, m.mask, (int) m.eof, show(in).c_str());
		printf("  event %zu of old=%zu new=%zu\n", i, a.size(), b.size());
		if (i < a.size()) printf("  old: %s\n", show(a[i]).c_str());
		if (i < b.size()) printf("  new: %s\n", show(b[i]).c_str());
	}
	if (stop) {
		fflush(stdout);
		exit(1);
	}
	return false;
}

struct Seed {
	std::string name, bytes;
	enum http_parser_type type;
};

std::mt19937_64 rng(0x68747470);
size_t rnd(size_t n) { return n ? (size_t) (rng() % n) : 0; }

std::vector<size_t> random_plan(size_t max_chunk) {
	std::vector<size_t> p;
	for (int i = 0; i < 6; ++i) p.push_back(1 + rnd(max_chunk));
	return p;
}

const char interesting[] = { 0, '\t', '\n', '\r', ' ', ':', '/', '?', '#', '%', '@', ',', ';', '[', 'a', 'Z', '0', '9', '-', '\x7f', '\x80', '\xff' };

// ---------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------
#define LIT(s) std::string(s, sizeof(s) - 1)  // a literal that may hold NULs

std::vector<Seed> corpus() {
	std::vector<Seed> v;
	auto req = [&](const char* name, std::string s) { v.push_back({ name, std::move(s), HTTP_REQUEST }); };
	auto res = [&](const char* name, std::string s) { v.push_back({ name, std::move(s), HTTP_RESPONSE }); };

	const char* methods[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MOVE", "PATCH",
		"SEARCH", "UNLOCK", "PURGE", "LINK", "UNLINK", "COUNT", "DUMP", "FLUSH", "INFO", "QUIT", "RESTORE", "WAL", "CLOSE", "CHECK",
		"COMMIT", "OPEN", "UPDATE", "UPSERT", "BREW", "GE", "GETX", "" };
	for (const char* m : methods) req("method", std::string(m) + " /x?y=1 HTTP/1.1\r\nHost: h\r\n\r\n");

	req("small", "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4\r\nAccept: */*\r\n\r\n");
	req("browser", "GET /search?q=kronuz&lang=en HTTP/1.1\r\nHost: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n"
		"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n"
		"Cookie: session=abcdef0123456789abcdef0123456789; theme=dark; tracking=1234567890abcdef\r\n"
		"Referer: https://www.example.com/previous/page?with=query\r\nUpgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\n\r\n");
	req("post-cl", "POST /api/v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":[1,2]} ");
	req("post-cl-0", "POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("post-cl-dup", "POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc");
	req("post-cl-bad", "POST /x HTTP/1.1\r\nContent-Length: 3x\r\n\r\nabc");
	req("post-cl-sp", "POST /x HTTP/1.1\r\nContent-Length:   3  \r\n\r\nabc");
	req("post-cl-huge", "POST /x HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\nabc");
	req("post-cl-big", "POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\nabc");
	req("chunked", "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nTrailer: v\r\n\r\n");
	req("chunked-both", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
	req("chunked-gzip", "POST /c HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n");
	req("chunked-badsize", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n");
	req("chunked-bigsize", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\n");
	req("abs-uri", "GET http://user:pw@host:8080/p/a/t/h?query=string#hash HTTP/1.1\r\nHost: host\r\n\r\n");
	req("abs-uri-v6", "GET http://[::1]:80/x HTTP/1.1\r\n\r\n");
	req("abs-uri-at-at", "GET http://a@b@c/ HTTP/1.1\r\n\r\n");
	req("connect", "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n");
	req("connect-tail", "CONNECT a:1 HTTP/1.1\r\n\r\nrest of the stream");
	req("options-star", "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n");
	req("url-high", "GET /caf\xc3\xa9/\xe2\x82\xac?q=\xff HTTP/1.1\r\nHost: h\r\n\r\n");
	req("url-query-frag", "GET /a/b?x=1?y=2#frag?x#y HTTP/1.1\r\n\r\n");
	req("url-percent", "GET /a%20b%zz?c=%7e HTTP/1.1\r\n\r\n");
	req("url-bad", "GET /a b HTTP/1.1\r\n\r\n");
	req("url-tab", "GET /a\tb HTTP/1.1\r\n\r\n");
	req("url-ff", "GET /a\fb HTTP/1.1\r\n\r\n");
	req("url-nul", LIT("GET /a\0b HTTP/1.1\r\n\r\n"));
	req("url-spaces", "GET   /sp   HTTP/1.1\r\n\r\n");
	req("http09", "GET /\r\n");
	req("http09-lf", "GET /\n");
	req("http10", "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
	req("http10-plain", "GET / HTTP/1.0\r\n\r\nGET / HTTP/1.0\r\n\r\n");
	req("http11-close", "GET / HTTP/1.1\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("http-ver-bad", "GET / HTTP/x.1\r\n\r\n");
	req("http-ver-big", "GET / HTTP/1000.1\r\n\r\n");
	req("http-ver-multi", "GET / HTTP/12.34\r\n\r\n");
	req("http-ver-zero", "GET / HTTP/0.9\r\n\r\n");
	req("http-ver-lower", "GET / http/1.1\r\n\r\n");
	req("upgrade", "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nframes");
	req("upgrade-multi", "GET /ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nframes");
	req("conn-multi", "GET / HTTP/1.1\r\nConnection: foo, close, bar\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("conn-multi2", "GET / HTTP/1.1\r\nConnection: keep-alive , close\r\n\r\n");
	req("conn-case", "GET / HTTP/1.1\r\nCoNnEcTiOn: KeEp-AlIvE\r\nCONTENT-LENGTH: 2\r\n\r\nhi");
	req("conn-near", "GET / HTTP/1.1\r\nConnectio: close\r\nConnectionx: close\r\nConnection : close\r\nconnection:close\r\n\r\n");
	req("proxy-conn", "GET / HTTP/1.1\r\nProxy-Connection: close\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("proxy-near", "GET / HTTP/1.1\r\nProxy-Connectio: close\r\nProxy-Connectionx: 1\r\nProx: 1\r\n\r\n");
	req("te-near", "GET / HTTP/1.1\r\nTransfer-Encodin: chunked\r\nTransfer-Encodingx: chunked\r\nTransfer-Encoding: chunke\r\nTransfer-Encoding: chunkedx\r\n\r\n");
	req("upgrade-near", "GET / HTTP/1.1\r\nUpgrad: 1\r\nUpgradex: 1\r\nUpgrade : 1\r\nUpgrade:1\r\n\r\n");
	req("cl-near", "GET / HTTP/1.1\r\nContent-Lengt: 1\r\nContent-Lengthx: 1\r\nContent-Type: a\r\nCont: 1\r\nCo: 1\r\n\r\n");
	req("folded", "GET / HTTP/1.1\r\nX-A: one\r\n two\r\n\tthree\r\nX-B: b\r\n\r\n");
	req("folded-empty", "GET / HTTP/1.1\r\nX-A:\r\n  value\r\nX-B:\r\n\r\n");
	req("empty-values", "GET / HTTP/1.1\r\nX-Empty:\r\nX-Empty2: \r\nX-Empty3:\t\r\n\r\n");
	req("no-space", "GET / HTTP/1.1\r\nFoo:bar\r\nBaz:\tqux\r\n\r\n");
	req("trailing-ws", "GET / HTTP/1.1\r\nFoo: bar  \t \r\n\r\n");
	req("bare-lf", "GET / HTTP/1.1\nHost: x\nX: y\n\n");
	req("mixed-eol", "GET / HTTP/1.1\r\nHost: x\nX: y\r\n\n");
	req("bare-cr", "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n");
	req("bare-cr-end", "GET / HTTP/1.1\r\nHost: a\r\r\n\r\n");
	req("nul-value", LIT("GET / HTTP/1.1\r\nX: a\0b\r\n\r\n"));
	req("nul-value-first", LIT("GET / HTTP/1.1\r\nX: \0b\r\n\r\n"));
	req("ctl-value", "GET / HTTP/1.1\r\nX: a\x01\x1f\x7f z\r\n\r\n");
	req("ctl-value-first", "GET / HTTP/1.1\r\nX: \x01z\r\n\r\n");
	req("del-value-first", "GET / HTTP/1.1\r\nX: \x7fz\r\n\r\n");
	req("high-value", "GET / HTTP/1.1\r\nX: caf\xc3\xa9 \xff\xfe\r\n\r\n");
	req("tab-value", "GET / HTTP/1.1\r\nX: a\tb\tc\r\n\r\n");
	req("bad-name", "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n");
	req("bad-name2", "GET / HTTP/1.1\r\nBad(Name): x\r\n\r\n");
	req("name-no-colon", "GET / HTTP/1.1\r\nBadName\r\n\r\n");
	req("name-high", "GET / HTTP/1.1\r\nX\xc3\xa9: x\r\n\r\n");
	req("name-colon-first", "GET / HTTP/1.1\r\n: x\r\n\r\n");
	req("long-value-300", "GET / HTTP/1.1\r\nX: " + std::string(300, 'v') + "\r\nY: " + std::string(64, 'w') + "\r\n\r\n");
	req("pipelined", "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n\r\nGET /2 HTTP/1.1\r\nHost: b\r\n\r\n\nPOST /3 HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"
		"GET /4 HTTP/1.1\r\n\r\n");
	req("leading-crlf", "\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("empty", "");
	req("just-crlf", "\r\n");
	req("garbage", LIT("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"));
	req("req-or-res", "HEAD / HTTP/1.1\r\n\r\n");
	req("h-start", "H");

	res("res-200", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
	res("res-204", "HTTP/1.1 204 No Content\r\nX: y\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n");
	res("res-100", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
	res("res-eof", "HTTP/1.0 200 OK\r\nServer: x\r\n\r\nbody until the end of the stream");
	res("res-chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nExpires: never\r\n\r\n");
	res("res-close", "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 2\r\n\r\nno");
	res("res-nostatus-text", "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n");
	res("res-weird-text", "HTTP/1.1 200 O\xffK \t!\r\nContent-Length: 0\r\n\r\n");
	res("res-bad-status", "HTTP/1.1 2x0 OK\r\n\r\n");
	res("res-bad-version", "HTTP/1.x 200 OK\r\n\r\n");
	res("res-lf", "HTTP/1.1 200 OK\nContent-Length: 1\n\nx");
	res("res-upgrade", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nframes");
	res("res-304-cl", "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n");
	res("res-headers", "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n"
		"ETag: \"34aa387-d-1568eb00\"\r\nAccept-Ranges: bytes\r\nContent-Length: 51\r\nVary: Accept-Encoding\r\nContent-Type: text/plain\r\n\r\n"
		"Hello World! My payload includes a trailing CRLF.\r\n");
	// Framing a 1xx, 204 or 304 response does not have, and Upgrade outside a 101.
	res("res-101-cl", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbodyproto");
	res("res-304-te", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
	res("res-304-te-next", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
	res("res-200-upgrade", "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbody");
	// Transfer-Encoding before HTTP/1.1, then another message on the same connection.
	req("http10-te", "POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
		"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n");
	res("res-http10-te", "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
	return v;
}

// Requests built around the 80 KB header limit: the byte at which the parser gives up must agree.
void limit_cases(const std::function<void(const std::string&, const std::string&, enum http_parser_type)>& add) {
	const long L = HTTP_MAX_HEADER_SIZE;
	for (long d = -24; d <= 24; ++d) {
		add("limit-url", "GET /" + std::string(L - 15 + d, 'a') + " HTTP/1.1\r\n\r\n", HTTP_REQUEST);
		add("limit-value", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-big", "GET / HTTP/1.1\r\nX: " + std::string(L + 40 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-edge", "GET / HTTP/1.1\r\nX: " + std::string(L + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-bigcr", "GET / HTTP/1.1\r\nX: " + std::string(L + 40 + d, 'a') + "\r\nY: b\r\n\r\n", HTTP_REQUEST);
		add("limit-value-lws", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a') + "\r\n \r\n\r\n", HTTP_REQUEST);
		add("limit-name", "GET / HTTP/1.1\r\n" + std::string(L - 36 + d, 'a') + ": x\r\n\r\n", HTTP_REQUEST);
		add("limit-value-conn", "GET / HTTP/1.1\r\nConnection: " + std::string(L - 36 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-chunk-size", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + std::string(L - 3 + d, '0') + "5\r\nhello\r\n0\r\n\r\n", HTTP_REQUEST);
		add("limit-chunk-ext", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;" + std::string(L - 5 + d, 'e') + "\r\nhello\r\n0\r\n\r\n", HTTP_REQUEST);
		add("limit-value-noeol", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a'), HTTP_REQUEST);
		std::string many = "GET / HTTP/1.1\r\n";
		while ((long) many.size() < L - 20 + d) many += "X-Header: 0123456789012345678901234567890123456789\r\n";
		add("limit-many", many + "\r\n", HTTP_REQUEST);
		add("limit-status", "HTTP/1.1 200 " + std::string(L - 20 + d, 'a') + "\r\n\r\n", HTTP_RESPONSE);
	}
}

// ---------------------------------------------------------------------------
// Random grammar-built messages.
// ---------------------------------------------------------------------------
std::string pick(const std::vector<std::string>& v) { return v[rnd(v.size())]; }

std::string random_value() {
	static const std::vector<std::string> fixed = { "keep-alive", "close", "Upgrade", "keep-alive, Upgrade", "close, TE", "chunked", "gzip, chunked",
		"websocket", "0", "5", "12", "text/html; charset=utf-8", "", " ", "a b c", "*/*", "max-age=0", "Keep-Alive", "CLOSE", "upgrade,", "x,close", "keep-alive,",
		"chunked, gzip", "chunkedx", "chunke", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" };
	if (rnd(3) != 0) return pick(fixed);
	std::string s;
	size_t n = rnd(rnd(3) == 0 ? 90 : 24);
	static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.,;:=/\"'()[]\t";
	for (size_t i = 0; i < n; ++i) s += alpha[rnd(sizeof alpha - 1)];
	if (rnd(10) == 0 && !s.empty()) s[rnd(s.size())] = interesting[rnd(sizeof interesting)];
	return s;
}

std::string random_name() {
	static const std::vector<std::string> fixed = { "Host", "User-Agent", "Connection", "Content-Length", "Transfer-Encoding", "Upgrade", "Proxy-Connection",
		"Cookie", "X-Foo-Bar", "Accept", "connection", "CONTENT-LENGTH", "Content-Type", "Cache-Control", "transfer-encoding", "UPGRADE", "Co", "Con", "Conn" };
	if (rnd(3) != 0) return pick(fixed);
	std::string s;
	size_t n = 1 + rnd(20);
	static const char tok[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!#$%&'*+^`|~";
	for (size_t i = 0; i < n; ++i) s += tok[rnd(sizeof tok - 1)];
	return s;
}

std::string random_message(bool request) {
	std::string eol = rnd(12) == 0 ? "\n" : "\r\n";
	std::string m;
	if (request) {
		static const std::vector<std::string> methods = { "GET", "GET", "GET", "POST", "PUT", "HEAD", "DELETE", "CONNECT", "OPTIONS", "PATCH", "COUNT", "UPSERT", "BREW" };
		static const std::vector<std::string> urls = { "/", "/index.html", "/a/b/c?x=1&y=2", "/q?a=b#frag", "*", "http://h:80/p?q#f", "http://u@h/", "h:443", "/\xc3\xa9", "/a%20b", "/a;b=c,d" };
		m = pick(methods) + " " + pick(urls) + " HTTP/1." + (rnd(5) == 0 ? "0" : "1") + eol;
	} else {
		static const std::vector<std::string> codes = { "200 OK", "204 No Content", "304 Not Modified", "100 Continue", "404 Not Found", "101 Switching Protocols", "200" };
		m = "HTTP/1." + std::string(rnd(5) == 0 ? "0" : "1") + " " + pick(codes) + eol;
	}
	size_t nh = rnd(9);
	bool chunked = false;
	long clen = -1;
	for (size_t i = 0; i < nh; ++i) {
		std::string name = random_name(), value = random_value();
		if (strcasecmp(name.c_str(), "content-length") == 0 && rnd(4) != 0) { clen = (long) rnd(20); value = std::to_string(clen); }
		if (strcasecmp(name.c_str(), "transfer-encoding") == 0 && rnd(2)) { value = "chunked"; chunked = true; }
		std::string sp = rnd(8) == 0 ? "" : (rnd(10) == 0 ? "\t" : (rnd(10) == 0 ? "   " : " "));
		m += name + ":" + sp + value;
		if (rnd(10) == 0) m += eol + " " + random_value();
		m += eol;
	}
	m += eol;
	if (chunked) {
		size_t nc = rnd(4);
		for (size_t i = 0; i < nc; ++i) {
			size_t n = rnd(40);
			char b[16]; snprintf(b, sizeof b, rnd(2) ? "%zx" : "%zX", n);
			m += b; if (rnd(6) == 0) m += ";ext=1";
			m += "\r\n" + std::string(n, 'z') + "\r\n";
		}
		m += "0\r\n";
		if (rnd(3) == 0) m += "T: v\r\n";
		m += "\r\n";
	} else if (clen > 0) {
		m += std::string(rnd(clen + 3), 'b');
	}
	return m;
}

std::string mutate(std::string s) {
	size_t k = 1 + rnd(3);
	for (size_t i = 0; i < k && !s.empty(); ++i) {
		size_t at = rnd(s.size());
		switch (rnd(4)) {
			case 0: s[at] = interesting[rnd(sizeof interesting)]; break;
			case 1: s.erase(at, 1); break;
			case 2: s.insert(s.begin() + at, interesting[rnd(sizeof interesting)]); break;
			default: s.resize(at); break;
		}
	}
	return s;
}

const enum http_parser_type types[] = { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };

}  // namespace

// The parser alone, not lenient: `in` must stop with `want` (HPE_OK: parse whole, with a
// message completed; HPE_CLOSED_CONNECTION: a message completed, and the bytes after it are
// refused), in one call, byte by byte, and (all_cuts) cut in two everywhere; and,
// given `at`, the one call must stop at that offset (the byte that breaks the rule); given
// `messages`, that many must complete, and given `upgrade`, the parser must end with it.
const enum http_parser_type t_req = HTTP_REQUEST, t_res = HTTP_RESPONSE;

void harden(enum http_parser_type t, const std::string& in, enum http_errno want, bool all_cuts = true, long at = -1,
	int messages = -1, int upgrade = -1) {
	std::vector<std::vector<size_t>> plans = { {}, { 1 } };
	for (size_t cut = 1; all_cuts && cut < in.size(); ++cut) plans.push_back({ cut, in.size() });
	if (!all_cuts) plans.push_back({ 16 });
	for (const auto& plan : plans) {
		std::vector<Event> ev;
		Mode m;
		m.eof = want == HPE_OK && t == HTTP_RESPONSE;
		drive(live, t, in, plan, m, ev, false);
		++checks;
		unsigned got = ev.empty() ? 0 : ev.back().snap.http_errno;
		bool completed = std::any_of(ev.begin(), ev.end(), [](const Event& e) { return e.kind == MSG_DONE; });
		long stop = !ev.empty() && ev.back().kind == RET ? ev.back().off : -1;
		bool where = at < 0 || !plan.empty() || stop == at;
		bool must_complete = want == HPE_OK || want == HPE_CLOSED_CONNECTION;
		long done = std::count_if(ev.begin(), ev.end(), [](const Event& e) { return e.kind == MSG_DONE; });
		bool counted = (messages < 0 || done == messages) && (upgrade < 0 || (!ev.empty() && (int) ev.back().snap.upgrade == upgrade));
		if (got == (unsigned) want && (!must_complete || completed) && where && counted) continue;
		++failures;
		if (failures <= 10) {
			printf("HARDENING %s type=%d plan=%s: want %s at %ld (%d messages, upgrade %d), got %s at %ld (%ld messages, upgrade %d)\n",
				show(in).c_str(), (int) t, plan.empty() ? "oneshot" : std::to_string(plan[0]).c_str(), http_errno_name(want), at,
				messages, upgrade, http_errno_name((enum http_errno) got), stop, done, ev.empty() ? -1 : (int) ev.back().snap.upgrade);
		}
		if (getenv("HTTP_PARSER_DIFF_STOP")) {
			fflush(stdout);
			exit(1);
		}
		return;
	}
}

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
