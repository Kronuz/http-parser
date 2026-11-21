// Snapshots, event recording, the driver, the comparison and the hardening-class rules of the differential test (see diff.cc).

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
std::vector<std::pair<const char*, long>> changed = { { "http10-te-close", 0 }, { "response-upgrade-101", 0 }, { "response-no-body", 0 },
	{ "response-te-cl", 0 } };

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
		// RFC 9112 section 6.3: Transfer-Encoding overrides Content-Length; a response with a
		// Transfer-Encoding other than chunked and a Content-Length is an error at the end of
		// its header section, where the old parser read the body by the length.
		if (s.http_errno == HPE_UNEXPECTED_CONTENT_LENGTH && s.type == HTTP_RESPONSE && (s.flags & F_CONTENTLENGTH) &&
				!(s.flags & F_CHUNKED) && sa && sa->http_errno == HPE_OK)
			return "response-te-cl";
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

