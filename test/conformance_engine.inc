// The conformance runner for an engine with http_parser's API (included by
// test/conformance.cc for this parser; another engine with the same API can include it
// with its own names).
// Before including it, define:
//   HP_FN(name)   the engine's name for an http_parser function (http_parser_execute, ...)
//   HP_T(name)    its name for the http_parser and http_parser_settings types
//   HP_ENGINE     the name of the runner function to define:
//                 conformance::Result HP_ENGINE(const conformance::Case&, size_t chunk)
//
// The runner feeds the case in pieces of `chunk` bytes (0: whole), resumes after a
// pause, stops at an error or an upgrade, and for the *-finish cases signals EOF and
// reports what llhttp's finish state would be. Pauses happen where the case asks,
// in the callbacks http_parser has (on_message_begin, on_headers_complete,
// on_chunk_header, on_chunk_complete, on_message_complete).
#include <cstring>

namespace {

struct HP_T(run_state) {
	const conformance::Case* c;
	conformance::Events ev;
	bool in_eof = false;
	bool eof_complete = false;
	bool pause_on(const char* cb) const { return std::strcmp(c->pause, cb) == 0; }
};

HP_T(run_state)* HP_T(state_of)(HP_T(http_parser)* p) { return static_cast<HP_T(run_state)*>(p->data); }

int HP_T(cb_begin)(HP_T(http_parser)* p) {
	auto* r = HP_T(state_of)(p);
	r->ev.event("begin");
	if (r->pause_on("on_message_begin")) HP_FN(http_parser_pause)(p, 1);
	return 0;
}
int HP_T(cb_url)(HP_T(http_parser)* p, const char* at, size_t n) { HP_T(state_of)(p)->ev.span(conformance::Events::URL, at, n); return 0; }
int HP_T(cb_status)(HP_T(http_parser)* p, const char* at, size_t n) { HP_T(state_of)(p)->ev.span(conformance::Events::STATUS, at, n); return 0; }
int HP_T(cb_field)(HP_T(http_parser)* p, const char* at, size_t n) { HP_T(state_of)(p)->ev.span(conformance::Events::FIELD, at, n); return 0; }
int HP_T(cb_value)(HP_T(http_parser)* p, const char* at, size_t n) { HP_T(state_of)(p)->ev.span(conformance::Events::VALUE, at, n); return 0; }
int HP_T(cb_body)(HP_T(http_parser)* p, const char* at, size_t n) { HP_T(state_of)(p)->ev.span(conformance::Events::BODY, at, n); return 0; }
int HP_T(cb_headers)(HP_T(http_parser)* p) {
	auto* r = HP_T(state_of)(p);
	char b[96];
	if (conformance::is_response(*r->c)) {
		std::snprintf(b, sizeof b, "headers v=%u/%u status=%u", unsigned(p->http_major), unsigned(p->http_minor), unsigned(p->status_code));
	} else {
		std::snprintf(b, sizeof b, "headers v=%u/%u method=%s", unsigned(p->http_major), unsigned(p->http_minor),
			HP_FN(http_method_str)(static_cast<enum http_method>(p->method)));
	}
	r->ev.event(b);
	if (r->pause_on("on_headers_complete")) HP_FN(http_parser_pause)(p, 1);
	return r->c->skip_body ? 1 : 0;
}
int HP_T(cb_chunk_header)(HP_T(http_parser)* p) {
	auto* r = HP_T(state_of)(p);
	char b[48];
	std::snprintf(b, sizeof b, "chunk %llu", static_cast<unsigned long long>(p->content_length));
	r->ev.event(b);
	if (r->pause_on("on_chunk_header")) HP_FN(http_parser_pause)(p, 1);
	return 0;
}
int HP_T(cb_chunk_complete)(HP_T(http_parser)* p) {
	auto* r = HP_T(state_of)(p);
	r->ev.event("chunk_done");
	if (r->pause_on("on_chunk_complete")) HP_FN(http_parser_pause)(p, 1);
	return 0;
}
int HP_T(cb_complete)(HP_T(http_parser)* p) {
	auto* r = HP_T(state_of)(p);
	if (r->in_eof) r->eof_complete = true;
	r->ev.event("complete");
	if (r->pause_on("on_message_complete")) HP_FN(http_parser_pause)(p, 1);
	return 0;
}

}  // namespace

conformance::Result HP_ENGINE(const conformance::Case& c, size_t chunk) {
	HP_T(run_state) r{&c};
	HP_T(http_parser_settings) s;
	HP_FN(http_parser_settings_init)(&s);
	s.on_message_begin = HP_T(cb_begin);
	s.on_url = HP_T(cb_url);
	s.on_status = HP_T(cb_status);
	s.on_header_field = HP_T(cb_field);
	s.on_header_value = HP_T(cb_value);
	s.on_headers_complete = HP_T(cb_headers);
	s.on_body = HP_T(cb_body);
	s.on_message_complete = HP_T(cb_complete);
	s.on_chunk_header = HP_T(cb_chunk_header);
	s.on_chunk_complete = HP_T(cb_chunk_complete);

	HP_T(http_parser) p;
	HP_FN(http_parser_init)(&p, conformance::is_response(c) ? HTTP_RESPONSE : HTTP_REQUEST);
	p.data = &r;
	std::string_view type(c.type);
	if (type.ends_with("-lenient-headers") || type.ends_with("-lenient-all")) {
		p.lenient_http_headers = 1;  // the one leniency knob http_parser has
	}

	conformance::Result res;
	const char* d = c.input.data();
	size_t len = c.input.size(), off = 0;
	bool stopped = false;
	int pauses = 0;
	while (off < len) {
		size_t feed = chunk ? std::min(chunk, len - off) : len - off;
		size_t n = HP_FN(http_parser_execute)(&p, &s, d + off, feed);
		off += n;
		auto e = HTTP_PARSER_ERRNO(&p);
		if (e == HPE_PAUSED) {
			r.ev.pause();
			HP_FN(http_parser_pause)(&p, 0);
			if (++pauses > 64) {
				r.ev.event("error");
				res.note = "stuck after pause";
				stopped = true;
				break;
			}
			continue;
		}
		if (e != HPE_OK) {
			r.ev.event("error");
			res.note = std::string(HP_FN(http_errno_name)(e)) + " off=" + std::to_string(off);
			stopped = true;
			break;
		}
		// http_parser sets upgrade at the end of the headers and stops at the end of the
		// message: stop where it stopped (a short return), or where the message ended.
		if (p.upgrade && (n < feed || r.ev.last_is("complete"))) {
			r.ev.event("upgrade");
			stopped = true;
			break;
		}
		if (n < feed && !p.upgrade) {
			r.ev.event("error");
			res.note = "short return without an error";
			stopped = true;
			break;
		}
	}
	if (conformance::is_finish(c) && !stopped) {
		r.in_eof = true;
		HP_FN(http_parser_execute)(&p, &s, nullptr, 0);
		if (HTTP_PARSER_ERRNO(&p) != HPE_OK) {
			r.ev.event("finish=2");
			res.note = std::string(HP_FN(http_errno_name)(HTTP_PARSER_ERRNO(&p))) + " at EOF";
		} else if (r.eof_complete) {
			r.ev.drop_last("complete");
			r.ev.event("finish=1");
		} else {
			r.ev.event("finish=0");
		}
	}
	res.events = r.ev.take();
	return res;
}
