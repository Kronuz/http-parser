// The conformance runner for llhttp itself, built from its release C sources
// (cmake -DHTTP_PARSER_LLHTTP_SOURCE_DIR=<llhttp release tree>). It mirrors
// llhttp's own test fixture: every pause point llhttp has, the lenient flags each
// case type names, and llhttp's finish state for the *-finish cases. With
// `strict` set it ignores the case type's lenient flags, so a lenient-* case shows
// llhttp's default verdict.
#include <algorithm>
#include <cstring>
#include <string>

#include <llhttp.h>

#include "conformance.h"

namespace {

using conformance::Events;

struct State {
	const conformance::Case* c;
	Events ev;
	int pause(const char* cb) const { return std::strcmp(c->pause, cb) == 0 ? HPE_PAUSED : 0; }
};

State* st(llhttp_t* p) { return static_cast<State*>(p->data); }

const char* method_name(unsigned m) {
	return llhttp_method_name(static_cast<llhttp_method_t>(m));
}

int on_begin(llhttp_t* p) { st(p)->ev.event("begin"); return st(p)->pause("on_message_begin"); }
int on_url(llhttp_t* p, const char* at, size_t n) { st(p)->ev.span(Events::URL, at, n); return 0; }
int on_status(llhttp_t* p, const char* at, size_t n) { st(p)->ev.span(Events::STATUS, at, n); return 0; }
int on_field(llhttp_t* p, const char* at, size_t n) { st(p)->ev.span(Events::FIELD, at, n); return 0; }
int on_value(llhttp_t* p, const char* at, size_t n) { st(p)->ev.span(Events::VALUE, at, n); return 0; }
int on_body(llhttp_t* p, const char* at, size_t n) { st(p)->ev.span(Events::BODY, at, n); return 0; }
int on_headers(llhttp_t* p) {
	char b[96];
	if (p->type == HTTP_RESPONSE) {
		std::snprintf(b, sizeof b, "headers v=%u/%u status=%u", p->http_major, p->http_minor, p->status_code);
	} else {
		std::snprintf(b, sizeof b, "headers v=%u/%u method=%s", p->http_major, p->http_minor, method_name(p->method));
	}
	st(p)->ev.event(b);
	if (int r = st(p)->pause("on_headers_complete")) return r;
	return st(p)->c->skip_body ? 1 : 0;
}
int on_chunk_header(llhttp_t* p) {
	char b[48];
	std::snprintf(b, sizeof b, "chunk %llu", static_cast<unsigned long long>(p->content_length));
	st(p)->ev.event(b);
	return st(p)->pause("on_chunk_header");
}
int on_chunk_complete(llhttp_t* p) { st(p)->ev.event("chunk_done"); return st(p)->pause("on_chunk_complete"); }
int on_complete(llhttp_t* p) { st(p)->ev.event("complete"); return st(p)->pause("on_message_complete"); }
// The callbacks http_parser lacks: they only pause, so a case that pauses there runs as in llhttp.
int on_method_complete(llhttp_t* p) { return st(p)->pause("on_method_complete"); }
int on_url_complete(llhttp_t* p) { return st(p)->pause("on_url_complete"); }
int on_protocol_complete(llhttp_t* p) { return st(p)->pause("on_protocol_complete"); }
int on_version_complete(llhttp_t* p) { return st(p)->pause("on_version_complete"); }
int on_status_complete(llhttp_t* p) { return st(p)->pause("on_status_complete"); }
int on_field_complete(llhttp_t* p) { return st(p)->pause("on_header_field_complete"); }
int on_value_complete(llhttp_t* p) { return st(p)->pause("on_header_value_complete"); }
int on_ext_name_complete(llhttp_t* p) { return st(p)->pause("on_chunk_extension_name"); }
int on_ext_value_complete(llhttp_t* p) { return st(p)->pause("on_chunk_extension_value"); }

void set_lenient(llhttp_t* p, std::string_view type) {
	auto has = [&](const char* flag) { return type.ends_with(flag) || type.ends_with("-lenient-all"); };
	if (has("-lenient-headers")) llhttp_set_lenient_headers(p, 1);
	if (has("-lenient-chunked-length")) llhttp_set_lenient_chunked_length(p, 1);
	if (has("-lenient-keep-alive")) llhttp_set_lenient_keep_alive(p, 1);
	if (has("-lenient-transfer-encoding")) llhttp_set_lenient_transfer_encoding(p, 1);
	if (has("-lenient-version")) llhttp_set_lenient_version(p, 1);
	if (has("-lenient-data-after-close")) llhttp_set_lenient_data_after_close(p, 1);
	if (has("-lenient-optional-lf-after-cr")) llhttp_set_lenient_optional_lf_after_cr(p, 1);
	if (has("-lenient-optional-cr-before-lf")) llhttp_set_lenient_optional_cr_before_lf(p, 1);
	if (has("-lenient-optional-crlf-after-chunk")) llhttp_set_lenient_optional_crlf_after_chunk(p, 1);
	if (type.ends_with("-lenient-spaces-after-chunk-size")) llhttp_set_lenient_spaces_after_chunk_size(p, 1);
	if (type.ends_with("-lenient-header-value-relaxed")) llhttp_set_lenient_header_value_relaxed(p, 1);
}

}  // namespace

conformance::Result run_llhttp(const conformance::Case& c, size_t chunk, bool strict) {
	State s{&c};
	llhttp_settings_t settings;
	llhttp_settings_init(&settings);
	settings.on_message_begin = on_begin;
	settings.on_url = on_url;
	settings.on_status = on_status;
	settings.on_header_field = on_field;
	settings.on_header_value = on_value;
	settings.on_headers_complete = on_headers;
	settings.on_body = on_body;
	settings.on_message_complete = on_complete;
	settings.on_chunk_header = on_chunk_header;
	settings.on_chunk_complete = on_chunk_complete;
	settings.on_method_complete = on_method_complete;
	settings.on_url_complete = on_url_complete;
	settings.on_protocol_complete = on_protocol_complete;
	settings.on_version_complete = on_version_complete;
	settings.on_status_complete = on_status_complete;
	settings.on_header_field_complete = on_field_complete;
	settings.on_header_value_complete = on_value_complete;
	settings.on_chunk_extension_name_complete = on_ext_name_complete;
	settings.on_chunk_extension_value_complete = on_ext_value_complete;

	llhttp_t p;
	llhttp_init(&p, conformance::is_response(c) ? HTTP_RESPONSE : HTTP_REQUEST, &settings);
	p.data = &s;
	if (!strict) set_lenient(&p, c.type);

	conformance::Result res;
	const char* d = c.input.data();
	size_t len = c.input.size(), off = 0;
	bool stopped = false;
	int pauses = 0;
	bool resumed = false;  // after a pause, run once more even with no input left
	while (off < len || resumed) {
		resumed = false;
		size_t feed = chunk ? std::min(chunk, len - off) : len - off;
		llhttp_errno_t e = llhttp_execute(&p, d + off, feed);
		if (e == HPE_OK) {
			off += feed;
			continue;
		}
		size_t at = llhttp_get_error_pos(&p) - d;
		if (e == HPE_PAUSED) {
			s.ev.pause();
			llhttp_resume(&p);
			off = at;
			resumed = true;
			if (++pauses > 64) { s.ev.event("error"); res.note = "stuck after pause"; stopped = true; break; }
			continue;
		}
		if (e == HPE_PAUSED_UPGRADE) { s.ev.event("upgrade"); stopped = true; break; }
		if (e == HPE_PAUSED_H2_UPGRADE) { s.ev.event("h2upgrade"); stopped = true; break; }
		s.ev.event("error");
		res.note = std::string(llhttp_errno_name(e)) + " off=" + std::to_string(at) + " " + llhttp_get_error_reason(&p);
		stopped = true;
		break;
	}
	if (conformance::is_finish(c) && !stopped) {
		s.ev.event("finish=" + std::to_string(p.finish));
	}
	res.events = s.ev.take();
	return res;
}
