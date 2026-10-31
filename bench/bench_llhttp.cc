// The llhttp arm of bench.cc, in its own translation unit (see bench_shared.h).
#include <llhttp.h>

#include "bench_shared.h"

bool run_llhttp(const char* data, size_t n, size_t chunk, bool response, Stats& st) {
	llhttp_settings_t s;
	llhttp_settings_init(&s);
	s.on_message_begin = on_begin<llhttp_t>; s.on_url = on_url<llhttp_t>; s.on_header_field = on_field<llhttp_t>;
	s.on_header_value = on_value<llhttp_t>; s.on_headers_complete = on_hdone<llhttp_t>; s.on_body = on_body<llhttp_t>;
	llhttp_t p;
	llhttp_init(&p, response ? HTTP_RESPONSE : HTTP_REQUEST, &s);
	p.data = &st;
	if (!chunk) chunk = n;
	for (size_t off = 0; off < n; off += chunk) {
		size_t len = n - off < chunk ? n - off : chunk;
		if (llhttp_execute(&p, data + off, len) != HPE_OK) return false;
	}
	return true;
}
