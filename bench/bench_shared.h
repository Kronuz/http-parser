// Shared by bench.cc and bench_llhttp.cc. The two cannot share a translation unit:
// llhttp.h and http_parser.h define the same enumerators (F_CHUNKED, HPE_OK, ...).
#pragma once

#include <cstddef>
#include <cstdint>

struct Stats {
	uint64_t msgs = 0, field_bytes = 0, value_bytes = 0, url_bytes = 0, body_bytes = 0, calls = 0;
	int method = -1;
	bool operator==(const Stats& o) const {
		return msgs == o.msgs && field_bytes == o.field_bytes && value_bytes == o.value_bytes && url_bytes == o.url_bytes &&
			body_bytes == o.body_bytes && method == o.method;
	}
};

template <typename P> int on_begin(P* p) { ((Stats*) p->data)->msgs++; return 0; }
template <typename P> int on_url(P* p, const char*, size_t n) { auto* s = (Stats*) p->data; s->url_bytes += n; s->calls++; return 0; }
template <typename P> int on_field(P* p, const char*, size_t n) { auto* s = (Stats*) p->data; s->field_bytes += n; s->calls++; return 0; }
template <typename P> int on_value(P* p, const char*, size_t n) { auto* s = (Stats*) p->data; s->value_bytes += n; s->calls++; return 0; }
template <typename P> int on_hdone(P* p) { ((Stats*) p->data)->method = (int) p->method; return 0; }
template <typename P> int on_body(P* p, const char*, size_t n) { ((Stats*) p->data)->body_bytes += n; return 0; }

#ifdef HAVE_LLHTTP
bool run_llhttp(const char* data, size_t n, size_t chunk, bool response, Stats& st);
#endif
