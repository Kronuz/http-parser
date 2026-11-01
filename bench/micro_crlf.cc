// Microbenchmark of the CR/LF scan alone: the two-memchr find_crlf against a fused NEON/SSE2 scan and a byte loop.
// Standalone (it copies the scans; it does not link the parser):
//   c++ -std=c++20 -O3 -mcpu=native bench/micro_crlf.cc -o micro_crlf     (x86: -march=native)
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#if defined(__ARM_NEON)
# include <arm_neon.h>
#elif defined(__SSE2__)
# include <emmintrin.h>
#endif

#define CR '\r'
#define LF '\n'
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define HTTP_MAX_HEADER_SIZE (80 * 1024)

__attribute__((noinline)) const char* find_old(const char* p, const char* data, size_t len) {
	const char* p_cr;
	const char* p_lf;
	size_t limit = data + len - p;
	limit = MIN(limit, HTTP_MAX_HEADER_SIZE);
	p_cr = (const char*) memchr(p, CR, limit);
	p_lf = (const char*) memchr(p, LF, limit);
	if (p_cr != NULL) {
		if (p_lf != NULL && p_cr >= p_lf) p = p_lf; else p = p_cr;
	} else if (p_lf != NULL) {
		p = p_lf;
	} else {
		p = data + len;
	}
	return p;
}

static inline const char* scan_crlf(const char* p, const char* end) {
#if defined(__ARM_NEON)
	const uint8x16_t cr = vdupq_n_u8(CR);
	const uint8x16_t lf = vdupq_n_u8(LF);
	while (end - p >= 16) {
		const uint8x16_t v = vld1q_u8((const uint8_t*) p);
		const uint8x16_t m = vorrq_u8(vceqq_u8(v, cr), vceqq_u8(v, lf));
		const uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);
		if (bits) return p + (__builtin_ctzll(bits) >> 2);
		p += 16;
	}
#elif defined(__SSE2__)
	const __m128i cr = _mm_set1_epi8(CR);
	const __m128i lf = _mm_set1_epi8(LF);
	while (end - p >= 16) {
		const __m128i v = _mm_loadu_si128((const __m128i*) p);
		const unsigned bits = (unsigned) _mm_movemask_epi8(_mm_or_si128(_mm_cmpeq_epi8(v, cr), _mm_cmpeq_epi8(v, lf)));
		if (bits) return p + __builtin_ctz(bits);
		p += 16;
	}
#endif
	while (p < end) {
		if (*p == CR || *p == LF) return p;
		++p;
	}
	return end;
}

__attribute__((noinline)) const char* find_simd(const char* p, const char* data, size_t len) {
	size_t limit = data + len - p;
	limit = MIN(limit, HTTP_MAX_HEADER_SIZE);
	const char* r = scan_crlf(p, p + limit);
	return r == p + limit ? data + len : r;
}

__attribute__((noinline)) const char* find_byte(const char* p, const char* data, size_t len) {
	size_t limit = data + len - p;
	limit = MIN(limit, HTTP_MAX_HEADER_SIZE);
	const char* e = p + limit;
	while (p < e && *p != CR && *p != LF) ++p;
	return p == e ? data + len : p;
}

template <typename F> double bench(F f, const std::string& buf, size_t start, uint64_t n) {
	auto t0 = std::chrono::steady_clock::now();
	uintptr_t acc = 0;
	for (uint64_t i = 0; i < n; ++i) {
		const char* r = f(buf.data() + start, buf.data(), buf.size());
		acc += (uintptr_t) r;
		asm volatile("" : "+r"(acc) : : "memory");
	}
	double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / double(n);
	if (acc == 1) printf(" ");
	return ns;
}

int main() {
	for (size_t vlen : { 4, 8, 11, 17, 30, 50, 117, 300 }) {
		for (size_t tail : { 4, 64 }) {  // bytes after the value's CRLF (4: the final header of a bodiless request)
			std::string buf = "GET / HTTP/1.1\r\nX: ";
			size_t start = buf.size();
			buf += std::string(vlen, 'v') + "\r\n" + std::string(tail > 2 ? tail - 2 : 0, 'z');
			if (buf.back() != '\n' && tail == 4) buf += "\r\n";
			double best[3] = { 1e9, 1e9, 1e9 };
			for (int r = 0; r < 15; ++r) {
				best[0] = std::min(best[0], bench(find_old, buf, start, 2000000));
				best[1] = std::min(best[1], bench(find_simd, buf, start, 2000000));
				best[2] = std::min(best[2], bench(find_byte, buf, start, 2000000));
			}
			const char* a = find_old(buf.data() + start, buf.data(), buf.size());
			const char* b = find_simd(buf.data() + start, buf.data(), buf.size());
			const char* c = find_byte(buf.data() + start, buf.data(), buf.size());
			printf("value %3zu B, tail %2zu: memchr x2 %5.2f ns  simd %5.2f ns  byte loop %5.2f ns  %s\n", vlen, tail, best[0], best[1], best[2],
				(a == b && b == c) ? "same" : "DIFFERENT");
		}
	}
}
