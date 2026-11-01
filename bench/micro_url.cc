// Microbenchmark of the URL-run scan alone: the IS_URL_CHAR bit loop, a 256-entry table loop and the vector scan,
// plus an exhaustive check that the vector predicate equals the table for every byte value in every lane.
// Standalone (it copies the scans; it does not link the parser):
//   c++ -std=c++20 -O3 -mcpu=native bench/micro_url.cc -o micro_url     (x86: -march=native)
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#if defined(__ARM_NEON)
# include <arm_neon.h>
#elif defined(__SSE2__)
# include <emmintrin.h>
#endif

// strict-mode normal_url_char, built from the predicate (0x21..0x7e except '#' and '?'), packed 8 per byte like http_parser.cc
struct Packed {
	uint8_t b[32];
	constexpr Packed() : b() {
		for (int c = 0; c < 256; ++c)
			if (c >= 0x21 && c <= 0x7e && c != '#' && c != '?') b[c >> 3] |= (uint8_t) (1 << (c & 7));
	}
};
static constexpr Packed packed;
#define normal_url_char packed.b
#define BIT_AT(a, i) (!!((unsigned int) (a)[(unsigned int) (i) >> 3] & (1 << ((unsigned int) (i) & 7))))
#define IS_URL_CHAR(c) (BIT_AT(normal_url_char, (unsigned char) c))

struct Tab {
	uint8_t t[256];
	constexpr Tab() : t() {
		for (int c = 0; c < 256; ++c) t[c] = (packed.b[c >> 3] >> (c & 7)) & 1;
	}
};
static constexpr Tab tab;

__attribute__((noinline)) const char* skip_bitat(const char* q, const char* e) {
	while (q < e && IS_URL_CHAR(*q)) ++q;
	return q;
}
__attribute__((noinline)) const char* skip_tab(const char* q, const char* e) {
	while (q < e && tab.t[(unsigned char) *q]) ++q;
	return q;
}
__attribute__((noinline)) const char* skip_simd(const char* q, const char* e) {
#if defined(__ARM_NEON)
	const uint8x16_t lo = vdupq_n_u8(0x21), span = vdupq_n_u8(0x5d), hash = vdupq_n_u8('#'), qm = vdupq_n_u8('?');
	while (e - q >= 16) {
		const uint8x16_t v = vld1q_u8((const uint8_t*) q);
		const uint8x16_t bad = vorrq_u8(vorrq_u8(vcgtq_u8(vsubq_u8(v, lo), span), vceqq_u8(v, hash)), vceqq_u8(v, qm));
		const uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(bad), 4)), 0);
		if (bits) return q + (__builtin_ctzll(bits) >> 2);
		q += 16;
	}
#elif defined(__SSE2__)
	const __m128i lo = _mm_set1_epi8(0x21), hash = _mm_set1_epi8('#'), qm = _mm_set1_epi8('?');
	const __m128i sign = _mm_set1_epi8((char) 0x80);
	while (e - q >= 16) {
		const __m128i v = _mm_loadu_si128((const __m128i*) q);
		// bytes < 0x21 or > 0x7e: shift into signed range and compare: (v - 0x21 as unsigned) > 0x5d
		const __m128i d = _mm_sub_epi8(v, lo);
		const __m128i oob = _mm_cmpgt_epi8(_mm_xor_si128(d, sign), _mm_set1_epi8((char) (0x5d ^ 0x80)));
		const __m128i bad = _mm_or_si128(_mm_or_si128(oob, _mm_cmpeq_epi8(v, hash)), _mm_cmpeq_epi8(v, qm));
		const unsigned bits = (unsigned) _mm_movemask_epi8(bad);
		if (bits) return q + __builtin_ctz(bits);
		q += 16;
	}
#endif
	while (q < e && tab.t[(unsigned char) *q]) ++q;
	return q;
}

template <typename F> double bench(F f, const std::string& buf, size_t start, uint64_t n) {
	auto t0 = std::chrono::steady_clock::now();
	uintptr_t acc = 0;
	for (uint64_t i = 0; i < n; ++i) {
		const char* r = f(buf.data() + start, buf.data() + buf.size());
		acc += (uintptr_t) r;
		asm volatile("" : "+r"(acc) : : "memory");
	}
	double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / double(n);
	if (acc == 1) printf(" ");
	return ns;
}

int main() {
	for (size_t len : { 3, 10, 24, 60, 125, 400 }) {
		std::string path = "/";
		for (size_t i = 0; path.size() < len; ++i) path += (i % 7 == 6) ? '/' : char('a' + i % 26);
		std::string buf = "GET " + path + " HTTP/1.1\r\nHost: example.com\r\n\r\n";
		size_t start = 4 + 1;  // after the first URL byte
		double best[3] = { 1e9, 1e9, 1e9 };
		for (int r = 0; r < 15; ++r) {
			best[0] = std::min(best[0], bench(skip_bitat, buf, start, 2000000));
			best[1] = std::min(best[1], bench(skip_tab, buf, start, 2000000));
			best[2] = std::min(best[2], bench(skip_simd, buf, start, 2000000));
		}
		const char* e = buf.data() + buf.size();
		const char* a = skip_bitat(buf.data() + start, e);
		const char* b = skip_tab(buf.data() + start, e);
		const char* c = skip_simd(buf.data() + start, e);
		printf("url %3zu B: BIT_AT %6.2f ns  table %6.2f ns  simd %6.2f ns  %s\n", len, best[0], best[1], best[2], (a == b && b == c) ? "same" : "DIFFERENT");
	}
	// exhaustive: the SIMD predicate against the table for every byte at every lane
	int bad = 0;
	for (int c = 0; c < 256; ++c)
		for (int lane = 0; lane < 16; ++lane) {
			char b[40];
			memset(b, 'a', sizeof b);
			b[lane] = (char) c;
			const char* r = skip_simd(b, b + 32);
			const char* want = b + (tab.t[c] ? 32 : lane);
			if (r != want) { ++bad; if (bad < 5) printf("mismatch byte %d lane %d\n", c, lane); }
		}
	printf("exhaustive SIMD vs table: %d mismatches\n", bad);
}
