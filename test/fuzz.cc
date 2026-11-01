// Differential fuzz target: the live parser against the frozen copy in
// test/http_parser_old.cc, on bytes the fuzzer chooses.
//
// The input is 8 control bytes and then the message:
//   [0]       parser type: request, response or both
//   [1]       bits 0-1: value on_headers_complete returns (0 to 2); bit 2: call
//             execute() with no data at the end; bits 3-4: which callbacks are
//             installed; bit 7: bit 16 of the pad count
//   [2], [3]  the callback with this ordinal fails / pauses the parser (128 or
//             more: none)
//   [4], [5]  position in the message of a run of filler bytes
//   [6], [7]  low 16 bits of the length of that run (the pad count); the run
//             repeats the byte before its position and reaches the 80 KB limit
//
// Every input runs in one call, byte by byte, with a random split plan, and with
// the buffer cut in two at every position (or at 48 sampled positions when the
// message is long), each chunk in its own exact-size heap block, so an
// out-of-bounds read is an AddressSanitizer report. Any difference between the
// two parsers aborts.
//
// Built with -fsanitize=fuzzer this is a libFuzzer target. Without it
// (HTTP_PARSER_FUZZ_DRIVER) main() is a mutation loop over the diff test's corpus:
//   http_parser_fuzz [--iters N] [--seed S] [--splits N] [--dump-corpus DIR] [FILE...]
#include <cstring>

#define main http_parser_diff_main  // diff.cc's main() is not wanted here
#include "diff.cc"
#undef main

namespace {

size_t all_splits_up_to = 320;  // two-chunk splits at every position up to this length

void fuzz_one(const uint8_t* data, size_t size) {
	if (size < 8) return;
	const enum http_parser_type t = types[data[0] % 3];
	Mode m;
	m.hc_ret = (data[1] & 3) % 3;
	m.eof = (data[1] >> 2) & 1;
	switch ((data[1] >> 3) & 3) {
		case 1: m.mask = (1u << URL) | (1u << FIELD) | (1u << VALUE) | (1u << BODY) | (1u << STATUS); break;
		case 2: m.mask = (1u << MSG_BEGIN) | (1u << MSG_DONE) | (1u << HDRS_DONE); break;
		case 3: m.mask = 0; break;
		default: break;
	}
	m.fail_at = data[2] < 128 ? data[2] % 64 : -1;
	m.pause_at = data[3] < 128 ? data[3] % 64 : -1;

	std::string in((const char*) data + 8, size - 8);
	const size_t pos = ((size_t) data[4] << 8 | data[5]) % (in.size() + 1);
	const size_t pad = ((size_t) (data[1] >> 7) << 16) | ((size_t) data[7] << 8) | data[6];
	if (pad) in.insert(pos, pad, pos ? in[pos - 1] : 'a');

	uint64_t h = 1469598103934665603ull;  // seeds the random plan from the input
	for (size_t i = 0; i < size; ++i) h = (h ^ data[i]) * 1099511628211ull;
	rng.seed(h);

	const long before = failures;
	check("fuzz", t, in, {}, m);
	check("fuzz", t, in, { 1 }, m);
	check("fuzz", t, in, random_plan(16), m);
	if (in.size() <= 4096) {
		const size_t n = in.size();
		const size_t step = n <= all_splits_up_to ? 1 : n / 48 + 1;
		for (size_t s = 1; s < n; s += step) check("fuzz", t, in, { s }, m);
	} else {
		check("fuzz", t, in, { 4096 }, m);
		check("fuzz", t, in, { in.size() / 2 }, m);
	}
	if (failures != before) abort();
}

}  // namespace

#ifdef HTTP_PARSER_FUZZ_DRIVER

namespace {

std::string read_file(const char* path) {
	std::string s;
	FILE* f = fopen(path, "rb");
	if (!f) return s;
	char b[4096];
	size_t n;
	while ((n = fread(b, 1, sizeof b, f)) > 0) s.append(b, n);
	fclose(f);
	return s;
}

std::string with_controls(enum http_parser_type t, const std::string& msg) {
	std::string c(8, '\0');
	c[0] = (char) (t == HTTP_REQUEST ? 0 : t == HTTP_RESPONSE ? 1 : 2);
	c[2] = c[3] = (char) 0xff;
	return c + msg;
}

}  // namespace

int main(int argc, char** argv) {
	long iters = 2000;
	const char* dump = nullptr;
	std::vector<std::string> pool;
	for (const Seed& s : corpus()) pool.push_back(with_controls(s.type, s.bytes));
	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--iters") && i + 1 < argc) iters = atol(argv[++i]);
		else if (!strcmp(argv[i], "--seed") && i + 1 < argc) rng.seed((uint64_t) atoll(argv[++i]));
		else if (!strcmp(argv[i], "--splits") && i + 1 < argc) all_splits_up_to = (size_t) atol(argv[++i]);
		else if (!strcmp(argv[i], "--dump-corpus") && i + 1 < argc) dump = argv[++i];
		else pool.push_back(read_file(argv[i]));
	}
	if (dump) {
		for (size_t i = 0; i < pool.size(); ++i) {
			std::string path = std::string(dump) + "/seed-" + std::to_string(i);
			FILE* f = fopen(path.c_str(), "wb");
			if (!f) { perror(path.c_str()); return 1; }
			fwrite(pool[i].data(), 1, pool[i].size(), f);
			fclose(f);
		}
		printf("wrote %zu seeds to %s\n", pool.size(), dump);
		return 0;
	}

	long ran = 0;
	for (long i = 0; i < iters; ++i) {
		std::string in = pool[rnd(pool.size())];
		if (in.size() > 4000) continue;  // the limit cases belong to the pad count
		if (rnd(4) == 0) {  // splice in the tail of another seed
			const std::string& o = pool[rnd(pool.size())];
			if (o.size() > 8 && o.size() < 4000) in = in.substr(0, 8 + rnd(in.size() - 7)) + o.substr(8 + rnd(o.size() - 7));
		}
		std::string msg = mutate(in.substr(8));
		if (rnd(3) == 0) msg = mutate(msg);
		std::string v = in.substr(0, 8) + msg;
		if (rnd(2)) { v[1] = (char) rnd(256); v[2] = (char) (rnd(3) ? 0xff : rnd(256)); v[3] = (char) (rnd(3) ? 0xff : rnd(256)); }
		if (rnd(2)) v[0] = (char) rnd(3);
		if (rnd(10) == 0) {  // a filler run, some of them around the 80 KB limit
			const size_t pad = rnd(2) ? rnd(70000) : (size_t) (HTTP_MAX_HEADER_SIZE - 40 + rnd(80));
			v[4] = (char) rnd(256); v[5] = (char) rnd(256);
			v[6] = (char) (pad & 255); v[7] = (char) ((pad >> 8) & 255);
			v[1] = (char) ((v[1] & 0x7f) | ((pad >> 16) & 1) << 7);
		}
		fuzz_one((const uint8_t*) v.data(), v.size());
		++ran;
	}
	printf("fuzz driver: %ld inputs, %ld checks, %ld failures\n", ran, checks, failures);
	return failures ? 1 : 0;
}

#else

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	fuzz_one(data, size);
	return 0;
}

#endif
