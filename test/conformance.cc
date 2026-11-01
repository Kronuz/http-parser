// Conformance test: llhttp's markdown suite (test/llhttp_corpus.inc) against this
// parser, with llhttp itself as an optional engine.
//
// Each case's expected log is llhttp's, reduced to the events http_parser reports
// (test/conformance.h). This parser does not match all of them: the cases where it
// differs are listed, with a category, in test/llhttp_divergences.txt. The test
// fails when a case differs that is not listed, or a listed case no longer differs,
// so a change in how the parser treats any of the suite's inputs shows up here.
// It also parses every case one byte at a time: where that gives other events than
// one buffer, the case must be listed as split:LOCATION.
//
// Usage:
//   http_parser_conformance DIVERGENCES        the CTest check
//   http_parser_conformance --report [DIV]     every case: the verdict of each engine and
//                                              the differing events (TSV summary at the end)
//   http_parser_conformance --case LOCATION    one case's events from every engine
//
// Engines (compiled in when available):
//   ours       this parser (http_parser.cc)
//   llhttp     llhttp built from its release C sources (HTTP_PARSER_LLHTTP_SOURCE_DIR);
//              it must reproduce the expected logs, which checks the harness itself.
//              "llhttp-strict" is the same parser without the case type's lenient flags.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "http_parser.h"
#include "conformance.h"

using conformance::Case;
using conformance::Result;

#define HP_FN(name) name
#define HP_T(name) name
#define HP_ENGINE run_ours
#include "conformance_engine.inc"
#undef HP_FN
#undef HP_T
#undef HP_ENGINE

#ifdef HAVE_LLHTTP_ENGINE
Result run_llhttp(const Case& c, size_t chunk, bool strict);
#endif

namespace {

const Case cases[] = {
#include "llhttp_corpus.inc"
};

// The pause points http_parser has; elsewhere the expected pause cannot happen.
bool pause_supported(const Case& c) {
	static const char* ok[] = { "", "on_message_begin", "on_headers_complete", "on_chunk_header",
		"on_chunk_complete", "on_message_complete" };
	for (auto* p : ok) {
		if (std::strcmp(c.pause, p) == 0) return true;
	}
	return false;
}

// The expected events this API can produce: without a pause the API cannot request.
std::string expected_for_api(const Case& c) {
	std::string e = c.expected;
	if (pause_supported(c)) return e;
	std::string out;
	std::istringstream in(e);
	for (std::string line; std::getline(in, line);) {
		if (line != "pause") out += line + "\n";
	}
	return out;
}

std::vector<std::string> lines(const std::string& s) {
	std::vector<std::string> v;
	std::istringstream in(s);
	for (std::string line; std::getline(in, line);) v.push_back(line);
	return v;
}

std::string verdict(const std::string& events) {
	auto v = lines(events);
	if (v.empty()) return "nothing";
	const std::string& last = v.back();
	if (last == "error") return "reject";
	if (last == "upgrade" || last == "h2upgrade") return last;
	if (last.starts_with("finish=")) return "accept " + last;
	return "accept";
}

// A line diff (LCS), '-' for expected only, '+' for actual only.
std::string diff(const std::string& a, const std::string& b) {
	auto x = lines(a), y = lines(b);
	size_t n = x.size(), m = y.size();
	std::vector<std::vector<int>> L(n + 1, std::vector<int>(m + 1, 0));
	for (size_t i = n; i-- > 0;)
		for (size_t j = m; j-- > 0;)
			L[i][j] = x[i] == y[j] ? L[i + 1][j + 1] + 1 : std::max(L[i + 1][j], L[i][j + 1]);
	std::string out;
	size_t i = 0, j = 0;
	while (i < n || j < m) {
		if (i < n && j < m && x[i] == y[j]) { out += "      " + x[i] + "\n"; ++i; ++j; }
		else if (j < m && (i == n || L[i][j + 1] >= L[i + 1][j])) { out += "    + " + y[j] + "\n"; ++j; }
		else { out += "    - " + x[i] + "\n"; ++i; }
	}
	return out;
}

struct Listed {
	std::string category, note;
};

std::map<std::string, Listed> load_divergences(const char* path) {
	std::map<std::string, Listed> m;
	std::ifstream in(path);
	if (!in) {
		std::fprintf(stderr, "cannot read %s\n", path);
		std::exit(2);
	}
	for (std::string line; std::getline(in, line);) {
		if (line.empty() || line[0] == '#') continue;
		auto t1 = line.find('\t');
		auto t2 = t1 == std::string::npos ? t1 : line.find('\t', t1 + 1);
		Listed l;
		l.category = line.substr(t1 + 1, t2 == std::string::npos ? std::string::npos : t2 - t1 - 1);
		if (t2 != std::string::npos) l.note = line.substr(t2 + 1);
		m[line.substr(0, t1)] = l;
	}
	return m;
}

void show_case(const Case& c) {
	std::printf("== %s  %s  [%s%s%s]\n", c.location, c.title, c.type, *c.pause ? " pause=" : "", c.pause);
	std::string in;
	conformance::escape(in, c.input);
	std::printf("-- input\n%s\n", in.c_str());
	std::printf("-- expected (llhttp's log)%s%s\n%s", *c.note ? ": " : "", c.note, expected_for_api(c).c_str());
	auto ours = run_ours(c, 0);
	std::printf("-- ours%s%s\n%s", ours.note.empty() ? "" : ": ", ours.note.c_str(), diff(expected_for_api(c), ours.events).c_str());
#ifdef HAVE_LLHTTP_ENGINE
	auto ll = run_llhttp(c, 0, false);
	std::printf("-- llhttp%s%s\n%s", ll.note.empty() ? "" : ": ", ll.note.c_str(), diff(c.expected, ll.events).c_str());
	auto lls = run_llhttp(c, 0, true);
	std::printf("-- llhttp-strict%s%s\n%s", lls.note.empty() ? "" : ": ", lls.note.c_str(), diff(c.expected, lls.events).c_str());
#endif
}

}  // namespace

int main(int argc, char** argv) {
#if !HTTP_PARSER_STRICT
	// The non-strict build (HTTP_PARSER_STRICT=0) skips checks llhttp makes, so the
	// divergence list does not describe it.
	std::printf("skipped: the divergence list describes the strict build\n");
	return 77;
#endif
	bool report = argc > 1 && std::strcmp(argv[1], "--report") == 0;
	if (argc > 2 && std::strcmp(argv[1], "--case") == 0) {
		for (auto& c : cases) {
			if (std::string_view(c.location) == argv[2]) show_case(c);
		}
		return 0;
	}
	const char* div_path = report ? (argc > 2 ? argv[2] : nullptr) : (argc > 1 ? argv[1] : nullptr);
	std::map<std::string, Listed> listed;
	if (div_path) listed = load_divergences(div_path);

	int failures = 0, differ = 0, llhttp_bad = 0;
	std::set<std::string> seen;
	std::string tsv = "location\ttype\texpected\tours\tllhttp-strict\tcategory\ttitle\n";
	for (auto& c : cases) {
		std::string want = expected_for_api(c);
		Result ours = run_ours(c, 0);
		Result bytewise = run_ours(c, 1);
		if (bytewise.events != ours.events) {
			std::string key = std::string("split:") + c.location;
			if (listed.count(key)) {
				seen.insert(key);
			} else {
				++failures;
				std::printf("FAIL %s: one byte at a time differs from one buffer, and it is not listed as %s\n%s",
					c.location, key.c_str(), diff(ours.events, bytewise.events).c_str());
			}
		}
		bool d = ours.events != want;
		auto it = listed.find(c.location);
		if (d) {
			++differ;
			seen.insert(c.location);
		}
		std::string ll_strict = "-";
#ifdef HAVE_LLHTTP_ENGINE
		Result ll = run_llhttp(c, 0, false);
		if (ll.events != c.expected) {
			++llhttp_bad;
			++failures;
			std::printf("FAIL %s: llhttp does not reproduce its own log (harness bug)\n%s", c.location, diff(c.expected, ll.events).c_str());
		}
		ll_strict = verdict(run_llhttp(c, 0, true).events);
#endif
		std::string category = it != listed.end() ? it->second.category : (d ? "UNLISTED" : "");
		if (d || report) {
			tsv += std::string(c.location) + "\t" + c.type + "\t" + verdict(want) + "\t" + verdict(ours.events) + "\t" +
				ll_strict + "\t" + category + "\t" + c.title + "\n";
		}
		if (report && d) {
			std::printf("DIFF %s %s [%s] %s\n  llhttp: %s\n  ours:   %s\n%s", c.location, c.title, c.type, category.c_str(), c.note,
				ours.note.c_str(), diff(want, ours.events).c_str());
		}
		if (!report && d && it == listed.end()) {
			++failures;
			std::printf("FAIL %s (%s): differs from llhttp and is not in the divergence list\n  llhttp: %s\n  ours:   %s\n%s",
				c.location, c.title, c.note, ours.note.c_str(), diff(want, ours.events).c_str());
		}
	}
	if (!report && div_path) {
		for (auto& [loc, l] : listed) {
			if (!seen.count(loc)) {
				++failures;
				std::printf("FAIL %s: listed as %s but now matches llhttp; remove it from the list\n", loc.c_str(), l.category.c_str());
			}
		}
	}
	if (report) {
		std::printf("\n%s", tsv.c_str());
		std::map<std::string, int> per;
		for (auto& [loc, l] : listed) {
			if (seen.count(loc)) per[l.category]++;
		}
		for (auto& [cat, n] : per) std::printf("category\t%s\t%d\n", cat.c_str(), n);
	}
	std::printf("%zu cases: %d differ from llhttp (%zu listed)", std::size(cases), differ, listed.size());
#ifdef HAVE_LLHTTP_ENGINE
	std::printf(", llhttp reproduces %zu of %zu logs", std::size(cases) - llhttp_bad, std::size(cases));
#endif
	std::printf("\n");
	if (failures) {
		std::printf("%d conformance failures\n", failures);
		return 1;
	}
	if (!report) std::printf("all http-parser conformance checks passed\n");
	return 0;
}
