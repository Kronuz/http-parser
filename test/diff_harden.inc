// The hardening sweep: inputs the strict parser must stop on, with their oracle errno (see diff.cc).
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

