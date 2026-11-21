// Random grammar-built messages and their mutations for the differential test (see diff.cc).
// ---------------------------------------------------------------------------
// Random grammar-built messages.
// ---------------------------------------------------------------------------
std::string pick(const std::vector<std::string>& v) { return v[rnd(v.size())]; }

std::string random_value() {
	static const std::vector<std::string> fixed = { "keep-alive", "close", "Upgrade", "keep-alive, Upgrade", "close, TE", "chunked", "gzip, chunked",
		"websocket", "0", "5", "12", "text/html; charset=utf-8", "", " ", "a b c", "*/*", "max-age=0", "Keep-Alive", "CLOSE", "upgrade,", "x,close", "keep-alive,",
		"chunked, gzip", "chunkedx", "chunke", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" };
	if (rnd(3) != 0) return pick(fixed);
	std::string s;
	size_t n = rnd(rnd(3) == 0 ? 90 : 24);
	static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.,;:=/\"'()[]\t";
	for (size_t i = 0; i < n; ++i) s += alpha[rnd(sizeof alpha - 1)];
	if (rnd(10) == 0 && !s.empty()) s[rnd(s.size())] = interesting[rnd(sizeof interesting)];
	return s;
}

std::string random_name() {
	static const std::vector<std::string> fixed = { "Host", "User-Agent", "Connection", "Content-Length", "Transfer-Encoding", "Upgrade", "Proxy-Connection",
		"Cookie", "X-Foo-Bar", "Accept", "connection", "CONTENT-LENGTH", "Content-Type", "Cache-Control", "transfer-encoding", "UPGRADE", "Co", "Con", "Conn" };
	if (rnd(3) != 0) return pick(fixed);
	std::string s;
	size_t n = 1 + rnd(20);
	static const char tok[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!#$%&'*+^`|~";
	for (size_t i = 0; i < n; ++i) s += tok[rnd(sizeof tok - 1)];
	return s;
}

std::string random_message(bool request) {
	std::string eol = rnd(12) == 0 ? "\n" : "\r\n";
	std::string m;
	if (request) {
		static const std::vector<std::string> methods = { "GET", "GET", "GET", "POST", "PUT", "HEAD", "DELETE", "CONNECT", "OPTIONS", "PATCH", "COUNT", "UPSERT", "BREW" };
		static const std::vector<std::string> urls = { "/", "/index.html", "/a/b/c?x=1&y=2", "/q?a=b#frag", "*", "http://h:80/p?q#f", "http://u@h/", "h:443", "/\xc3\xa9", "/a%20b", "/a;b=c,d" };
		m = pick(methods) + " " + pick(urls) + " HTTP/1." + (rnd(5) == 0 ? "0" : "1") + eol;
	} else {
		static const std::vector<std::string> codes = { "200 OK", "204 No Content", "304 Not Modified", "100 Continue", "404 Not Found", "101 Switching Protocols", "200" };
		m = "HTTP/1." + std::string(rnd(5) == 0 ? "0" : "1") + " " + pick(codes) + eol;
	}
	size_t nh = rnd(9);
	bool chunked = false;
	long clen = -1;
	for (size_t i = 0; i < nh; ++i) {
		std::string name = random_name(), value = random_value();
		if (strcasecmp(name.c_str(), "content-length") == 0 && rnd(4) != 0) { clen = (long) rnd(20); value = std::to_string(clen); }
		if (strcasecmp(name.c_str(), "transfer-encoding") == 0 && rnd(2)) { value = "chunked"; chunked = true; }
		std::string sp = rnd(8) == 0 ? "" : (rnd(10) == 0 ? "\t" : (rnd(10) == 0 ? "   " : " "));
		m += name + ":" + sp + value;
		if (rnd(10) == 0) m += eol + " " + random_value();
		m += eol;
	}
	m += eol;
	if (chunked) {
		size_t nc = rnd(4);
		for (size_t i = 0; i < nc; ++i) {
			size_t n = rnd(40);
			char b[16]; snprintf(b, sizeof b, rnd(2) ? "%zx" : "%zX", n);
			m += b; if (rnd(6) == 0) m += ";ext=1";
			m += "\r\n" + std::string(n, 'z') + "\r\n";
		}
		m += "0\r\n";
		if (rnd(3) == 0) m += "T: v\r\n";
		m += "\r\n";
	} else if (clen > 0) {
		m += std::string(rnd(clen + 3), 'b');
	}
	return m;
}

std::string mutate(std::string s) {
	size_t k = 1 + rnd(3);
	for (size_t i = 0; i < k && !s.empty(); ++i) {
		size_t at = rnd(s.size());
		switch (rnd(4)) {
			case 0: s[at] = interesting[rnd(sizeof interesting)]; break;
			case 1: s.erase(at, 1); break;
			case 2: s.insert(s.begin() + at, interesting[rnd(sizeof interesting)]); break;
			default: s.resize(at); break;
		}
	}
	return s;
}

const enum http_parser_type types[] = { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };

