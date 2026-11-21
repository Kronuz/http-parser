// The hand-written corpus and the 80 KB header-limit cases of the differential test (see diff.cc).
// ---------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------
#define LIT(s) std::string(s, sizeof(s) - 1)  // a literal that may hold NULs

std::vector<Seed> corpus() {
	std::vector<Seed> v;
	auto req = [&](const char* name, std::string s) { v.push_back({ name, std::move(s), HTTP_REQUEST }); };
	auto res = [&](const char* name, std::string s) { v.push_back({ name, std::move(s), HTTP_RESPONSE }); };

	const char* methods[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "COPY", "LOCK", "MOVE", "PATCH",
		"SEARCH", "UNLOCK", "PURGE", "LINK", "UNLINK", "COUNT", "DUMP", "FLUSH", "INFO", "QUIT", "RESTORE", "WAL", "CLOSE", "CHECK",
		"COMMIT", "OPEN", "UPDATE", "UPSERT", "BREW", "GE", "GETX", "" };
	for (const char* m : methods) req("method", std::string(m) + " /x?y=1 HTTP/1.1\r\nHost: h\r\n\r\n");

	req("small", "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.4\r\nAccept: */*\r\n\r\n");
	req("browser", "GET /search?q=kronuz&lang=en HTTP/1.1\r\nHost: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\n"
		"Accept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\n"
		"Cookie: session=abcdef0123456789abcdef0123456789; theme=dark; tracking=1234567890abcdef\r\n"
		"Referer: https://www.example.com/previous/page?with=query\r\nUpgrade-Insecure-Requests: 1\r\n"
		"Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\n\r\n");
	req("post-cl", "POST /api/v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\":[1,2]} ");
	req("post-cl-0", "POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("post-cl-dup", "POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc");
	req("post-cl-bad", "POST /x HTTP/1.1\r\nContent-Length: 3x\r\n\r\nabc");
	req("post-cl-sp", "POST /x HTTP/1.1\r\nContent-Length:   3  \r\n\r\nabc");
	req("post-cl-huge", "POST /x HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\nabc");
	req("post-cl-big", "POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\nabc");
	req("chunked", "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3;ext=1\r\nabc\r\nA\r\n0123456789\r\n0\r\nTrailer: v\r\n\r\n");
	req("chunked-both", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
	req("chunked-gzip", "POST /c HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n");
	req("chunked-badsize", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n");
	req("chunked-bigsize", "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\n");
	req("abs-uri", "GET http://user:pw@host:8080/p/a/t/h?query=string#hash HTTP/1.1\r\nHost: host\r\n\r\n");
	req("abs-uri-v6", "GET http://[::1]:80/x HTTP/1.1\r\n\r\n");
	req("abs-uri-at-at", "GET http://a@b@c/ HTTP/1.1\r\n\r\n");
	req("connect", "CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n");
	req("connect-tail", "CONNECT a:1 HTTP/1.1\r\n\r\nrest of the stream");
	req("options-star", "OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n");
	req("url-high", "GET /caf\xc3\xa9/\xe2\x82\xac?q=\xff HTTP/1.1\r\nHost: h\r\n\r\n");
	req("url-query-frag", "GET /a/b?x=1?y=2#frag?x#y HTTP/1.1\r\n\r\n");
	req("url-percent", "GET /a%20b%zz?c=%7e HTTP/1.1\r\n\r\n");
	req("url-bad", "GET /a b HTTP/1.1\r\n\r\n");
	req("url-tab", "GET /a\tb HTTP/1.1\r\n\r\n");
	req("url-ff", "GET /a\fb HTTP/1.1\r\n\r\n");
	req("url-nul", LIT("GET /a\0b HTTP/1.1\r\n\r\n"));
	req("url-spaces", "GET   /sp   HTTP/1.1\r\n\r\n");
	req("http09", "GET /\r\n");
	req("http09-lf", "GET /\n");
	req("http10", "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
	req("http10-plain", "GET / HTTP/1.0\r\n\r\nGET / HTTP/1.0\r\n\r\n");
	req("http11-close", "GET / HTTP/1.1\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("http-ver-bad", "GET / HTTP/x.1\r\n\r\n");
	req("http-ver-big", "GET / HTTP/1000.1\r\n\r\n");
	req("http-ver-multi", "GET / HTTP/12.34\r\n\r\n");
	req("http-ver-zero", "GET / HTTP/0.9\r\n\r\n");
	req("http-ver-lower", "GET / http/1.1\r\n\r\n");
	req("upgrade", "GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nframes");
	req("upgrade-multi", "GET /ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nframes");
	req("conn-multi", "GET / HTTP/1.1\r\nConnection: foo, close, bar\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("conn-multi2", "GET / HTTP/1.1\r\nConnection: keep-alive , close\r\n\r\n");
	req("conn-case", "GET / HTTP/1.1\r\nCoNnEcTiOn: KeEp-AlIvE\r\nCONTENT-LENGTH: 2\r\n\r\nhi");
	req("conn-near", "GET / HTTP/1.1\r\nConnectio: close\r\nConnectionx: close\r\nConnection : close\r\nconnection:close\r\n\r\n");
	req("proxy-conn", "GET / HTTP/1.1\r\nProxy-Connection: close\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("proxy-near", "GET / HTTP/1.1\r\nProxy-Connectio: close\r\nProxy-Connectionx: 1\r\nProx: 1\r\n\r\n");
	req("te-near", "GET / HTTP/1.1\r\nTransfer-Encodin: chunked\r\nTransfer-Encodingx: chunked\r\nTransfer-Encoding: chunke\r\nTransfer-Encoding: chunkedx\r\n\r\n");
	req("upgrade-near", "GET / HTTP/1.1\r\nUpgrad: 1\r\nUpgradex: 1\r\nUpgrade : 1\r\nUpgrade:1\r\n\r\n");
	req("cl-near", "GET / HTTP/1.1\r\nContent-Lengt: 1\r\nContent-Lengthx: 1\r\nContent-Type: a\r\nCont: 1\r\nCo: 1\r\n\r\n");
	req("folded", "GET / HTTP/1.1\r\nX-A: one\r\n two\r\n\tthree\r\nX-B: b\r\n\r\n");
	req("folded-empty", "GET / HTTP/1.1\r\nX-A:\r\n  value\r\nX-B:\r\n\r\n");
	req("empty-values", "GET / HTTP/1.1\r\nX-Empty:\r\nX-Empty2: \r\nX-Empty3:\t\r\n\r\n");
	req("no-space", "GET / HTTP/1.1\r\nFoo:bar\r\nBaz:\tqux\r\n\r\n");
	req("trailing-ws", "GET / HTTP/1.1\r\nFoo: bar  \t \r\n\r\n");
	req("bare-lf", "GET / HTTP/1.1\nHost: x\nX: y\n\n");
	req("mixed-eol", "GET / HTTP/1.1\r\nHost: x\nX: y\r\n\n");
	req("bare-cr", "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n");
	req("bare-cr-end", "GET / HTTP/1.1\r\nHost: a\r\r\n\r\n");
	req("nul-value", LIT("GET / HTTP/1.1\r\nX: a\0b\r\n\r\n"));
	req("nul-value-first", LIT("GET / HTTP/1.1\r\nX: \0b\r\n\r\n"));
	req("ctl-value", "GET / HTTP/1.1\r\nX: a\x01\x1f\x7f z\r\n\r\n");
	req("ctl-value-first", "GET / HTTP/1.1\r\nX: \x01z\r\n\r\n");
	req("del-value-first", "GET / HTTP/1.1\r\nX: \x7fz\r\n\r\n");
	req("high-value", "GET / HTTP/1.1\r\nX: caf\xc3\xa9 \xff\xfe\r\n\r\n");
	req("tab-value", "GET / HTTP/1.1\r\nX: a\tb\tc\r\n\r\n");
	req("bad-name", "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n");
	req("bad-name2", "GET / HTTP/1.1\r\nBad(Name): x\r\n\r\n");
	req("name-no-colon", "GET / HTTP/1.1\r\nBadName\r\n\r\n");
	req("name-high", "GET / HTTP/1.1\r\nX\xc3\xa9: x\r\n\r\n");
	req("name-colon-first", "GET / HTTP/1.1\r\n: x\r\n\r\n");
	req("long-value-300", "GET / HTTP/1.1\r\nX: " + std::string(300, 'v') + "\r\nY: " + std::string(64, 'w') + "\r\n\r\n");
	req("pipelined", "GET /1 HTTP/1.1\r\nHost: a\r\n\r\n\r\nGET /2 HTTP/1.1\r\nHost: b\r\n\r\n\nPOST /3 HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"
		"GET /4 HTTP/1.1\r\n\r\n");
	req("leading-crlf", "\r\n\r\nGET / HTTP/1.1\r\n\r\n");
	req("empty", "");
	req("just-crlf", "\r\n");
	req("garbage", LIT("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"));
	req("req-or-res", "HEAD / HTTP/1.1\r\n\r\n");
	req("h-start", "H");

	res("res-200", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
	res("res-204", "HTTP/1.1 204 No Content\r\nX: y\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\n");
	res("res-100", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
	res("res-eof", "HTTP/1.0 200 OK\r\nServer: x\r\n\r\nbody until the end of the stream");
	res("res-chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nExpires: never\r\n\r\n");
	res("res-close", "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 2\r\n\r\nno");
	res("res-nostatus-text", "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n");
	res("res-weird-text", "HTTP/1.1 200 O\xffK \t!\r\nContent-Length: 0\r\n\r\n");
	res("res-bad-status", "HTTP/1.1 2x0 OK\r\n\r\n");
	res("res-bad-version", "HTTP/1.x 200 OK\r\n\r\n");
	res("res-lf", "HTTP/1.1 200 OK\nContent-Length: 1\n\nx");
	res("res-upgrade", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nframes");
	res("res-304-cl", "HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n");
	res("res-headers", "HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n"
		"ETag: \"34aa387-d-1568eb00\"\r\nAccept-Ranges: bytes\r\nContent-Length: 51\r\nVary: Accept-Encoding\r\nContent-Type: text/plain\r\n\r\n"
		"Hello World! My payload includes a trailing CRLF.\r\n");
	// Framing a 1xx, 204 or 304 response does not have, and Upgrade outside a 101.
	res("res-101-cl", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbodyproto");
	res("res-304-te", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
	res("res-304-te-next", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
	res("res-te-cl", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
	res("res-cl-te", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: identity\r\n\r\nhello");
	res("res-200-upgrade", "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: h2c\r\nContent-Length: 4\r\n\r\nbody");
	// Transfer-Encoding before HTTP/1.1, then another message on the same connection.
	req("http10-te", "POST / HTTP/1.0\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
		"GET /admin HTTP/1.1\r\nHost: a\r\n\r\n");
	res("res-http10-te", "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
	return v;
}

// Requests built around the 80 KB header limit: the byte at which the parser gives up must agree.
void limit_cases(const std::function<void(const std::string&, const std::string&, enum http_parser_type)>& add) {
	const long L = HTTP_MAX_HEADER_SIZE;
	for (long d = -24; d <= 24; ++d) {
		add("limit-url", "GET /" + std::string(L - 15 + d, 'a') + " HTTP/1.1\r\n\r\n", HTTP_REQUEST);
		add("limit-value", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-big", "GET / HTTP/1.1\r\nX: " + std::string(L + 40 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-edge", "GET / HTTP/1.1\r\nX: " + std::string(L + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-value-bigcr", "GET / HTTP/1.1\r\nX: " + std::string(L + 40 + d, 'a') + "\r\nY: b\r\n\r\n", HTTP_REQUEST);
		add("limit-value-lws", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a') + "\r\n \r\n\r\n", HTTP_REQUEST);
		add("limit-name", "GET / HTTP/1.1\r\n" + std::string(L - 36 + d, 'a') + ": x\r\n\r\n", HTTP_REQUEST);
		add("limit-value-conn", "GET / HTTP/1.1\r\nConnection: " + std::string(L - 36 + d, 'a') + "\r\n\r\n", HTTP_REQUEST);
		add("limit-chunk-size", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + std::string(L - 3 + d, '0') + "5\r\nhello\r\n0\r\n\r\n", HTTP_REQUEST);
		add("limit-chunk-ext", "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5;" + std::string(L - 5 + d, 'e') + "\r\nhello\r\n0\r\n\r\n", HTTP_REQUEST);
		add("limit-value-noeol", "GET / HTTP/1.1\r\nX: " + std::string(L - 36 + d, 'a'), HTTP_REQUEST);
		std::string many = "GET / HTTP/1.1\r\n";
		while ((long) many.size() < L - 20 + d) many += "X-Header: 0123456789012345678901234567890123456789\r\n";
		add("limit-many", many + "\r\n", HTTP_REQUEST);
		add("limit-status", "HTTP/1.1 200 " + std::string(L - 20 + d, 'a') + "\r\n\r\n", HTTP_RESPONSE);
	}
}

