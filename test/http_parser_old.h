// Declarations of the frozen reference parser (test/http_parser_old.cc), which is
// a verbatim copy of http_parser.cc taken before the header-scan change, with its
// external symbols renamed so it links beside the live parser. Used by
// test/diff.cc and bench/bench.cc.
#pragma once

#include "http_parser.h"

extern "C" {
size_t http_parser_old_execute(http_parser* parser, const http_parser_settings* settings, const char* data, size_t len);
void http_parser_old_init(http_parser* parser, enum http_parser_type type);
void http_parser_old_settings_init(http_parser_settings* settings);
void http_parser_old_pause(http_parser* parser, int paused);
int http_parser_old_should_keep_alive(const http_parser* parser);
int http_parser_old_parse_url(const char* buf, size_t buflen, int is_connect, struct http_parser_url* u);
}
