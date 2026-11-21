/* Parse-loop states for the request line: method, URL, version (license: see http_parser.cc). */
      case s_start_req:
      {
        if (ch == CR || ch == LF)
          break;
        parser->flags = 0;
        parser->extra_flags = 0;
        parser->content_length = ULLONG_MAX;

        if unlikely(!IS_ALPHA(ch)) {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        parser->method = (enum http_method) 0;
        parser->index = 1;
        switch (ch) {
          case 'C': parser->method = HTTP_COUNT; /* or COPY, CONNECT, COMMIT, CLOSE, CHECK */ break;
          case 'D': parser->method = HTTP_DUMP; /* or DELETE */ break;
          case 'F': parser->method = HTTP_FLUSH; break;
          case 'G': parser->method = HTTP_GET; break;
          case 'H': parser->method = HTTP_HEAD; break;
          case 'I': parser->method = HTTP_INFO; break;
          case 'L': parser->method = HTTP_LOCK; /* or LINK */ break;
          case 'M': parser->method = HTTP_MOVE; break;
          case 'O': parser->method = HTTP_OPTIONS; /* or OPEN */ break;
          case 'P': parser->method = HTTP_PUT; /* or PURGE, POST, PATCH */ break;
          case 'Q': parser->method = HTTP_QUIT; break;
          case 'R': parser->method = HTTP_RESTORE; break;
          case 'S': parser->method = HTTP_SEARCH; /* or SEARCH */ break;
          case 'T': parser->method = HTTP_TRACE; break;
          case 'U': parser->method = HTTP_UNLOCK; /* or UNLINK, UPDATE, UPSERT */ break;
          case 'W': parser->method = HTTP_WAL; break;
          default:
            SET_ERRNO(HPE_INVALID_METHOD);
            goto error;
        }
        UPDATE_STATE(s_req_method);

        CALLBACK_NOTIFY(message_begin);

        break;
      }

      case s_req_method:
      {
        const char *matcher;
        if unlikely(ch == '\0') {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        matcher = method_strings[parser->method];
        if (ch == ' ' && matcher[parser->index] == '\0') {
          UPDATE_STATE(s_req_spaces_before_url);
        } else if (ch == matcher[parser->index]) {
          ; /* nada */
        } else if (IS_ALPHA(ch)) {

          switch (parser->method << 16 | parser->index << 8 | ch) {
#define XX(meth, pos, ch, new_meth) \
            case (HTTP_##meth << 16 | pos << 8 | ch): \
              parser->method = HTTP_##new_meth; break;

            XX(COUNT,     1, 'L', CLOSE)
            XX(COUNT,     1, 'H', CHECK)
            XX(COUNT,     2, 'M', COMMIT)
            XX(COUNT,     2, 'N', CONNECT)
            XX(COUNT,     2, 'P', COPY)
            XX(DUMP,      1, 'E', DELETE)
            XX(LOCK,      1, 'I', LINK)
            XX(OPTIONS,   2, 'E', OPEN)
            XX(PUT,       1, 'O', POST)
            XX(PUT,       1, 'A', PATCH)
            XX(PUT,       2, 'R', PURGE)
            XX(UNLOCK,    1, 'P', UPDATE)
            XX(UPDATE,    2, 'S', UPSERT)
            XX(UNLOCK,    3, 'I', UNLINK)
#undef XX

            default:
              SET_ERRNO(HPE_INVALID_METHOD);
              goto error;
          }
        } else {
          SET_ERRNO(HPE_INVALID_METHOD);
          goto error;
        }

        ++parser->index;
        break;
      }

      case s_req_spaces_before_url:
      {
        if (ch == ' ') break;

        MARK(url);
        if (parser->method == HTTP_CONNECT) {
          UPDATE_STATE(s_req_server_start);
        }

        UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
        if unlikely(CURRENT_STATE() == s_dead) {
          SET_ERRNO(HPE_INVALID_URL);
          goto error;
        }

        break;
      }

      case s_req_schema:
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      {
        switch (ch) {
          /* No whitespace allowed here */
          case ' ':
          case CR:
          case LF:
            SET_ERRNO(HPE_INVALID_URL);
            goto error;
          default:
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
            if unlikely(CURRENT_STATE() == s_dead) {
              SET_ERRNO(HPE_INVALID_URL);
              goto error;
            }
        }

        break;
      }

      case s_req_server:
      case s_req_server_with_at:
      case s_req_path:
      case s_req_query_string_start:
      case s_req_query_string:
      case s_req_fragment_start:
      case s_req_fragment:
      {
        switch (ch) {
          case ' ':
            UPDATE_STATE(s_req_http_start);
            CALLBACK_DATA(url);
            break;
          case LF:
            if (!lenient) {
              SET_ERRNO(HPE_CR_EXPECTED);
              goto error;
            }
            /* FALLTHROUGH */
          case CR:
            /* Unless lenient: a request line has a version. HTTP/0.9 has no
             * headers, and this would read them (RFC 9112 section 3) */
            if (!lenient) {
              SET_ERRNO(HPE_INVALID_VERSION);
              goto error;
            }
            parser->http_major = 0;
            parser->http_minor = 9;
            UPDATE_STATE((ch == CR) ?
              s_req_line_almost_done :
              s_header_field_start);
            CALLBACK_DATA(url);
            break;
          default:
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
            if unlikely(CURRENT_STATE() == s_dead) {
              SET_ERRNO(HPE_INVALID_URL);
              goto error;
            }

            switch (CURRENT_STATE()) {
              case s_req_path:
              case s_req_query_string:
              case s_req_fragment:
              {
                /* In these states every further URL character keeps the state
                 * as it is, so take the whole run at once. Each byte still
                 * counts against the header size, and the run stops short of
                 * the limit so that the byte which crosses it is handled (and
                 * reported) by the loop above. */
                const char* q = p + 1;
                size_t n = (size_t) ((data + len) - q);
                const size_t room = HTTP_MAX_HEADER_SIZE - parser->nread;

                if (n > room) n = room;
                q = skip_url_chars(q, q + n);
                parser->nread += (uint32_t) (q - (p + 1));
                p = q - 1;
                break;
              }
              default:
                break;
            }
        }
        break;
      }

      case s_req_http_start:
        switch (ch) {
          case 'H':
            /* The usual end of a request line, "HTTP/d.d" and its CRLF, in one
             * step: the same fields, state and header-size count as the
             * states below leave. Anything else takes the slow path. */
            if ((data + len) - p >= 10 &&
                parser->nread + 9 <= HTTP_MAX_HEADER_SIZE &&
                memcmp(p, "HTTP/", 5) == 0 && p[5] >= '1' && p[5] <= '9' &&
                p[6] == '.' && IS_NUM(p[7]) && p[8] == CR && p[9] == LF &&
                (lenient || KNOWN_VERSION(p[5] - '0', p[7] - '0'))) {
              parser->http_major = (unsigned short) (p[5] - '0');
              parser->http_minor = (unsigned short) (p[7] - '0');
              parser->nread += 9;
              p += 9;
              UPDATE_STATE(s_header_field_start);
              NEXTCHAR_COUNTED();
              goto header_field_start;
            }
            UPDATE_STATE(s_req_http_H);
            break;
          case ' ':
            break;
          default:
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
        }
        break;

      case s_req_http_H:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_req_http_HT);
        NEXTHEADERCHAR();

      case s_req_http_HT:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_req_http_HTT);
        NEXTHEADERCHAR();

      case s_req_http_HTT:
        STRICT_CHECK(ch != 'P');
        UPDATE_STATE(s_req_http_HTTP);
        NEXTHEADERCHAR();

      case s_req_http_HTTP:
        STRICT_CHECK(ch != '/');
        UPDATE_STATE(s_req_first_http_major);
        break;

      /* first digit of major HTTP version */
      case s_req_first_http_major:
        if unlikely(ch < '1' || ch > '9') {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major = ch - '0';
        UPDATE_STATE(s_req_http_major);
        break;

      /* major HTTP version or dot */
      case s_req_http_major:
      {
        if (ch == '.') {
          UPDATE_STATE(s_req_first_http_minor);
          break;
        }

        /* Unless lenient: one digit (RFC 9112: HTTP/DIGIT.DIGIT) */
        if unlikely(!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major *= 10;
        parser->http_major += ch - '0';

        if unlikely(parser->http_major > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      /* first digit of minor HTTP version */
      case s_req_first_http_minor:
        if unlikely(!IS_NUM(ch)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor = ch - '0';
        /* Unless lenient: the version is complete, and must be a known one */
        if (!lenient && !VERSION_KNOWN(parser)) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }
        UPDATE_STATE(s_req_http_minor);
        break;

      /* minor HTTP version or end of request line */
      case s_req_http_minor:
      {
        if (ch == CR) {
          UPDATE_STATE(s_req_line_almost_done);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_field_start);
          break;
        }

        /* XXX allow spaces after digit? */

        if unlikely(!IS_NUM(ch) || !lenient) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        if unlikely(parser->http_minor > 999) {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        break;
      }

      /* end of request line */
      case s_req_line_almost_done:
      {
        if unlikely(ch != LF) {
          SET_ERRNO(HPE_LF_EXPECTED);
          goto error;
        }

        UPDATE_STATE(s_header_field_start);
        break;
      }

