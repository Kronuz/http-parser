/* Parse-loop states for the response line: start, version, status code and reason (license: see http_parser.cc). */
      case s_dead:
        /* this state is used after a 'Connection: close' message
         * the parser will error out if it reads another message
         */
        if likely(ch == CR || ch == LF)
          break;

        SET_ERRNO(HPE_CLOSED_CONNECTION);
        goto error;

      case s_start_req_or_res:
      {
        if (ch == CR || ch == LF)
          break;
        parser->flags = 0;
        parser->content_length = ULLONG_MAX;

        if (ch == 'H') {
          UPDATE_STATE(s_res_or_resp_H);

          CALLBACK_NOTIFY(message_begin);
        } else {
          parser->type = HTTP_REQUEST;
          UPDATE_STATE(s_start_req);
          REEXECUTE();
        }

        break;
      }

      case s_res_or_resp_H:
        if (ch == 'T') {
          parser->type = HTTP_RESPONSE;
          UPDATE_STATE(s_res_HT);
        } else {
          if unlikely(ch != 'E') {
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
          }

          parser->type = HTTP_REQUEST;
          parser->method = HTTP_HEAD;
          parser->index = 2;
          UPDATE_STATE(s_req_method);
        }
        break;

      case s_start_res:
      {
        parser->flags = 0;
        parser->extra_flags = 0;
        parser->content_length = ULLONG_MAX;

        switch (ch) {
          case 'H':
            UPDATE_STATE(s_res_H);
            break;

          case CR:
          case LF:
            break;

          default:
            SET_ERRNO(HPE_INVALID_CONSTANT);
            goto error;
        }

        CALLBACK_NOTIFY(message_begin);
        break;
      }

      case s_res_H:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_res_HT);
        NEXTHEADERCHAR();

      case s_res_HT:
        STRICT_CHECK(ch != 'T');
        UPDATE_STATE(s_res_HTT);
        NEXTHEADERCHAR();

      case s_res_HTT:
        STRICT_CHECK(ch != 'P');
        UPDATE_STATE(s_res_HTTP);
        NEXTHEADERCHAR();

      case s_res_HTTP:
        STRICT_CHECK(ch != '/');
        UPDATE_STATE(s_res_first_http_major);
        break;

      case s_res_first_http_major:
        if unlikely(ch < '0' || ch > '9') {
          SET_ERRNO(HPE_INVALID_VERSION);
          goto error;
        }

        parser->http_major = ch - '0';
        UPDATE_STATE(s_res_http_major);
        break;

      /* major HTTP version or dot */
      case s_res_http_major:
      {
        if (ch == '.') {
          UPDATE_STATE(s_res_first_http_minor);
          break;
        }

        /* Unless lenient: one digit (RFC 9112: HTTP/DIGIT.DIGIT) */
        if (!IS_NUM(ch) || !lenient) {
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
      case s_res_first_http_minor:
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
        UPDATE_STATE(s_res_http_minor);
        break;

      /* minor HTTP version or end of request line */
      case s_res_http_minor:
      {
        if (ch == ' ') {
          UPDATE_STATE(s_res_first_status_code);
          break;
        }

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

      case s_res_first_status_code:
      {
        if (!IS_NUM(ch)) {
          /* Unless lenient: one space before the status (RFC 9112 section 4) */
          if (ch == ' ' && lenient) {
            break;
          }

          SET_ERRNO(HPE_INVALID_STATUS);
          goto error;
        }
        parser->status_code = ch - '0';
        UPDATE_STATE(s_res_status_code);
        break;
      }

      case s_res_status_code:
      {
        if (!IS_NUM(ch)) {
          /* Unless lenient: three digits (RFC 9112 section 4) */
          if (!lenient && parser->status_code < 100) {
            SET_ERRNO(HPE_INVALID_STATUS);
            goto error;
          }
          switch (ch) {
            case ' ':
              UPDATE_STATE(s_res_status_start);
              break;
            case CR:
              UPDATE_STATE(s_res_line_almost_done);
              break;
            case LF:
              if (!lenient) {
                SET_ERRNO(HPE_CR_EXPECTED);
                goto error;
              }
              UPDATE_STATE(s_header_field_start);
              break;
            default:
              SET_ERRNO(HPE_INVALID_STATUS);
              goto error;
          }
          break;
        }

        parser->status_code *= 10;
        parser->status_code += ch - '0';

        if unlikely(parser->status_code > 999) {
          SET_ERRNO(HPE_INVALID_STATUS);
          goto error;
        }

        break;
      }

      case s_res_status_start:
      {
        if (ch == CR) {
          UPDATE_STATE(s_res_line_almost_done);
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

        MARK(status);
        UPDATE_STATE(s_res_status);
        parser->index = 0;
        break;
      }

      case s_res_status:
        if (ch == CR) {
          UPDATE_STATE(s_res_line_almost_done);
          CALLBACK_DATA(status);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_field_start);
          CALLBACK_DATA(status);
          break;
        }

        break;

      case s_res_line_almost_done:
        STRICT_CHECK(ch != LF);
        UPDATE_STATE(s_header_field_start);
        break;

