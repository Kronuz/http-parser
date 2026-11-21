/* Parse-loop states for header fields and values, header termination and the body decision (license: see http_parser.cc). */
      header_field_start:
      case s_header_field_start:
      {
        if (ch == CR) {
          UPDATE_STATE(s_headers_almost_done);
          NEXTCHAR_COUNTED();
          goto headers_almost_done;
        }

        if (ch == LF) {
          /* they might be just sending \n instead of \r\n so this would be
           * the second \n to denote the end of headers*/
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_headers_almost_done);
          goto headers_almost_done;
        }

        c = TOKEN(ch);

        if unlikely(!c) {
          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
          goto error;
        }

        MARK(header_field);

        parser->index = 0;
        UPDATE_STATE(s_header_field);

        switch (c) {
          case 'c':
            parser->header_state = h_C;
            break;

          case 'p':
            parser->header_state = h_matching_proxy_connection;
            break;

          case 't':
            parser->header_state = h_matching_transfer_encoding;
            break;

          case 'u':
            parser->header_state = h_matching_upgrade;
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        NEXTHEADERCHAR();
      }

      case s_header_field:
      {
        const char* start = p;
header_field_begin:
        if ( parser->header_state == h_general ) {
          for (; p != data + len; p++) {
            ch = *p;
            c = TOKEN(ch);

            if (!c)
              break;
          }
        } else {
          for (; p != data + len; p++) {
            ch = *p;
            c = TOKEN(ch);

            if (!c)
              break;

            /* One step of matching a special header name: h_C to h_matching_upgrade
             * compare the byte with the name at parser->index (a table, not a switch:
             * twelve cases make a chain of compares on AArch64, where a jump table needs
             * thirteen), h_connection to h_upgrade take only spaces after the name. */
            const unsigned hs = parser->header_state;
            if (likely(hs - (unsigned) h_C <= (unsigned) (h_matching_upgrade - h_C))) {
              const struct name_matcher &m = name_matchers[hs - h_C];
              parser->index++;
              if (c == m.name[parser->index]) {
                if (parser->index == m.last) {
                  parser->header_state = m.matched;
                }
              } else {
                /* h_CON forks: "con" + 'n' is connection, + 't' content-length */
                parser->header_state = hs == (unsigned) h_CON && c == 't' ? h_matching_content_length : h_general;
              }
            } else if (hs == h_general) {
              --p;
              goto header_field_begin;
            } else {
              assert(hs >= (unsigned) h_connection && hs <= (unsigned) h_upgrade);
              if (ch != ' ') parser->header_state = h_general;
            }
          }
        }
        COUNT_HEADER_SIZE(p - start);

        if (p == data + len) {
          --p;
          break;
        }

        if (ch == ':') {
          UPDATE_STATE(s_header_value_discard_ws);
          CALLBACK_DATA(header_field);
          NEXTCHAR_COUNTED();
          goto header_value_discard_ws;
        }

        SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
        goto error;
      }

      header_value_discard_ws:
      case s_header_value_discard_ws:
        if (ch == ' ' || ch == '\t') {
          NEXTCHAR_COUNTED();
          goto header_value_discard_ws;
        }

        if (ch == CR) {
          UPDATE_STATE(s_header_value_discard_ws_almost_done);
          break;
        }

        if (ch == LF) {
          if (!lenient) {
            SET_ERRNO(HPE_CR_EXPECTED);
            goto error;
          }
          UPDATE_STATE(s_header_value_discard_lws);
          break;
        }

        /* FALLTHROUGH */

      case s_header_value_start:
      {
        /* Unless lenient, every byte of a value is checked, the first one too */
        if (!lenient && !header_char.ok[(unsigned char) ch]) {
          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
          goto error;
        }

        MARK(header_value);

        UPDATE_STATE(s_header_value);
        parser->index = 0;

        c = LOWER(ch);

        switch (parser->header_state) {
          case h_upgrade:
            parser->flags |= F_UPGRADE;
            parser->header_state = h_general;
            break;

          case h_transfer_encoding:
            parser->extra_flags |= F_TRANSFER_ENCODING >> 8;
            /* looking for 'Transfer-Encoding: chunked' */
            if ('c' == c) {
              parser->header_state = h_matching_transfer_encoding_chunked;
            } else {
              parser->header_state = lenient ? h_general : h_transfer_encoding_other;
            }
            break;

          case h_content_length:
            /* Unless lenient: no Content-Length in a trailer section, where it
             * cannot frame the message (RFC 9110 section 6.5.1) */
            if unlikely(!IS_NUM(ch) || (!lenient && (parser->flags & F_TRAILING))) {
              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
              goto error;
            }

            if (parser->flags & F_CONTENTLENGTH) {
              SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);
              goto error;
            }

            parser->flags |= F_CONTENTLENGTH;
            parser->content_length = ch - '0';
            break;

          case h_connection:
            /* looking for 'Connection: keep-alive' */
            if (c == 'k') {
              parser->header_state = h_matching_connection_keep_alive;
            /* looking for 'Connection: close' */
            } else if (c == 'c') {
              parser->header_state = h_matching_connection_close;
            } else if (c == 'u') {
              parser->header_state = h_matching_connection_upgrade;
            } else {
              parser->header_state = h_matching_connection_token;
            }
            break;

          /* Multi-value `Connection` header */
          case h_matching_connection_token_start:
            break;

          default:
            parser->header_state = h_general;
            break;
        }
        NEXTCHAR_COUNTED();
        /* FALLTHROUGH */
      }

      case s_header_value:
      {
        const char* start = p;
        enum header_states h_state = (enum header_states) parser->header_state;
        for (; p != data + len; p++) {
          ch = *p;
          if (ch == CR) {
            UPDATE_STATE(s_header_almost_done);
            parser->header_state = h_state;
            CALLBACK_DATA(header_value);
            break;
          }

          if (ch == LF) {
            if (!lenient) {
              parser->header_state = h_state;
              SET_ERRNO(HPE_CR_EXPECTED);
              goto error;
            }
            UPDATE_STATE(s_header_almost_done);
            COUNT_HEADER_SIZE(p - start);
            parser->header_state = h_state;
            CALLBACK_DATA_NOADVANCE(header_value);
            REEXECUTE();
          }

          if (!lenient && !header_char.ok[(unsigned char) ch]) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }

          c = LOWER(ch);

          switch (h_state) {
            case h_general:
            case h_transfer_encoding_other:
            {
              /* Unless lenient the run also stops at a byte a value may not
               * hold, which the check above then rejects. */
              p = lenient ? find_crlf(p, data, len) : find_value_end(p, data, len);
              --p;

              break;
            }

            case h_connection:
            case h_transfer_encoding:
              assert(0 && "Shouldn't get here.");
              break;

            case h_content_length:
            {
              uint64_t t;

              if (ch == ' ') {
                /* Unless lenient, only spaces may follow the digits
                 * (`Content-Length: 4 2` is not 42) */
                if (!lenient) h_state = h_content_length_ws;
                break;
              }

              if unlikely(!IS_NUM(ch)) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                parser->header_state = h_state;
                goto error;
              }

              t = parser->content_length;
              t *= 10;
              t += ch - '0';

              /* Overflow? Test against a conservative limit for simplicity. */
              if unlikely((ULLONG_MAX - 10) / 10 < parser->content_length) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                parser->header_state = h_state;
                goto error;
              }

              parser->content_length = t;
              break;
            }

            case h_content_length_ws:
              if (ch == ' ') break;
              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
              parser->header_state = h_state;
              goto error;

            /* Transfer-Encoding: chunked */
            case h_matching_transfer_encoding_chunked:
              parser->index++;
              if (parser->index > sizeof(CHUNKED)-1
                  || c != CHUNKED[parser->index]) {
                h_state = lenient ? h_general : h_transfer_encoding_other;
              } else if (parser->index == sizeof(CHUNKED)-2) {
                h_state = h_transfer_encoding_chunked;
              }
              break;

            case h_matching_connection_token_start:
              /* looking for 'Connection: keep-alive' */
              if (c == 'k') {
                h_state = h_matching_connection_keep_alive;
              /* looking for 'Connection: close' */
              } else if (c == 'c') {
                h_state = h_matching_connection_close;
              } else if (c == 'u') {
                h_state = h_matching_connection_upgrade;
              } else if (STRICT_TOKEN(c)) {
                h_state = h_matching_connection_token;
              } else if (c == ' ' || c == '\t') {
                /* Skip lws */
              } else {
                h_state = h_general;
              }
              break;

            /* looking for 'Connection: keep-alive' */
            case h_matching_connection_keep_alive:
              parser->index++;
              if (parser->index > sizeof(KEEP_ALIVE)-1
                  || c != KEEP_ALIVE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(KEEP_ALIVE)-2) {
                h_state = h_connection_keep_alive;
              }
              break;

            /* looking for 'Connection: close' */
            case h_matching_connection_close:
              parser->index++;
              if (parser->index > sizeof(CLOSE)-1 || c != CLOSE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(CLOSE)-2) {
                h_state = h_connection_close;
              }
              break;

            /* looking for 'Connection: upgrade' */
            case h_matching_connection_upgrade:
              parser->index++;
              if (parser->index > sizeof(UPGRADE) - 1 ||
                  c != UPGRADE[parser->index]) {
                h_state = h_matching_connection_token;
              } else if (parser->index == sizeof(UPGRADE)-2) {
                h_state = h_connection_upgrade;
              }
              break;

            case h_matching_connection_token:
              if (ch == ',') {
                h_state = h_matching_connection_token_start;
                parser->index = 0;
              }
              break;

            case h_transfer_encoding_chunked:
              if (ch != ' ') h_state = lenient ? h_general : h_transfer_encoding_other;
              break;

            case h_connection_keep_alive:
            case h_connection_close:
            case h_connection_upgrade:
              if (ch == ',') {
                if (h_state == h_connection_keep_alive) {
                  parser->flags |= F_CONNECTION_KEEP_ALIVE;
                } else if (h_state == h_connection_close) {
                  parser->flags |= F_CONNECTION_CLOSE;
                } else if (h_state == h_connection_upgrade) {
                  parser->flags |= F_CONNECTION_UPGRADE;
                }
                h_state = h_matching_connection_token_start;
                parser->index = 0;
              } else if (ch != ' ') {
                h_state = h_matching_connection_token;
              }
              break;

            default:
              UPDATE_STATE(s_header_value);
              h_state = h_general;
              break;
          }
        }
        parser->header_state = h_state;

        COUNT_HEADER_SIZE(p - start);

        if (p == data + len) {
          --p;
        } else if (CURRENT_STATE() == s_header_almost_done &&
                   (data + len) - p >= 3 &&
                   parser->nread + 2 <= HTTP_MAX_HEADER_SIZE &&
                   p[1] == LF) {
          /* The value ended at a CR (p) that is followed by LF and one more
           * byte: take both now and let s_header_value_lws look at that byte,
           * which is what s_header_almost_done and the next pass would do,
           * with the same header-size count. */
          parser->nread += 2;
          p += 2;
          ch = *p;
          UPDATE_STATE(s_header_value_lws);
          goto header_value_lws;
        }
        break;
      }

      case s_header_almost_done:
      {
        if unlikely(ch != LF) {
          SET_ERRNO(HPE_LF_EXPECTED);
          goto error;
        }

        UPDATE_STATE(s_header_value_lws);
        break;
      }

      header_value_lws:
      case s_header_value_lws:
      {
        if (ch == ' ' || ch == '\t') {
          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */
          if (!lenient) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }
          UPDATE_STATE(s_header_value_start);
          REEXECUTE();
        }

        /* finished the header */
        switch (parser->header_state) {
          case h_connection_keep_alive:
            parser->flags |= F_CONNECTION_KEEP_ALIVE;
            break;
          case h_connection_close:
            parser->flags |= F_CONNECTION_CLOSE;
            break;
          case h_transfer_encoding_chunked:
            /* Unless lenient, a request is chunked once and last: a second
             * Transfer-Encoding header would apply a coding after it. */
            if (!lenient && parser->type == HTTP_REQUEST && (parser->flags & F_CHUNKED)) {
              SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
              goto error;
            }
            parser->flags |= F_CHUNKED;
            break;
          case h_matching_transfer_encoding_chunked:
          case h_transfer_encoding_other:
            /* Unless lenient, a request's Transfer-Encoding is "chunked" and
             * nothing else: this parser decodes no other coding, and the body's
             * length would be unknown (RFC 9112 section 6.3). */
            if (!lenient && (parser->type == HTTP_REQUEST || (parser->flags & F_CHUNKED))) {
              /* nor, in a response, is there a coding after chunked: chunked
               * is the last one (RFC 9112 section 6.1) */
              SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
              goto error;
            }
            break;
          case h_connection_upgrade:
            parser->flags |= F_CONNECTION_UPGRADE;
            break;
          default:
            break;
        }

        UPDATE_STATE(s_header_field_start);
        goto header_field_start;
      }

      case s_header_value_discard_ws_almost_done:
      {
        STRICT_CHECK(ch != LF);
        UPDATE_STATE(s_header_value_discard_lws);
        break;
      }

      case s_header_value_discard_lws:
      {
        if (ch == ' ' || ch == '\t') {
          /* Unless lenient, obs-fold is an error (RFC 9112 section 5.2) */
          if (!lenient) {
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
            goto error;
          }
          UPDATE_STATE(s_header_value_discard_ws);
          break;
        } else {
          switch (parser->header_state) {
            case h_content_length:
              /* Unless lenient, an empty Content-Length is an error */
              if (!lenient) {
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
                goto error;
              }
              break;
            case h_transfer_encoding:
              /* Unless lenient, so is an empty Transfer-Encoding */
              if (!lenient) {
                SET_ERRNO(HPE_INVALID_TRANSFER_ENCODING);
                goto error;
              }
              break;
            case h_connection_keep_alive:
              parser->flags |= F_CONNECTION_KEEP_ALIVE;
              break;
            case h_connection_close:
              parser->flags |= F_CONNECTION_CLOSE;
              break;
            case h_connection_upgrade:
              parser->flags |= F_CONNECTION_UPGRADE;
              break;
            case h_transfer_encoding_chunked:
              parser->flags |= F_CHUNKED;
              break;
            default:
              break;
          }

          /* header value was empty */
          MARK(header_value);
          UPDATE_STATE(s_header_field_start);
          CALLBACK_DATA_NOADVANCE(header_value);
          REEXECUTE();
        }
      }

      headers_almost_done:
      case s_headers_almost_done:
      {
        STRICT_CHECK(ch != LF);

        if (parser->flags & F_TRAILING) {
          /* End of a chunked request */
          UPDATE_STATE(s_message_done);
          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);
          goto message_done;
        }

        /* Cannot use chunked encoding and a content-length header together
           per the HTTP specification. Unless lenient, nor any other
           Transfer-Encoding: it overrides Content-Length, and a response read
           by the length would leave the rest of its body to be read as the
           next response (RFC 9112 section 6.3; upstream 7d5c99d, llhttp). */
        if ((parser->flags & F_CONTENTLENGTH) &&
            ((parser->flags & F_CHUNKED) ||
             (!lenient && (parser->extra_flags & (F_TRANSFER_ENCODING >> 8))))) {
          SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);
          goto error;
        }

        UPDATE_STATE(s_headers_done);

        /* Set this here so that on_headers_complete() callbacks can see it */
        parser->upgrade =
          ((parser->flags & (F_UPGRADE | F_CONNECTION_UPGRADE)) ==
           (F_UPGRADE | F_CONNECTION_UPGRADE) ||
           parser->method == HTTP_CONNECT);
        /* Unless lenient: a response switches protocols only with a 101; in
         * any other, Upgrade announces what the server supports (RFC 9110
         * section 7.8) */
        if (!lenient && parser->type == HTTP_RESPONSE && parser->status_code != 101) {
          parser->upgrade = 0;
        }

        /* Here we call the headers_complete callback. This is somewhat
         * different than other callbacks because if the user returns 1, we
         * will interpret that as saying that this message has no body. This
         * is needed for the annoying case of recieving a response to a HEAD
         * request.
         *
         * We'd like to use CALLBACK_NOTIFY_NOADVANCE() here but we cannot, so
         * we have to simulate it by handling a change in errno below.
         */
        if (settings->on_headers_complete) {
          switch (settings->on_headers_complete(parser)) {
            case 0:
              break;

            case 2:
              parser->upgrade = 1;

            case 1:
              parser->flags |= F_SKIPBODY;
              break;

            default:
              SET_ERRNO(HPE_CB_headers_complete);
              RETURN(p - data); /* Error */
          }
        }

        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
          RETURN(p - data);
        }

        goto headers_done;
      }

      headers_done:
      case s_headers_done:
      {
        int hasBody, skipBody;
        STRICT_CHECK(ch != LF);

        parser->nread = 0;

        /* Unless lenient: a 1xx, 204 or 304 response ends with its header
         * section, whatever framing it names (RFC 9112 section 6.3) */
        skipBody = (parser->flags & F_SKIPBODY) ||
          (!lenient && parser->type == HTTP_RESPONSE &&
           (parser->status_code / 100 == 1 || parser->status_code == 204 ||
            parser->status_code == 304));
        hasBody = parser->flags & F_CHUNKED ||
          (parser->content_length > 0 && parser->content_length != ULLONG_MAX);
        if (parser->upgrade && (parser->method == HTTP_CONNECT ||
                                skipBody || !hasBody)) {
          /* Exit, the rest of the message is in a different protocol. */
          UPDATE_STATE(NEW_MESSAGE());
          CALLBACK_NOTIFY(message_complete);
          RETURN((p - data) + 1);
        }

        if (skipBody) {
          UPDATE_STATE(NEW_MESSAGE());
          CALLBACK_NOTIFY(message_complete);
        } else if (parser->flags & F_CHUNKED) {
          /* chunked encoding - ignore Content-Length header */
          UPDATE_STATE(s_chunk_size_start);
        } else {
          if (parser->content_length == 0) {
            /* Content-Length header given but zero: Content-Length: 0\r\n */
            UPDATE_STATE(NEW_MESSAGE());
            CALLBACK_NOTIFY(message_complete);
          } else if (parser->content_length != ULLONG_MAX) {
            /* Content-Length header given and non-zero */
            UPDATE_STATE(s_body_identity);
          } else {
            if (!message_needs_eof(parser)) {
              /* Assume content-length 0 - read the next */
              UPDATE_STATE(NEW_MESSAGE());
              CALLBACK_NOTIFY(message_complete);
            } else {
              /* Read body until EOF */
              UPDATE_STATE(s_body_identity_eof);
            }
          }
        }

        if (CURRENT_STATE() == s_body_identity) {
          NEXTCHAR();
          goto body_identity;
        }

        break;
      }

