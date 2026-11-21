/* Parse-loop states for identity and chunked bodies and message completion (license: see http_parser.cc). */
      body_identity:
      case s_body_identity:
      {
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* The difference between advancing content_length and p is because
         * the latter will automaticaly advance on the next loop iteration.
         * Further, if content_length ends up at 0, we want to see the last
         * byte again for our message complete callback.
         */
        MARK(body);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length == 0) {
          UPDATE_STATE(s_message_done);

          /* Mimic CALLBACK_DATA_NOADVANCE() but with one extra byte.
           *
           * The alternative to doing this is to wait for the next byte to
           * trigger the data callback, just as in every other case. The
           * problem with this is that this makes it difficult for the test
           * harness to distinguish between complete-on-EOF and
           * complete-on-length. It's not clear that this distinction is
           * important for applications, but let's keep it for now.
           */
          CALLBACK_DATA_(body, p - body_mark + 1, p - data);
          goto message_done;
        }

        break;
      }

      /* read until EOF */
      case s_body_identity_eof:
        MARK(body);
        p = data + len - 1;

        break;

      message_done:
      case s_message_done:
        UPDATE_STATE(NEW_MESSAGE());
        CALLBACK_NOTIFY(message_complete);
        if (parser->upgrade) {
          /* Exit, the rest of the message is in a different protocol. */
          RETURN((p - data) + 1);
        }
        break;

      chunk_size_start:
      case s_chunk_size_start:
      {
        assert(parser->nread == 1);
        assert(parser->flags & F_CHUNKED);

        unhex_val = unhex[(unsigned char)ch];
        if unlikely(unhex_val == -1) {
          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
          goto error;
        }

        parser->content_length = unhex_val;
        UPDATE_STATE(s_chunk_size);
        NEXTCHAR_COUNTED();
        /* FALLTHROUGH */
      }

      chunk_size:
      case s_chunk_size:
      {
        uint64_t t;

        assert(parser->flags & F_CHUNKED);

        if (ch == CR) {
          UPDATE_STATE(s_chunk_size_almost_done);
          NEXTCHAR_COUNTED();
          goto chunk_size_almost_done;
        }

        unhex_val = unhex[(unsigned char)ch];

        if (unhex_val == -1) {
          /* Unless lenient: only ';' (an extension) after the size */
          if (ch == ';' || (ch == ' ' && lenient)) {
            parser->index = lenient ? parser->index : CHUNK_EXT_START;
            UPDATE_STATE(s_chunk_parameters);
            break;
          }

          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
          goto error;
        }

        t = parser->content_length;
        t *= 16;
        t += unhex_val;

        /* Overflow? Test against a conservative limit for simplicity. */
        if unlikely((ULLONG_MAX - 16) / 16 < parser->content_length) {
          SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
          goto error;
        }

        parser->content_length = t;
        NEXTCHAR_COUNTED();
        goto chunk_size;
      }

      case s_chunk_parameters:
      {
        assert(parser->flags & F_CHUNKED);
        if (!lenient) {
          /* chunk-ext = *( ";" chunk-ext-name [ "=" ( token / quoted-string ) ] )
           * (RFC 9112 section 7.1.1, without whitespace), parser->index the place
           * in it: a malformed extension, or a bare LF or another control byte in
           * one, is an error. */
          if (!chunk_ext_char(parser, ch)) {
            SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
            goto error;
          }
          if (ch == CR) {
            UPDATE_STATE(s_chunk_size_almost_done);
          }
          break;
        }
        /* just ignore this shit. TODO check for overflow */
        if (ch == CR) {
          UPDATE_STATE(s_chunk_size_almost_done);
          break;
        }
        break;
      }

      chunk_size_almost_done:
      case s_chunk_size_almost_done:
      {
        assert(parser->flags & F_CHUNKED);
        STRICT_CHECK(ch != LF);

        parser->nread = 0;

        if (parser->content_length == 0) {
          parser->flags |= F_TRAILING;
          UPDATE_STATE(s_header_field_start);
          CALLBACK_NOTIFY(chunk_header);
          break;
        }

        UPDATE_STATE(s_chunk_data);
        CALLBACK_NOTIFY(chunk_header);
        NEXTCHAR();
        goto chunk_data;
      }

      chunk_data:
      case s_chunk_data:
      {
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* See the explanation in s_body_identity for why the content
         * length and data pointers are managed this way.
         */
        MARK(body);
        parser->content_length -= to_read;
        p += to_read - 1;

        if (parser->content_length != 0) {
          break;
        }

        UPDATE_STATE(s_chunk_data_almost_done);
        NEXTCHAR();
        /* FALLTHROUGH */
      }

      case s_chunk_data_almost_done:
        assert(parser->flags & F_CHUNKED);
        assert(parser->content_length == 0);
        STRICT_CHECK(ch != CR);
        UPDATE_STATE(s_chunk_data_done);
        CALLBACK_DATA(body);
        NEXTCHAR();
        /* FALLTHROUGH */

      case s_chunk_data_done:
        assert(parser->flags & F_CHUNKED);
        STRICT_CHECK(ch != LF);
        parser->nread = 0;
        UPDATE_STATE(s_chunk_size_start);
        CALLBACK_NOTIFY(chunk_complete);
        NEXTCHAR_COUNTED();
        goto chunk_size_start;

