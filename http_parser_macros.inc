/* State, callback and byte-stepping macros of the parse loop (license: see http_parser.cc). */

#define CURRENT_STATE() p_state
#define UPDATE_STATE(V) p_state = (enum state) (V);
#define RETURN(V)                                                    \
do {                                                                 \
  parser->state = CURRENT_STATE();                                   \
  return (V);                                                        \
} while (0);
#define REEXECUTE()                                                  \
  goto reexecute;                                                    \


/* Run the notify callback FOR, returning ER if it fails */
#define CALLBACK_NOTIFY_(FOR, ER)                                    \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if likely(settings->on_##FOR) {                                    \
    parser->state = CURRENT_STATE();                                 \
    if unlikely(0 != settings->on_##FOR(parser)) {                   \
      SET_ERRNO(HPE_CB_##FOR);                                       \
    }                                                                \
    UPDATE_STATE(parser->state);                                     \
                                                                     \
    /* We either errored above or got paused; get out */             \
    if unlikely(HTTP_PARSER_ERRNO(parser) != HPE_OK) {               \
      return (ER);                                                   \
    }                                                                \
  }                                                                  \
} while (0)

/* Run the notify callback FOR and consume the current byte */
#define CALLBACK_NOTIFY(FOR)            CALLBACK_NOTIFY_(FOR, p - data + 1)

/* Run the notify callback FOR and don't consume the current byte */
#define CALLBACK_NOTIFY_NOADVANCE(FOR)  CALLBACK_NOTIFY_(FOR, p - data)

/* Run data callback FOR with LEN bytes, returning ER if it fails */
#define CALLBACK_DATA_(FOR, LEN, ER)                                 \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (FOR##_mark) {                                                  \
    if likely(settings->on_##FOR) {                                  \
      parser->state = CURRENT_STATE();                               \
      if unlikely(0 !=                                               \
                   settings->on_##FOR(parser, FOR##_mark, (LEN))) {  \
        SET_ERRNO(HPE_CB_##FOR);                                     \
      }                                                              \
      UPDATE_STATE(parser->state);                                   \
                                                                     \
      /* We either errored above or got paused; get out */           \
      if unlikely(HTTP_PARSER_ERRNO(parser) != HPE_OK) {             \
        return (ER);                                                 \
      }                                                              \
    }                                                                \
    FOR##_mark = NULL;                                               \
  }                                                                  \
} while (0)

/* Run the data callback FOR and consume the current byte */
#define CALLBACK_DATA(FOR)                                           \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data + 1)

/* Run the data callback FOR and don't consume the current byte */
#define CALLBACK_DATA_NOADVANCE(FOR)                                 \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data)

/* Set the mark FOR; non-destructive if mark is already set */
#define MARK(FOR)                                                    \
do {                                                                 \
  if (!FOR##_mark) {                                                 \
    FOR##_mark = p;                                                  \
  }                                                                  \
} while (0)

/* Don't allow the total size of the HTTP headers (including the status
 * line) to exceed HTTP_MAX_HEADER_SIZE.  This check is here to protect
 * embedders against denial-of-service attacks where the attacker feeds
 * us a never-ending header that the embedder keeps buffering.
 *
 * This check is arguably the responsibility of embedders but we're doing
 * it on the embedder's behalf because most won't bother and this way we
 * make the web a little safer.  HTTP_MAX_HEADER_SIZE is still far bigger
 * than any reasonable request or response so this should never affect
 * day-to-day operation.
 */
#define COUNT_HEADER_SIZE(V)                                         \
do {                                                                 \
  parser->nread += (V);                                              \
  if unlikely(parser->nread > (HTTP_MAX_HEADER_SIZE)) {              \
    SET_ERRNO(HPE_HEADER_OVERFLOW);                                  \
    goto error;                                                      \
  }                                                                  \
} while (0)


#define PARSING_HEADER(state) (state <= s_headers_done)


#define NEXTHEADERCHAR() \
  if unlikely(p+1 == (data+len)) {                            \
    COUNT_HEADER_SIZE(0);                                     \
    break;                                                    \
  }                                                           \
  ch = *++p;                                                  \
  ++parser->nread;

/* Step to the next byte and count it as the top of the loop does, so that the
 * code can go straight to the state it has just set (goto) instead of through
 * the loop and the dispatch. With no next byte the switch is left and the loop
 * ends, as it does after any other state. */
#define NEXTCHAR_COUNTED() \
  if unlikely(p+1 == (data+len)) {                            \
    break;                                                    \
  }                                                           \
  ch = *++p;                                                  \
  COUNT_HEADER_SIZE(1);

/* The same for a state whose bytes are not counted against the header size. */
#define NEXTCHAR() \
  if unlikely(p+1 == (data+len)) {                            \
    break;                                                    \
  }                                                           \
  ch = *++p;


#define start_state (parser->type == HTTP_REQUEST ? s_start_req : s_start_res)

/* Unless lenient, the HTTP versions a message may carry (llhttp's: 0.9, 1.0, 1.1, 2.0) */
#define KNOWN_VERSION(major, minor)                                            \
  (((major) == 1 && (minor) <= 1) || ((major) == 2 && (minor) == 0) ||        \
   ((major) == 0 && (minor) == 9))
#define VERSION_KNOWN(parser) KNOWN_VERSION((parser)->http_major, (parser)->http_minor)

#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    SET_ERRNO(HPE_STRICT);                                           \
    goto error;                                                      \
  }                                                                  \
} while (0)
# define NEW_MESSAGE() (should_keep_alive(parser) ? start_state : s_dead)
#else
# define STRICT_CHECK(cond)
# define NEW_MESSAGE() start_state
#endif
