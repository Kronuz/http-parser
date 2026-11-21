/* Header-name matchers, token tables, header character table and chunk-extension grammar (license: see http_parser.cc). */

#define PROXY_CONNECTION "proxy-connection"
#define CONNECTION "connection"
/* A Transfer-Encoding field was seen: kept in parser->extra_flags, shifted
 * down by 8, as upstream 7d5c99d keeps it */
#define F_TRANSFER_ENCODING (1 << 8)

#define CONTENT_LENGTH "content-length"
#define TRANSFER_ENCODING "transfer-encoding"
#define UPGRADE "upgrade"

/* The special header names, by header state from h_C to h_matching_upgrade: the
 * name the byte at parser->index must match, the index of its last byte, and the
 * state after it. h_C and h_CO match "co" and "con" on the way to h_CON, which
 * goes on with "conn" (h_CON's 't', content-length, is the one fork). */
struct name_matcher {
  const char *name;
  unsigned char last;
  unsigned char matched;
};
static const struct name_matcher name_matchers[] = {
  { "co", 1, h_CO },                                                /* h_C */
  { "con", 2, h_CON },                                              /* h_CO */
  { "conn", 3, h_matching_connection },                             /* h_CON */
  { CONNECTION, sizeof(CONNECTION) - 2, h_connection },             /* h_matching_connection */
  { PROXY_CONNECTION, sizeof(PROXY_CONNECTION) - 2, h_connection }, /* h_matching_proxy_connection */
  { CONTENT_LENGTH, sizeof(CONTENT_LENGTH) - 2, h_content_length }, /* h_matching_content_length */
  { TRANSFER_ENCODING, sizeof(TRANSFER_ENCODING) - 2, h_transfer_encoding }, /* h_matching_transfer_encoding */
  { UPGRADE, sizeof(UPGRADE) - 2, h_upgrade },                      /* h_matching_upgrade */
};
static_assert(h_CO == h_C + 1 && h_CON == h_C + 2 && h_matching_connection == h_C + 3 &&
              h_matching_proxy_connection == h_C + 4 && h_matching_content_length == h_C + 5 &&
              h_matching_transfer_encoding == h_C + 6 && h_matching_upgrade == h_C + 7 &&
              h_connection == h_matching_upgrade + 1 && h_upgrade == h_connection + 3,
              "name_matchers follows the header states");
#define CHUNKED "chunked"
#define KEEP_ALIVE "keep-alive"
#define CLOSE "close"


/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */
static const char tokens[256] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0,      '!',      0,      '#',     '$',     '%',     '&',    '\'',
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        0,       0,      '*',     '+',      0,      '-',     '.',      0,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
       '0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
       '8',     '9',      0,       0,       0,       0,       0,       0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
       'x',     'y',     'z',      0,       0,       0,      '^',     '_',
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
       '`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
       'x',     'y',     'z',      0,      '|',      0,      '~',       0 };


static const int8_t unhex[256] =
  {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };


/**
 * Verify that a char is a valid visible (printable) US-ASCII
 * character or %x80-FF
 **/
#define IS_HEADER_CHAR(ch)                                                     \
  (ch == CR || ch == LF || ch == 9 || ((unsigned char)ch > 31 && ch != 127))

/* IS_HEADER_CHAR as a table: one load where the parser checks a value's bytes */
struct HeaderChar {
  uint8_t ok[256];
  constexpr HeaderChar() : ok() {
    for (int c = 0; c < 256; ++c) ok[c] = IS_HEADER_CHAR((char) c);
  }
};
static constexpr HeaderChar header_char{};

/* Unless lenient, a chunk extension is checked byte by byte; parser->index is
 * where in the grammar the last byte left it. */
enum chunk_ext_state {
  CHUNK_EXT_START = 0,   /* after ';': a name follows */
  CHUNK_EXT_NAME,        /* in the name */
  CHUNK_EXT_EQUALS,      /* after '=': a token or a quoted string follows */
  CHUNK_EXT_TOKEN,       /* in a token value */
  CHUNK_EXT_QUOTED,      /* in a quoted string */
  CHUNK_EXT_ESCAPE,      /* after a backslash in a quoted string */
  CHUNK_EXT_CLOSED       /* after the closing quote */
};

/* Takes one byte of a chunk-size line after the size; 0 if it may not come here. */
static int chunk_ext_char(http_parser *parser, char ch) {
  const unsigned char c = (unsigned char) ch;
  const int vchar = c > 0x20 && c != 0x7f;  /* VCHAR or obs-text */
  switch (parser->index) {
    case CHUNK_EXT_START:
      if (!STRICT_TOKEN(ch)) return 0;
      parser->index = CHUNK_EXT_NAME;
      return 1;
    case CHUNK_EXT_NAME:
    case CHUNK_EXT_TOKEN:
      if (STRICT_TOKEN(ch)) return 1;
      if (ch == '=' && parser->index == CHUNK_EXT_NAME) { parser->index = CHUNK_EXT_EQUALS; return 1; }
      if (ch == ';') { parser->index = CHUNK_EXT_START; return 1; }
      return ch == CR;
    case CHUNK_EXT_EQUALS:
      if (ch == '"') { parser->index = CHUNK_EXT_QUOTED; return 1; }
      if (!STRICT_TOKEN(ch)) return 0;
      parser->index = CHUNK_EXT_TOKEN;
      return 1;
    case CHUNK_EXT_QUOTED:
      if (ch == '"') { parser->index = CHUNK_EXT_CLOSED; return 1; }
      if (ch == '\\') { parser->index = CHUNK_EXT_ESCAPE; return 1; }
      return vchar || ch == ' ' || ch == '\t';
    case CHUNK_EXT_ESCAPE:
      parser->index = CHUNK_EXT_QUOTED;
      return vchar || ch == ' ' || ch == '\t';
    case CHUNK_EXT_CLOSED:
      if (ch == ';') { parser->index = CHUNK_EXT_START; return 1; }
      return ch == CR;
  }
  return 0;
}
