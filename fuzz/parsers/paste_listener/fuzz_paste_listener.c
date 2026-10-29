/*
 * fuzz_paste_listener.c - libFuzzer harness for the paste HTTP(S)
 * listener (ircd/paste_listener.c): the request a browser (anyone who can
 * reach the paste port) sends is parsed by paste_parse_request,
 * paste_unescape_brackets / paste_validate_paste_id and
 * paste_request_wants_ws_upgrade; the paste body (multiline message text
 * a client sent, stored by ml_content.c) goes through
 * paste_parse_filename_hint, the HTML escaper and the HTML page builder.
 * paste_listener.c is #included; ml_content.c and common/fake_db.c are
 * linked for real, the rest is autostubbed.
 *
 * Input: request\0\0stored-content-row ; the harness maps paste id
 * "AB-secret" to msgid "MSGID" and stores the content row under it
 * (sender\0target\0text, possibly zstd-framed).  Properties: a 200 HTML
 * response contains no raw '<' that came from the paste text (every '<'
 * in the body belongs to the template), responses are well-formed.
 */
#include "config.h"
#include "ircd_features.h"
#include "db_env.h"
#include "fake_db.h"
#include "fuzz_util.h"

int feature_bool(enum Feature f) { (void)f; return 0; }
int feature_int(enum Feature f) { (void)f; return 0; }
const char *feature_str(enum Feature f) { (void)f; return ""; }

#include "../../../ircd/paste_listener.c"
#include "ml_content.h"

static struct db_env *env;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  db_env_open("/fuzz/paste", NULL, 8, &env);
  if (ml_content_init(env) != 0) abort();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static struct paste_conn conn;
  const uint8_t *sep = NULL;
  size_t i, rl;
  for (i = 0; i + 1 < size; i++)
    if (data[i] == 0 && data[i + 1] == 0) { sep = data + i; break; }
  rl = sep ? (size_t)(sep - data) : size;
  if (rl >= PASTE_MAX_REQUEST_SIZE) rl = PASTE_MAX_REQUEST_SIZE - 1;

  fake_db_clear();
  fake_db_put(fake_db_cf("ml_paste_secrets"), "AB-secret", 9, "MSGID", 5);
  if (sep)
    fake_db_put(fake_db_cf("ml_content"), "MSGID", 5, sep + 2, size - (sep + 2 - data));

  memset(&conn, 0, sizeof conn);
  conn.fd = -1;
  memcpy(conn.request, data, rl);
  conn.request[rl] = '\0';
  conn.request_len = (int)rl;
  /* paste_drain_read hands the request over once it holds a blank line */
  if (strstr(conn.request, "\r\n\r\n")) {
    (void)paste_request_wants_ws_upgrade(conn.request);
    paste_handle_request(&conn);
    if (conn.response) {
      CHECK(conn.response_len > 0 && !strncmp(conn.response, "HTTP/1.1 ", 9));
      MyFree(conn.response);
    }
  }
  {
    /* the body helpers on their own, with the content row as a paste */
    char fn[PASTE_FILENAME_MAX];
    const char *oc;
    size_t ol, el;
    char *esc;
    const char *body = sep ? (const char *)sep + 2 : (const char *)data;
    size_t bl = sep ? size - (sep + 2 - data) : size;
    paste_parse_filename_hint(body, bl, fn, sizeof fn, &oc, &ol);
    CHECK(strlen(fn) < sizeof fn && oc >= body && oc + ol == body + bl);
    (void)paste_ext_to_lang(fn);
    esc = paste_html_escape(body, bl, &el);
    if (esc) {
      CHECK(!memchr(esc, '<', el) && !memchr(esc, '>', el) && !memchr(esc, '"', el));
      MyFree(esc);
    }
  }
  return 0;
}
