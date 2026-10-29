/* Concrete reproduction against the REAL ircd/websocket.c: an upgrade
 * request whose Sec-WebSocket-Protocol header names no supported
 * subprotocol.  Stubs as in ircd/test/websocket_cmocka.c.  A 5-second
 * alarm turns a hang into a visible failure. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "../../../ircd/websocket.c"

int HighestFd = -1;
struct Client* LocalClientArray[MAXCONNECTIONS];
int feature_int(enum Feature f) { (void)f; return 0; }
struct Timer* timer_init(struct Timer* t) { return t; }
void timer_add(struct Timer* t, EventCallBack c, void* d, enum TimerType ty, time_t v)
{ (void)t; (void)c; (void)d; (void)ty; (void)v; }
const char *feature_str(enum Feature f) { (void)f; return ""; }
void update_write(struct Client* c) { (void)c; }
int ircd_snprintf(struct Client *d, char *b, size_t n, const char *fmt, ...)
{ va_list a; int r; (void)d; va_start(a, fmt); r = vsnprintf(b, n, fmt, a); va_end(a); return r; }
IOResult os_send_nonb(int fd, const char *b, unsigned int l, unsigned int *o)
{ (void)fd; (void)b; *o = l; return IO_SUCCESS; }

static void on_alarm(int s) { (void)s;
  static const char m[] = "HANG: parse_ws_handshake did not return within 5s\n";
  write(1, m, sizeof m - 1); _exit(2); }

int main(int argc, char **argv)
{
  const char *proto = argc > 1 ? argv[1] : "chat";
  char req[1024];
  int sub = -1, r;
  char key[64], origin[256];
  snprintf(req, sizeof req,
           "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\n\r\n", proto);
  signal(SIGALRM, on_alarm);
  alarm(5);
  r = parse_ws_handshake(req, (int)strlen(req), key, &sub, origin);
  printf("protocol '%s': parse_ws_handshake returned %d, subproto %d\n", proto, r, sub);
  return 0;
}

/* link stubs */
void *DoMalloc(size_t s, const char *t, const char *f, int l)
{ (void)t; (void)f; (void)l; return malloc(s); }
char *ircd_strncpy(char *d, const char *s, size_t n)
{ if (n) { strncpy(d, s, n - 1); d[n - 1] = '\0'; } return d; }
