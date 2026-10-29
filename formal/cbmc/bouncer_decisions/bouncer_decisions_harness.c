/*
 * CBMC harnesses for the pure bouncer decision modules:
 *   ircd/bouncer_converge.c     bounce_converge_peer_wins
 *   ircd/bouncer_rebind_auth.c  bounce_rebind_auth, bounce_rebind_kc_conflict,
 *                               bounce_kc_join
 *   ircd/bouncer_deauth.c       bounce_deauth_classify, the BX U field map
 *
 * Strings are arbitrary NUL-terminated byte strings of up to LEN-1 bytes
 * (or NULL); booleans are arbitrary ints.
 */
#include "../../../ircd/bouncer_converge.c"
#include "../../../ircd/bouncer_rebind_auth.c"
#include "../../../ircd/bouncer_deauth.c"

#include <assert.h>

#define LEN 5

int nondet_int(void);
char nondet_char(void);

static char bufs[4][LEN];

/* An arbitrary string of length < LEN, or NULL. */
static const char *any_str(int i)
{
  int k;
  if (nondet_int())
    return NULL;
  for (k = 0; k < LEN - 1; k++)
    bufs[i][k] = nondet_char();
  bufs[i][LEN - 1] = '\0';
  return bufs[i];
}

static int is_empty(const char *s) { return !s || !*s; }

/* C1: both peers run the tie-break on the same wire-visible inputs with
 * the roles swapped.  For two DIFFERENT sessions exactly one must
 * survive; for the same session neither side may retire its own. */
void harness_converge_agreement(void)
{
  int a_hold = nondet_int() != 0, b_hold = nondet_int() != 0;
  const char *a = any_str(0), *b = any_str(1);
  int a_retires = bounce_converge_peer_wins(a_hold, a, b_hold, b);
  int b_retires = bounce_converge_peer_wins(b_hold, b, a_hold, a);
  int same_id = (is_empty(a) && is_empty(b)) || (a && b && !strcmp(a, b));

  assert(a_retires == 0 || a_retires == 1);
  /* Never both retire: that loses the account's session everywhere. */
  assert(!(a_retires && b_retires) && "C1a never both retire");
  /* A live session is never retired for a held one. */
  if (!a_hold && b_hold)
    assert(!a_retires && "C1b live beats held");
  /* Different sessions converge on exactly one. */
  if (!same_id)
    assert((a_retires ^ b_retires) && "C1c distinct sessions converge");
}

/* C1d: the "two different sessions with no id" case.  Kept separate
 * so the agreement harness above states the intended contract. */
void harness_converge_empty_ids(void)
{
  int a_hold = nondet_int() != 0, b_hold = nondet_int() != 0;
  const char *a = nondet_int() ? NULL : "";
  const char *b = nondet_int() ? NULL : "";
  int a_retires = bounce_converge_peer_wins(a_hold, a, b_hold, b);
  int b_retires = bounce_converge_peer_wins(b_hold, b, a_hold, a);
  if (a_hold == b_hold)
    assert(!a_retires && !b_retires);
}

/* R1: the rebind authorization is the strongest signal, never ACC_TS. */
void harness_rebind_auth(void)
{
  int o = nondet_int(), s = nondet_int(), t = nondet_int();
  enum BounceRebindAuth r = bounce_rebind_auth(o, s, t);
  assert(r != BRA_ACC_TS);
  assert((r == BRA_NONE) == (!o && !s));
  if (s) assert(r == BRA_SESSID);
  assert(bounce_rebind_auth_name(r) != NULL);
}

/* K1: invariant 16 -- a login joins a session only when the ids agree or
 * one is missing; a conflict is never JOIN; END_STALE only for an unused
 * session.  The conflict test is symmetric. */
void harness_kc_join(void)
{
  const char *sid = any_str(0), *lid = any_str(1);
  int unused = nondet_int();
  enum BounceKcJoin j = bounce_kc_join(sid, lid, unused);
  int conflict = !is_empty(sid) && !is_empty(lid) && strcmp(sid, lid);

  assert(bounce_rebind_kc_conflict(sid, lid) == bounce_rebind_kc_conflict(lid, sid));
  assert((j == BKJ_JOIN) == !conflict);
  if (j == BKJ_END_STALE) assert(unused && conflict);
  if (conflict && !unused) assert(j == BKJ_REFUSE);
}

/* D1: deauth locality rules (B-2): a socket that is not ours is never
 * exited from here; only a local held ghost destroys a session; a deauth
 * without kill never disconnects anyone. */
void harness_deauth(void)
{
  struct BounceDeauthSubject s;
  int do_kill = nondet_int();
  enum BounceDeauthAction a;

  s.is_user = nondet_int(); s.is_account = nondet_int();
  s.account_matches = nondet_int(); s.is_alias = nondet_int();
  s.is_hold = nondet_int(); s.is_local = nondet_int();
  s.remote_ok = nondet_int();
  if (nondet_int()) {
    assert(bounce_deauth_classify(NULL, do_kill) == BOUNCE_DEAUTH_SKIP);
    return;
  }
  a = bounce_deauth_classify(&s, do_kill);

  if (a != BOUNCE_DEAUTH_SKIP)
    assert(s.is_user && s.is_account && s.account_matches);
  if (a == BOUNCE_DEAUTH_KILL_SOCKET)
    assert(s.is_local && do_kill && "D1a only local sockets, only on kill");
  if (a == BOUNCE_DEAUTH_DESTROY_SESSION)
    assert(s.is_local && s.is_hold && !s.is_alias);
  if (a == BOUNCE_DEAUTH_CLEAR_ACCOUNT)
    assert(!s.is_alias && "aliases follow their primary");
  /* A local, non-held, non-alias account holder is always acted on. */
  if (s.is_user && s.is_account && s.account_matches && s.is_local && !s.is_alias)
    assert(a != BOUNCE_DEAUTH_SKIP);
}

/* F1: the BX U field map is a bijection between known names and ids, and
 * any input string is handled without reading out of bounds. */
void harness_fields(void)
{
  const char *f = any_str(0);
  enum BounceAliasField id = bounce_alias_field_id(f);
  int k = nondet_int();

  assert(id >= BX_ALIAS_FIELD_UNKNOWN && id < BX_ALIAS_FIELD_COUNT);
  if (id != BX_ALIAS_FIELD_UNKNOWN)
    assert(bounce_alias_field_name(id) != NULL);
  __CPROVER_assume(k > BX_ALIAS_FIELD_UNKNOWN && k < BX_ALIAS_FIELD_COUNT);
  assert(bounce_alias_field_id(bounce_alias_field_name((enum BounceAliasField)k)) == k);
}
