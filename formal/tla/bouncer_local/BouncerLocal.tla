--------------------------- MODULE BouncerLocal ---------------------------
(***************************************************************************)
(* Single-server model of the Nefarious bouncer session lifecycle for ONE *)
(* account and ONE session slot (FEAT_BOUNCER_MAX_SESSIONS = 1), with one *)
(* optional remote alias R (BX C / BX X / remote KILL) and an optional    *)
(* STALE roster entry (a persisted remote alias restored by               *)
(* bounce_db_restore whose Client never reappears).                       *)
(*                                                                         *)
(* Every action is one synchronous C call path (the ircd is single-       *)
(* threaded and exit_client cascades are synchronous), so each action is  *)
(* atomic.  Guards/effects were derived from the C source on branch       *)
(* ircv3.2-upgrade; file:line citations are given per action.             *)
(*   bs.c  = ircd/bouncer_session.c      sm.c = ircd/s_misc.c             *)
(*   su.c  = ircd/s_user.c               mq.c = ircd/m_quit.c             *)
(*   sb.c  = ircd/s_bsd.c                mk.c = ircd/m_kill.c             *)
(*   mb.c  = ircd/m_bouncer.c            mp.c = ircd/m_persistence.c      *)
(*   ma.c  = ircd/m_account.c            ic.c = ircd/ircd.c               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
  L,              \* local connection slots (model values)
  R,              \* the remote alias Client (model value)
  STALE,          \* a roster entry with no Client behind it (model value)
  NULL,           \* null pointer (model value)
  MaxAl,          \* bounce_max_aliases()
  ReviveCanFail,  \* allow socket_add/socket_reattach failure in bounce_revive
  Restored,       \* allow the restored-from-DB initial state
  StaleRoster,    \* restored record carries a remote alias entry
  PeerLinks,      \* a peer completes a burst (EB -> bounce_prune_stale_aliases)
  UseRemote,      \* enable the remote alias R
  DefaultHold,    \* class_bouncer || FEAT_BOUNCER_DEFAULT_HOLD
  OperCmds,       \* enable oper-only BOUNCER RESUME / DISCONNECT
  UserCmds,       \* enable BOUNCER SET HOLD / SET SESSION HOLD / PERSISTENCE DETACH
  PlusZ,          \* the primary may sit in a +Z (SSL-only) channel
  DeauthOn,       \* account deauth (AC U / Keycloak webhook) may happen
  OperKillAlias   \* a local oper may /KILL a local alias

Cl    == L \cup {R}
Nicks == {"N"} \cup L          \* "N" = the session nick; c = c's own unique nick
Stat  == {"none", "user", "ghost", "alias"}
\* user  = registered live non-alias Client (local, or R as a remote primary)
\* ghost = IsBouncerHold Client (socket closed, still in channels / nick hash)
\* alias = IsBouncerAlias Client

VARIABLES
  st,     \* [Cl -> Stat]
  nk,     \* [Cl -> Nicks]
  acct,   \* [Cl -> BOOLEAN]  IsAccount
  tls,    \* [Cl -> BOOLEAN]  connection is TLS
  bc,     \* [Cl -> BOOLEAN]  connection class has CRFLAG_BOUNCER (class_bouncer)
  ap,     \* [Cl -> Cl \cup {NULL}]  cli_user(x)->alias_primary
  ss,     \* hs_state: "NONE" (no session) | "ACTIVE" | "HOLDING"
  hs,     \* hs_client
  al,     \* hs_aliases[] as a set (hs_alias_count = Cardinality(al))
  holdT,  \* t_active(&hs_hold_timer)
  promT,  \* t_active(&hs_promote_timer)
  db,     \* persisted record present
  gnum,   \* hs_ghost_numeric[0] != '\0'
  meta,   \* account metadata draft/persistence/hold: "unset" | "0" | "1"
  ovr,    \* hs_hold_override: -1 | 0 | 1
  zc,     \* the primary/ghost sits in a +Z (SSL-only) channel
  det,    \* a promoted alias was left as a live primary the session no longer tracks
  uaf,    \* a code path wrote to a freed BouncerSession
  kmark   \* the last action was a KILL of a session member and the session survived

vars == <<st, nk, acct, tls, bc, ap, ss, hs, al, holdT, promT, db, gnum, meta, ovr,
          zc, det, uaf, kmark>>

---------------------------------------------------------------------------
(* Helpers *)

Live(e)   == e # STALE /\ st[e] = "alias"
LiveAl    == {e \in al : Live(e)}
Cands(lo) == {e \in LiveAl : lo => e \in L}          \* bs.c:4942-4965
NullAp(x) == [y \in Cl |-> IF ap[y] = x THEN NULL ELSE ap[y]]   \* bs.c:2735
NickFree(n) == ~\E y \in Cl : st[y] \in {"user", "ghost"} /\ nk[y] = n
\* bounce_should_hold preference cascade, bs.c:5436-5452
HoldOn(p) == IF ovr >= 0 THEN ovr = 1
             ELSE IF meta # "unset" THEN meta = "1" ELSE (bc[p] \/ DefaultHold)
\* bounce_should_hold, bs.c:5404-5458 (not KILLED, MyUser, IsAccount, ACTIVE, hs==p)
ShouldHold(p) == p \in L /\ acct[p] /\ ss = "ACTIVE" /\ hs = p /\ HoldOn(p)
\* bounce_get_session, bs.c:10875-10943 (alias follows alias_primary first)
GetSess(c) ==
  LET x == IF st[c] = "alias" /\ ap[c] # NULL THEN ap[c] ELSE c
  IN ss # "NONE" /\ acct[c] /\ (hs = x \/ x \in al)

\* bounce_destroy, bs.c:2140-2162 (timers deleted, record deleted, freed)
Destroyed == /\ ss' = "NONE" /\ hs' = NULL /\ al' = {}
             /\ holdT' = FALSE /\ promT' = FALSE /\ db' = FALSE
             /\ gnum' = FALSE /\ ovr' = -1 /\ zc' = FALSE

\* bounce_promote_alias success, bs.c:4911-5192.  Session part only.
\* Hold timer cancelled (5112), promote timer NOT cancelled, ACTIVE (5127),
\* record deleted when no local holder remains (5135).
PromSess(w) == /\ ss' = "ACTIVE" /\ hs' = w /\ al' = al \ {w}
               /\ holdT' = FALSE
               /\ zc' = (zc /\ w \in L /\ tls[w])
               /\ db' = (db /\ (w \in L \/ \E e \in al \ {w} : e \in L))
               /\ UNCHANGED <<gnum, ovr>>
PromSessP(w) == PromSess(w) /\ UNCHANGED promT
\* promote + exit of the old primary `old` (old removed from channels by
\* promote A4, then exit_client'ed by the caller).
PromSt(w, old) == [y \in Cl |-> IF y = w THEN "user"
                                ELSE IF y = old THEN "none" ELSE st[y]]
PromAp(w, old) == [y \in Cl |-> IF y = w THEN NULL
                                ELSE IF y \in al /\ st[y] = "alias" THEN w   \* A2 bs.c:5148
                                ELSE IF ap[y] = old THEN NULL ELSE ap[y]]

\* bounce_hold_client, bs.c:5507-5638 (promote timer chosen by caller)
Hold(p) == /\ st' = [st EXCEPT ![p] = "ghost"]
           /\ ss' = "HOLDING" /\ holdT' = TRUE /\ db' = TRUE /\ gnum' = TRUE
           /\ UNCHANGED <<nk, acct, tls, bc, ap, hs, al, meta, ovr, zc, det, uaf>>

(***************************************************************************)
(* exit_one_client for a live non-alias, non-ghost user c                 *)
(* (sm.c:625-724; also reached by a ghost after ClearBouncerHold).        *)
(***************************************************************************)
ExitUser(c, killed) ==
  LET mine == ss # "NONE" /\ acct[c] /\ hs = c IN
  IF ~mine THEN
     /\ st' = [st EXCEPT ![c] = "none"] /\ ap' = NullAp(c)
     /\ UNCHANGED <<nk, acct, tls, bc, ss, hs, al, holdT, promT, db, gnum, meta,
                    ovr, zc, det, uaf>>
  ELSE IF killed THEN                     \* sm.c:643-664, 685-700
     /\ st' = [y \in Cl |-> IF y = c \/ y \in LiveAl THEN "none" ELSE st[y]]
     /\ ap' = NullAp(c) /\ Destroyed
     /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
  ELSE IF ss = "ACTIVE" THEN
     IF c \in L /\ al = {} THEN           \* sm.c:701-708 orphan destroy
        /\ st' = [st EXCEPT ![c] = "none"] /\ ap' = NullAp(c) /\ Destroyed
        /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE                                 \* sm.c:684 hs_client = NULL only
        /\ st' = [st EXCEPT ![c] = "none"] /\ ap' = NullAp(c) /\ hs' = NULL
        /\ UNCHANGED <<nk, acct, tls, bc, ss, al, holdT, promT, db, gnum, meta,
                       ovr, zc, det, uaf>>
  ELSE                                    \* HOLDING, sm.c:640-683
     IF al = {} THEN
        /\ st' = [st EXCEPT ![c] = "none"] /\ ap' = NullAp(c) /\ Destroyed
        /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE IF Cands(FALSE) # {} THEN
        \E w \in Cands(FALSE) :
           /\ st' = PromSt(w, c) /\ ap' = PromAp(w, c) /\ PromSessP(w)
           /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE                                 \* promote failed; sm.c:723 nulls hs
        /\ st' = [st EXCEPT ![c] = "none"] /\ ap' = NullAp(c)
        /\ hs' = NULL /\ holdT' = FALSE
        /\ UNCHANGED <<nk, acct, tls, bc, ss, al, promT, db, gnum, meta, ovr, zc,
                       det, uaf>>

(***************************************************************************)
(* exit_one_client IsBouncerAlias branch, sm.c:348-397.                   *)
(***************************************************************************)
ExitAlias(a, killed) ==
  LET p == ap[a] IN
  IF killed /\ p # NULL /\ p \in L /\ st[p] \in {"user", "ghost"} THEN
     \* sm.c:357-372: untrack a, SetFlag(primary, KILLED), exit_client(primary)
     IF ss # "NONE" /\ acct[p] /\ hs = p THEN
        \* primary's exit runs the killed teardown (sm.c:426-429 for a ghost,
        \* sm.c:685-700 for a live primary): every alias, then destroy.
        /\ st' = [y \in Cl |-> IF y \in {a, p} \cup LiveAl THEN "none" ELSE st[y]]
        /\ ap' = NullAp(p) /\ Destroyed
        /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE
        /\ st' = [y \in Cl |-> IF y \in {a, p} THEN "none" ELSE st[y]]
        /\ ap' = NullAp(p)
        /\ al' = IF acct[a] THEN al \ {a} ELSE al
        /\ hs' = IF hs = p THEN NULL ELSE hs
        /\ UNCHANGED <<nk, acct, tls, bc, ss, holdT, promT, db, gnum, meta, ovr,
                       zc, det, uaf>>
  ELSE
     \* bounce_alias_untrack bs.c:9356-9404 bails on !IsAccount(alias) (9372)
     /\ st' = [st EXCEPT ![a] = "none"]
     /\ al' = IF acct[a] THEN al \ {a} ELSE al
     /\ UNCHANGED <<nk, acct, tls, bc, ap, ss, hs, holdT, promT, db, gnum, meta,
                    ovr, zc, det, uaf>>

(***************************************************************************)
(* exit_one_client IsBouncerHold branch, sm.c:406-460.                    *)
(***************************************************************************)
ExitGhost(g, killed) ==
  IF killed /\ ss # "NONE" /\ acct[g] /\ hs = g THEN   \* sm.c:426-429 kill_session
     /\ st' = [y \in Cl |-> IF y = g \/ y \in LiveAl THEN "none" ELSE st[y]]
     /\ ap' = NullAp(g) /\ Destroyed
     /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
  ELSE                                                \* sm.c:452-456
     /\ st' = [st EXCEPT ![g] = "none"] /\ ap' = NullAp(g)
     /\ hs' = IF hs = g THEN NULL ELSE hs
     /\ UNCHANGED <<nk, acct, tls, bc, ss, al, holdT, promT, db, gnum, meta, ovr,
                    zc, det, uaf>>

(***************************************************************************)
(* Registration of local connection c.                                    *)
(***************************************************************************)
\* Normal registration (NICK N introduction), no session membership.
PlainReg(c, ssX, hTX, pTX) ==
  /\ \E n \in {"N", c} : /\ NickFree(n)
                         /\ nk' = [nk EXCEPT ![c] = n]
  /\ st' = [st EXCEPT ![c] = "user"]
  /\ ss' = ssX /\ holdT' = hTX /\ promT' = pTX
  /\ UNCHANGED <<ap, hs, al, db, gnum, meta, ovr, zc, det, uaf>>

\* bounce_setup_local_alias, bs.c:8406-8600 (requires IsUser(hs_client) 8421)
SetupAlias(c, ssX, hTX, pTX) ==
  /\ st' = [st EXCEPT ![c] = "alias"]
  /\ nk' = [nk EXCEPT ![c] = nk[hs]]
  /\ ap' = [ap EXCEPT ![c] = hs]
  /\ al' = al \cup {c}
  /\ ss' = ssX /\ holdT' = hTX /\ promT' = pTX
  /\ UNCHANGED <<hs, db, gnum, meta, ovr, zc, det, uaf>>

\* bounce_auto_resume, bs.c:1229-1565, entered with possibly-modified
\* session state (ssX, hTX, pTX) after a failed revive (su.c:592-699).
AutoResume(c, t, b, ssX, hTX, pTX) ==
  IF meta = "0" THEN PlainReg(c, ssX, hTX, pTX)             \* bs.c:1271-1273
  ELSE IF meta = "unset" /\ ~b /\ ~DefaultHold /\ ssX = "NONE"
  THEN PlainReg(c, ssX, hTX, pTX)                           \* bs.c:1274-1277
  ELSE IF ssX = "HOLDING" /\ hs \in L /\ st[hs] = "ghost" THEN
    \* local held session -> bounce_attach (bs.c:1433, 1905-2000)
    IF zc /\ ~t THEN
      \* +Z gate (bs.c:1931-1942) returns -1 AFTER timer_del (bs.c:1924-1925);
      \* falls through: session not ACTIVE, bounce_count != 0 -> return 0.
      PlainReg(c, ssX, FALSE, pTX)
    ELSE
      \* ghost exit_client'd with the session still HOLDING (bs.c:1964-1965)
      IF al = {} THEN
        \* sm.c:672-681 destroys + frees the session; bounce_attach then
        \* writes session->hs_state (bs.c:1976) -> use-after-free.
        /\ uaf' = TRUE /\ st' = [st EXCEPT ![hs] = "none", ![c] = "user"]
        /\ nk' = [nk EXCEPT ![c] = nk[hs]] /\ ap' = NullAp(hs) /\ Destroyed
        /\ UNCHANGED <<meta, det>>
      ELSE IF Cands(FALSE) # {} THEN
        \* sm.c:665-670 promotes an alias; attach then overwrites hs_client
        \E w \in Cands(FALSE) :
          /\ st' = [PromSt(w, hs) EXCEPT ![c] = "user"]
          /\ nk' = [nk EXCEPT ![c] = nk[hs]]
          /\ ap' = PromAp(w, hs)
          /\ ss' = "ACTIVE" /\ hs' = c /\ al' = al \ {w} /\ holdT' = FALSE
          /\ det' = TRUE
          /\ db' = FALSE /\ zc' = zc
          /\ UNCHANGED <<promT, gnum, meta, ovr, uaf>>
      ELSE
        /\ st' = [st EXCEPT ![hs] = "none", ![c] = "user"]
        /\ nk' = [nk EXCEPT ![c] = nk[hs]] /\ ap' = NullAp(hs)
        /\ ss' = "ACTIVE" /\ hs' = c /\ holdT' = FALSE /\ db' = FALSE
        /\ UNCHANGED <<al, promT, gnum, meta, ovr, zc, det, uaf>>
  ELSE IF ssX = "HOLDING" THEN
    \* hs NULL: resolve fails; discard only if nothing at all (bs.c:1366-1380)
    IF hs = NULL /\ ~gnum /\ al = {} THEN
      /\ st' = [st EXCEPT ![c] = "user"] /\ hs' = c        \* destroy + recreate
      /\ ss' = "ACTIVE" /\ al' = {} /\ holdT' = FALSE /\ promT' = FALSE
      /\ db' = TRUE /\ gnum' = FALSE /\ ovr' = -1 /\ zc' = FALSE
      /\ \E n \in {"N", c} : /\ NickFree(n)
                             /\ nk' = [nk EXCEPT ![c] = n]
      /\ UNCHANGED <<ap, meta, det, uaf>>
    ELSE PlainReg(c, ssX, hTX, pTX)     \* falls to bs.c:1543: count != 0
  ELSE IF ssX = "ACTIVE" /\ hs = NULL THEN
    \* orphan reclaim, bs.c:1484-1498 -> bounce_attach with no ghost
    /\ st' = [st EXCEPT ![c] = "user"]
    /\ \E n \in {"N", c} : /\ NickFree(n)
                           /\ nk' = [nk EXCEPT ![c] = n]
    /\ ss' = "ACTIVE" /\ hs' = c /\ holdT' = FALSE /\ promT' = pTX
    /\ db' = FALSE
    /\ UNCHANGED <<ap, al, gnum, meta, ovr, zc, det, uaf>>
  ELSE IF ssX = "ACTIVE" THEN
    IF Cardinality(al) < MaxAl /\ st[hs] \in {"user", "ghost"}
    THEN SetupAlias(c, ssX, hTX, pTX)          \* ALIAS_LOCAL/REMOTE bs.c:1500-1515
    ELSE                                       \* REJECT_DUPLICATE su.c:743-748
      /\ ss' = ssX /\ holdT' = hTX /\ promT' = pTX
      /\ UNCHANGED <<st, nk, ap, hs, al, db, gnum, meta, ovr, zc, det, uaf>>
  ELSE                                         \* no session: bounce_create bs.c:1552
    /\ st' = [st EXCEPT ![c] = "user"]
    /\ \E n \in {"N", c} : /\ NickFree(n)
                           /\ nk' = [nk EXCEPT ![c] = n]
    /\ ss' = "ACTIVE" /\ hs' = c /\ al' = {} /\ holdT' = FALSE /\ promT' = FALSE
    /\ db' = TRUE /\ gnum' = FALSE /\ ovr' = -1 /\ zc' = FALSE
    /\ UNCHANGED <<ap, meta, det, uaf>>

\* register_user, su.c:514-699
Connect(c, a, t, b) ==
  /\ st[c] = "none"
  /\ acct' = [acct EXCEPT ![c] = a]
  /\ IF ~a THEN /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
                /\ PlainReg(c, ss, holdT, promT)
     ELSE IF ss = "HOLDING" /\ hs \in L /\ st[hs] = "ghost" THEN  \* Try 1, su.c:531
       IF zc /\ ~t THEN                  \* revive +Z gate bs.c:5693-5710 (before any change)
         /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
         /\ AutoResume(c, t, b, ss, holdT, promT)
       ELSE
         \/ \* bounce_revive success: socket transplanted onto the ghost
            /\ st' = [st EXCEPT ![hs] = "user"]
            /\ tls' = [tls EXCEPT ![hs] = t]
            /\ bc' = [bc EXCEPT ![hs] = b]     \* confs transplanted (bs.c revive)
            /\ ss' = "ACTIVE" /\ holdT' = FALSE /\ promT' = FALSE /\ db' = FALSE
            /\ UNCHANGED <<nk, ap, hs, al, gnum, meta, ovr, zc, det, uaf>>
         \/ \* socket_add/socket_reattach failure, bs.c:5813-5838: state already
            \* flipped to ACTIVE and both timers deleted (bs.c:5717-5727)
            /\ ReviveCanFail
            /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
            /\ AutoResume(c, t, b, "ACTIVE", FALSE, FALSE)
     ELSE IF ss = "ACTIVE" /\ hs \in L /\ st[hs] = "ghost" THEN
       \* Try 2, su.c:543-555: ACTIVE session whose local primary has no socket
       \* (cli_fd == -1) -> bounce_revive relay-only branch (bs.c:5671-5676),
       \* which also clears a leftover hold flag (bs.c:6063).
       IF zc /\ ~t THEN
         /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
         /\ AutoResume(c, t, b, ss, holdT, promT)
       ELSE
         \/ /\ st' = [st EXCEPT ![hs] = "user"]
            /\ tls' = [tls EXCEPT ![hs] = t] /\ bc' = [bc EXCEPT ![hs] = b]
            /\ UNCHANGED <<nk, ap, ss, hs, al, holdT, promT, db, gnum, meta, ovr,
                           zc, det, uaf>>
         \/ /\ ReviveCanFail
            /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
            /\ AutoResume(c, t, b, ss, holdT, promT)
     ELSE /\ tls' = [tls EXCEPT ![c] = t] /\ bc' = [bc EXCEPT ![c] = b]
          /\ AutoResume(c, t, b, ss, holdT, promT)

(***************************************************************************)
(* Disconnects                                                            *)
(***************************************************************************)
\* m_quit, mq.c:140-160
PrimaryQuit(p) ==
  /\ p \in L /\ st[p] = "user"
  /\ IF ShouldHold(p) THEN
       IF al # {} /\ Cands(TRUE) # {} THEN          \* local-only promote mq.c:145
         \E w \in Cands(TRUE) :
           /\ st' = PromSt(w, p) /\ ap' = PromAp(w, p) /\ PromSessP(w)
           /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
       ELSE /\ Hold(p)
            /\ promT' = (promT \/ al # {})           \* mq.c:157-158
     ELSE ExitUser(p, FALSE)

\* dead socket / WS close: sb.c:1997-2007, sb.c:767-771, sb.c:1436-1440
PrimaryDrop(p) ==
  /\ p \in L /\ st[p] = "user"
  /\ IF ShouldHold(p) THEN Hold(p) /\ UNCHANGED promT
     ELSE ExitUser(p, FALSE)

\* check_pings, ic.c:762-779
PingOut(p) ==
  /\ p \in L /\ st[p] = "user"
  /\ IF acct[p] /\ ss # "NONE" /\ hs = p /\ al # {} /\ Cands(FALSE) # {} THEN
       \E w \in Cands(FALSE) :
         /\ st' = PromSt(w, p) /\ ap' = PromAp(w, p) /\ PromSessP(w)
         /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE IF ShouldHold(p) THEN Hold(p) /\ UNCHANGED promT
     ELSE ExitUser(p, FALSE)

\* mq.c:118, sb.c:1980 (alias skips all hold logic)
AliasQuit(a) == a \in L /\ st[a] = "alias" /\ ExitAlias(a, FALSE)

(***************************************************************************)
(* Timers                                                                 *)
(***************************************************************************)
\* bounce_hold_expire ET_EXPIRE, bs.c:727-784.  The re-arm branch (735) is
\* a stutter and omitted.  The 0-tick promote timer always fires before a
\* >= 1 s hold timer, hence ~promT.
HoldExpire ==
  /\ holdT /\ ss = "HOLDING" /\ ~promT
  /\ LET g == hs IN
     IF al # {} THEN
       IF Cands(FALSE) # {} THEN                     \* bs.c:753-772
         \E w \in Cands(FALSE) :
           /\ st' = PromSt(w, g) /\ ap' = PromAp(w, g) /\ PromSessP(w)
           /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
       ELSE
         \* promote failed: ghost exits WITHOUT hold flag (bs.c:767-771) ->
         \* sm.c:665-670 promotes again (fails) -> sm.c:723 nulls hs_client.
         /\ st' = IF g # NULL THEN [st EXCEPT ![g] = "none"] ELSE st
         /\ ap' = IF g # NULL THEN NullAp(g) ELSE ap
         /\ hs' = NULL /\ holdT' = FALSE
         /\ UNCHANGED <<nk, acct, tls, bc, ss, al, promT, db, gnum, meta, ovr, zc,
                        det, uaf>>
     ELSE                                            \* bs.c:774-783
       /\ st' = IF g # NULL THEN [st EXCEPT ![g] = "none"] ELSE st
       /\ ap' = IF g # NULL THEN NullAp(g) ELSE ap
       /\ Destroyed
       /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>

\* bounce_finish_cross_server_promote, bs.c:5195-5257
PromoteFire ==
  /\ promT
  /\ IF ss = "HOLDING" /\ hs # NULL /\ st[hs] = "ghost" /\ Cands(FALSE) # {} THEN
       \E w \in Cands(FALSE) :
         /\ st' = PromSt(w, hs) /\ ap' = PromAp(w, hs)
         /\ PromSess(w)   \* promT' = FALSE set in OtherStep
         /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE UNCHANGED <<st, nk, acct, tls, bc, ap, ss, hs, al, holdT, db, gnum, meta,
                      ovr, zc, det, uaf>>

(***************************************************************************)
(* KILL                                                                   *)
(***************************************************************************)
Member(v) == ss # "NONE" /\ (hs = v \/ v \in LiveAl)
\* (a KILL whose session primary is remote is ended by the primary's home
\*  server when the relayed KILL reaches it, sm.c:351-356 -- out of scope)

\* Local oper KILL of a local victim: do_kill does NOT set FLAG_KILLED
\* (mk.c:134-144); hook mk.c:179-184 only fires when hs_client == victim.
KillLocal(v) ==
  /\ v \in L /\ st[v] # "none" /\ (st[v] = "alias" => OperKillAlias)
  /\ IF st[v] \in {"user", "ghost"} /\ acct[v] /\ ss # "NONE" /\ hs = v THEN
       \* bounce_kill_session bs.c:2184-2214, then exit_client_msg(victim)
       /\ st' = [y \in Cl |-> IF y = v \/ y \in LiveAl THEN "none" ELSE st[y]]
       /\ ap' = NullAp(v) /\ Destroyed
       /\ UNCHANGED <<nk, acct, tls, bc, meta, det, uaf>>
     ELSE IF st[v] = "alias" THEN ExitAlias(v, FALSE)
     ELSE IF st[v] = "ghost" THEN ExitGhost(v, FALSE)
     ELSE ExitUser(v, FALSE)

\* KILL arriving from a server (or local oper KILL of a remote client):
\* FLAG_KILLED is set (mk.c:143).
KillS2S(v) ==
  /\ st[v] # "none" /\ (v = R => UseRemote)
  /\ IF st[v] = "ghost" THEN ExitGhost(v, TRUE)
     ELSE IF st[v] = "alias" THEN ExitAlias(v, TRUE)
     ELSE ExitUser(v, TRUE)

(***************************************************************************)
(* Account deauth: bounce_account_deauth_apply bs.c:7200-7275 and the     *)
(* callers ma.c:177-212 / sasl_webhook.c:186-217 (exit a returned ghost). *)
(***************************************************************************)
Deauth(c) ==
  /\ DeauthOn /\ c \in L /\ acct[c] /\ st[c] # "none"
  /\ LET emitAl  == IF ss # "NONE" /\ hs # NULL /\ acct[hs] /\ st[hs] # "alias"
                    THEN LiveAl ELSE {}                    \* bs.c:7221-7226
         ghostOwn == ss # "NONE" /\ hs = c /\ st[c] = "ghost"  \* bs.c:7239
         exitSet == (IF ghostOwn THEN LiveAl ELSE {})
                    \cup (IF st[c] = "ghost" THEN {c} ELSE {})  \* bs.c:7274 + caller
     IN /\ st' = [y \in Cl |-> IF y \in exitSet THEN "none" ELSE st[y]]
        /\ acct' = [y \in Cl |-> IF y = c \/ y \in emitAl THEN FALSE ELSE acct[y]]
        /\ ap' = IF st[c] = "ghost" THEN NullAp(c) ELSE ap
        /\ IF ss # "NONE" THEN Destroyed                          \* bs.c:7238-7248
           ELSE UNCHANGED <<ss, hs, al, holdT, promT, db, gnum, ovr, zc>>
        /\ UNCHANGED <<nk, tls, bc, meta, det, uaf>>

\* services login of an already-registered plain user (AC R)
Login(c) == /\ c \in L /\ st[c] = "user" /\ ~acct[c]
            /\ acct' = [acct EXCEPT ![c] = TRUE]
            /\ UNCHANGED <<st, nk, tls, bc, ap, ss, hs, al, holdT, promT, db, gnum,
                           meta, ovr, zc, det, uaf>>

(***************************************************************************)
(* BOUNCER / PERSISTENCE commands                                         *)
(***************************************************************************)
\* BOUNCER SET HOLD on, mb.c:713-745 (bounce_create on the caller when
\* bounce_get_session(caller) is NULL; no IsBouncerAlias check)
SetHoldOn(c) ==
  /\ UserCmds /\ c \in L /\ acct[c] /\ st[c] \in {"user", "alias"}
  /\ meta' = "1"
  /\ IF ~GetSess(c) /\ ss = "NONE" THEN                  \* bs.c:1584 count < max
       /\ ss' = "ACTIVE" /\ hs' = c /\ al' = {} /\ holdT' = FALSE /\ promT' = FALSE
       /\ db' = TRUE /\ gnum' = FALSE /\ ovr' = -1 /\ zc' = FALSE
     ELSE UNCHANGED <<ss, hs, al, holdT, promT, db, gnum, ovr, zc>>
  /\ UNCHANGED <<st, nk, acct, tls, bc, ap, det, uaf>>

\* BOUNCER SET HOLD off (mb.c:746-770) and PERSISTENCE DETACH (mp.c:833-878):
\* hs_client = NULL; bounce_destroy.  No connection is exited.
SetHoldOff(c) ==
  /\ UserCmds /\ c \in L /\ acct[c] /\ st[c] \in {"user", "alias"}
  /\ meta' = "0"
  /\ IF GetSess(c) THEN Destroyed
     ELSE UNCHANGED <<ss, hs, al, holdT, promT, db, gnum, ovr, zc>>
  /\ UNCHANGED <<st, nk, acct, tls, bc, ap, det, uaf>>

\* BOUNCER SET SESSION <id> HOLD on|off, mb.c:808-818
SetSessHold(c, v) ==
  /\ UserCmds /\ c \in L /\ acct[c] /\ st[c] \in {"user", "alias"} /\ ss # "NONE"
  /\ ovr # v /\ ovr' = v
  /\ UNCHANGED <<st, nk, acct, tls, bc, ap, ss, hs, al, holdT, promT, db, gnum, meta,
                 zc, det, uaf>>

\* BOUNCER DISCONNECT <sessid> (oper), mb.c:451-453: record destroyed only
Disconnect(c) ==
  /\ OperCmds /\ c \in L /\ st[c] = "user" /\ acct[c] /\ ss # "NONE"
  /\ Destroyed
  /\ UNCHANGED <<st, nk, acct, tls, bc, ap, meta, det, uaf>>

\* BOUNCER RESUME <token> (oper), mb.c:123-188 -> bounce_attach bs.c:1905-2000
Resume(c) ==
  /\ OperCmds /\ c \in L /\ st[c] = "user" /\ acct[c] /\ ss # "NONE" /\ hs # c
  /\ ~(ss = "ACTIVE" /\ hs # NULL)                        \* bs.c:1914
  /\ IF hs \in L /\ st[hs] = "ghost" THEN
       IF zc /\ ~tls[c] THEN                              \* +Z refusal after timer_del
         /\ holdT' = FALSE
         /\ UNCHANGED <<st, nk, acct, tls, bc, ap, ss, hs, al, promT, db, gnum, meta,
                        ovr, zc, det, uaf>>
       ELSE IF al = {} THEN                               \* ghost exit frees session
         /\ uaf' = TRUE /\ st' = [st EXCEPT ![hs] = "none"] /\ ap' = NullAp(hs)
         /\ Destroyed /\ UNCHANGED <<nk, acct, tls, bc, meta, det>>
       ELSE IF Cands(FALSE) # {} THEN
         \E w \in Cands(FALSE) :
           /\ st' = PromSt(w, hs) /\ ap' = PromAp(w, hs)
           /\ ss' = "ACTIVE" /\ hs' = c /\ al' = al \ {w} /\ holdT' = FALSE
           /\ det' = TRUE /\ db' = FALSE
           /\ UNCHANGED <<nk, acct, tls, bc, promT, gnum, meta, ovr, zc, uaf>>
       ELSE
         /\ st' = [st EXCEPT ![hs] = "none"] /\ ap' = NullAp(hs)
         /\ ss' = "ACTIVE" /\ hs' = c /\ holdT' = FALSE /\ db' = FALSE
         /\ UNCHANGED <<nk, acct, tls, bc, al, promT, gnum, meta, ovr, zc, det, uaf>>
     ELSE    \* no local ghost: initiate_transfer (bs.c:10853) or plain attach
       /\ ss' = "ACTIVE" /\ hs' = c /\ holdT' = FALSE /\ db' = FALSE
       /\ UNCHANGED <<st, nk, acct, tls, bc, ap, al, promT, gnum, meta, ovr, zc, det, uaf>>

(***************************************************************************)
(* Remote alias R and peer links                                          *)
(***************************************************************************)
\* BX C, bounce_alias_create bs.c:8844-9340 (session move at 9325-9338)
RemoteAliasAttach ==
  /\ UseRemote /\ st[R] = "none" /\ ss # "NONE" /\ hs \in L
  /\ st[hs] \in {"user", "ghost"} /\ Cardinality(al) < 16
  /\ IF ss = "HOLDING" /\ st[hs] = "ghost" THEN
       \E w \in Cands(FALSE) \cup {R} :
         LET st1 == [st EXCEPT ![R] = "alias"]
             al1 == al \cup {R}
         IN /\ st' = [y \in Cl |-> IF y = w THEN "user"
                                    ELSE IF y = hs THEN "none" ELSE st1[y]]
            /\ ap' = [y \in Cl |-> IF y = w THEN NULL
                                   ELSE IF y \in al1 /\ st1[y] = "alias" THEN w
                                   ELSE IF ap[y] = hs THEN NULL ELSE ap[y]]
            /\ acct' = [acct EXCEPT ![R] = TRUE]
            /\ nk' = [nk EXCEPT ![R] = nk[hs]]
            /\ ss' = "ACTIVE" /\ hs' = w /\ al' = al1 \ {w} /\ holdT' = FALSE
            /\ zc' = (zc /\ w \in L /\ tls[w])
            /\ db' = (db /\ (w \in L \/ \E e \in al1 \ {w} : e \in L))
            /\ UNCHANGED <<tls, bc, promT, gnum, meta, ovr, det, uaf>>
     ELSE
       /\ st' = [st EXCEPT ![R] = "alias"] /\ ap' = [ap EXCEPT ![R] = hs]
       /\ acct' = [acct EXCEPT ![R] = TRUE] /\ nk' = [nk EXCEPT ![R] = nk[hs]]
       /\ al' = al \cup {R}
       /\ UNCHANGED <<tls, bc, ss, hs, holdT, promT, db, gnum, meta, ovr, zc, det, uaf>>

\* BX X for R, bounce_alias_destroy bs.c:9411-9500
RemoteAliasQuit ==
  /\ UseRemote /\ st[R] = "alias"
  /\ st' = [st EXCEPT ![R] = "none"]
  /\ al' = IF acct[R] THEN al \ {R} ELSE al
  /\ UNCHANGED <<nk, acct, tls, bc, ap, ss, hs, holdT, promT, db, gnum, meta, ovr,
                 zc, det, uaf>>

\* ms_end_of_burst -> bounce_prune_stale_aliases (m_endburst.c:159, bs.c:1721)
PruneStale ==
  /\ PeerLinks /\ STALE \in al
  /\ al' = al \ {STALE}
  /\ UNCHANGED <<st, nk, acct, tls, bc, ap, ss, hs, holdT, promT, db, gnum, meta,
                 ovr, zc, det, uaf>>

\* channel churn: the primary joins / leaves a +Z channel
JoinZ(p) == /\ PlusZ /\ p \in L /\ st[p] = "user" /\ ss = "ACTIVE" /\ hs = p /\ tls[p] /\ ~zc
            /\ zc' = TRUE
            /\ UNCHANGED <<st, nk, acct, tls, bc, ap, ss, hs, al, holdT, promT, db,
                           gnum, meta, ovr, det, uaf>>

---------------------------------------------------------------------------
Init0 ==
  /\ st = [c \in Cl |-> "none"] /\ nk = [c \in Cl |-> IF c = R THEN "N" ELSE c]
  /\ acct = [c \in Cl |-> FALSE] /\ tls = [c \in Cl |-> FALSE] /\ bc = [c \in Cl |-> FALSE]
  /\ ap = [c \in Cl |-> NULL]
  /\ ss = "NONE" /\ hs = NULL /\ al = {} /\ holdT = FALSE /\ promT = FALSE
  /\ db = FALSE /\ gnum = FALSE /\ meta = "unset" /\ ovr = -1 /\ zc = FALSE
  /\ det = FALSE /\ uaf = FALSE /\ kmark = FALSE

\* bounce_db_restore, bs.c:3082 (ghost) + 3651-3684 (roster) + 3687 (timer)
InitRestored ==
  /\ Restored
  /\ \E g \in L :
       /\ st = [c \in Cl |-> IF c = g THEN "ghost" ELSE "none"]
       /\ nk = [c \in Cl |-> IF c \in {g, R} THEN "N" ELSE c]
       /\ acct = [c \in Cl |-> c = g] /\ tls = [c \in Cl |-> c = g] /\ bc = [c \in Cl |-> c = g]
       /\ ap = [c \in Cl |-> NULL]
       /\ ss = "HOLDING" /\ hs = g
       /\ al = IF StaleRoster THEN {STALE} ELSE {}
       /\ holdT = TRUE /\ promT = FALSE /\ db = TRUE /\ gnum = TRUE
       /\ meta = "unset" /\ ovr = -1 /\ zc \in IF PlusZ THEN BOOLEAN ELSE {FALSE}
       /\ det = FALSE /\ uaf = FALSE /\ kmark = FALSE

Init == Init0 \/ InitRestored

Ok == ~uaf /\ kmark' = FALSE      \* a use-after-free is a crash: stop exploring
A_Connect(c, a, t, b) == ~uaf /\ Connect(c, a, t, b) /\ kmark' = FALSE
A_PrimaryQuit(p)    == Ok /\ PrimaryQuit(p)
A_PrimaryDrop(p)    == Ok /\ PrimaryDrop(p)
A_PingOut(p)        == Ok /\ PingOut(p)
A_JoinZ(p)          == Ok /\ JoinZ(p)
A_AliasQuit(a)      == Ok /\ AliasQuit(a)
A_HoldExpire        == Ok /\ HoldExpire
A_PromoteFire       == Ok /\ PromoteFire /\ promT' = FALSE
A_Deauth(c)         == Ok /\ Deauth(c)
A_Login(c)          == Ok /\ Login(c)
A_SetHoldOn(c)      == Ok /\ SetHoldOn(c)
A_SetHoldOff(c)     == Ok /\ SetHoldOff(c)
A_Disconnect(c)     == Ok /\ Disconnect(c)
A_Resume(c)         == Ok /\ Resume(c)
A_SetSessHold(c, v) == Ok /\ SetSessHold(c, v)
A_RemoteAliasAttach == Ok /\ RemoteAliasAttach
A_RemoteAliasQuit   == Ok /\ RemoteAliasQuit
A_PruneStale        == Ok /\ PruneStale
A_KillLocal(v)      == ~uaf /\ KillLocal(v) /\ kmark' = (Member(v) /\ hs \in L /\ ss' # "NONE")
A_KillS2S(v)        == ~uaf /\ KillS2S(v) /\ kmark' = (Member(v) /\ hs \in L /\ ss' # "NONE")

Next ==
  \/ \E c \in L, a \in BOOLEAN, t \in BOOLEAN, b \in BOOLEAN : A_Connect(c, a, t, b)
  \/ \E p \in L : A_PrimaryQuit(p)
  \/ \E p \in L : A_PrimaryDrop(p)
  \/ \E p \in L : A_PingOut(p)
  \/ \E p \in L : A_JoinZ(p)
  \/ \E a \in L : A_AliasQuit(a)
  \/ A_HoldExpire
  \/ A_PromoteFire
  \/ \E c \in L : A_Deauth(c)
  \/ \E c \in L : A_Login(c)
  \/ \E c \in L : A_SetHoldOn(c)
  \/ \E c \in L : A_SetHoldOff(c)
  \/ \E c \in L : A_Disconnect(c)
  \/ \E c \in L : A_Resume(c)
  \/ \E c \in L, v \in {0, 1} : A_SetSessHold(c, v)
  \/ A_RemoteAliasAttach
  \/ A_RemoteAliasQuit
  \/ A_PruneStale
  \/ \E v \in L : A_KillLocal(v)
  \/ \E v \in Cl : A_KillS2S(v)

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(A_HoldExpire) /\ WF_vars(A_PromoteFire)

---------------------------------------------------------------------------
(* Invariants *)
TypeOK ==
  /\ st \in [Cl -> Stat] /\ bc \in [Cl -> BOOLEAN] /\ nk \in [Cl -> Nicks] /\ acct \in [Cl -> BOOLEAN]
  /\ ap \in [Cl -> Cl \cup {NULL}] /\ ss \in {"NONE", "ACTIVE", "HOLDING"}
  /\ hs \in Cl \cup {NULL} /\ al \subseteq Cl \cup {STALE}
  /\ st[R] \in {"none", "user", "alias"}

\* bounce_session_assert_invariant -4/-5 plus the timer requirement
HoldingOK == ss = "HOLDING" => hs \in L /\ st[hs] = "ghost" /\ holdT
ActiveOK  == ss = "ACTIVE"  => hs # NULL /\ st[hs] = "user"
GhostAnchored == \A c \in L : st[c] = "ghost" => ss = "HOLDING" /\ hs = c /\ holdT
AliasInSession == \A a \in Cl : st[a] = "alias" => ss # "NONE" /\ a \in al
NoOrphanAlias == \A a \in Cl : st[a] = "alias" => ap[a] # NULL /\ st[ap[a]] # "none"
AliasPrimaryOK == \A a \in LiveAl : ap[a] = hs                \* assert_invariant -7
EntriesResolve == \A e \in al : e # STALE => st[e] = "alias"  \* assert_invariant -6
DestroyedClean == ss = "NONE" => ~holdT /\ ~promT /\ hs = NULL /\ al = {} /\ ~db
NickUnique == \A n \in Nicks :
                Cardinality({y \in Cl : st[y] \in {"user", "ghost"} /\ nk[y] = n}) <= 1
NoUAF == ~uaf
NoDetachedPrimary == ~det
KillEndsSession == ~kmark

Sym == Permutations(L)

\* Liveness: a HOLDING session eventually revives or is destroyed
HoldingResolves == (ss = "HOLDING") ~> (ss # "HOLDING")
\* ...and no ghost holds its nick forever without a user ever coming back
GhostResolves == \A c \in L : (st[c] = "ghost") ~> (st[c] # "ghost")
=============================================================================
