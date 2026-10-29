--------------------------- MODULE BouncerConverge ---------------------------
(***************************************************************************)
(* Cross-server convergence of ONE account's bouncer session in Nefarious *)
(* (branch ircv3.2-upgrade).  Every guard/effect below is transliterated  *)
(* from the C and cited as file:line.  Abbreviations:                     *)
(*   BS  = ircd/bouncer_session.c      NK = ircd/m_nick.c                 *)
(*   SV  = ircd/s_serv.c               MI = ircd/s_misc.c                 *)
(*   CV  = ircd/bouncer_converge.c     RA = ircd/bouncer_rebind_auth.c    *)
(*                                                                         *)
(* The whole network is one record variable w so that handlers with      *)
(* cascades (kill -> session destroy -> broadcast) can be written as      *)
(* pure functions World -> World.                                         *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
  NS,          \* number of servers (2 or 3); topology is the chain 1-2-..-NS
  MaxC,        \* max client connections ever created (logins)
  KCs,         \* Keycloak ids logins may carry, e.g. {1} or {1,2}
  Nicks,       \* nicks a fresh login may pick, e.g. {1} or {1,2}
  MaxLinkEv,   \* budget of link up/down events
  MaxDisc,     \* budget of disconnect / hold-expiry events
  StartLinked, \* TRUE: start with all links up; FALSE: start fully split
  QuietEnv,    \* TRUE: logins/disconnects/link events only when all queues are
               \* empty (no in-flight races); FALSE: fully interleaved
  Fixes        \* subset of {"A","B","C","D","E"}: model-only patches for confirmed
               \* bugs (see README), so TLC can look past them

Servers == 1..NS
Clients == 1..MaxC
E  == { <<i, i+1>> : i \in 1..(NS-1) }              \* undirected chain
DP == E \cup { <<e[2], e[1]>> : e \in E }           \* directed links
LinkOf(a, b) == IF a < b THEN <<a, b>> ELSE <<b, a>>

NoV == [pres |-> FALSE, al |-> FALSE, sid |-> 0, ap |-> 0, nick |-> 0]
NoS == [ex |-> FALSE, sid |-> 0, tok |-> 0, st |-> "N", prim |-> 0,
        als |-> {}, kc |-> 0, org |-> 0]

Msg(t, c, c2, srv, sid, tok, st, ts, kc, nick, src) ==
  [t |-> t, c |-> c, c2 |-> c2, srv |-> srv, sid |-> sid, tok |-> tok,
   st |-> st, ts |-> ts, kc |-> kc, nick |-> nick, src |-> src]

VARIABLE w
vars == <<w>>

(***************************************************************************)
(* Basic accessors                                                         *)
(***************************************************************************)
V(W, s, c)       == W.vw[s][c]
Pres(W, s, c)    == c \in Clients /\ W.vw[s][c].pres
Hashed(W, s, c)  == Pres(W, s, c) /\ ~W.vw[s][c].al
MyConn(W, s, c)  == Pres(W, s, c) /\ W.home[c] = s
\* IsBouncerHold is local-only state (BS comment NK:324-327: not on the wire)
IsHold(W, s, c)  == MyConn(W, s, c) /\ W.kind[c] = "ghost"
S(W, s)          == W.sess[s]
Conf(a, b)       == a # 0 /\ b # 0 /\ a # b                   \* RA:39-44
\* bounce_session_kc_id: hs_kc_id, else the primary's id (BS:1111-1133)
SessKc(W, s) ==
  IF S(W,s).kc # 0 THEN S(W,s).kc
  ELSE IF S(W,s).prim # 0 /\ Pres(W, s, S(W,s).prim) THEN W.kc[S(W,s).prim]
  ELSE 0
\* session_has_local_holder (BS:2262-2285)
LocalHolder(W, s) ==
  S(W,s).ex /\ ( (S(W,s).prim # 0 /\ MyConn(W, s, S(W,s).prim))
                 \/ \E e \in S(W,s).als : e[1] = s )
\* bounce_get_session(c) (BS:10875-10943): primary or alias-roster match
\* "held" as far as server s can tell: its own ghost, or its replica says so
HeldAt(W, s, c) == IsHold(W, s, c) \/ (S(W,s).ex /\ S(W,s).st = "H" /\ S(W,s).prim = c)
InSess(W, s, c) ==
  S(W,s).ex /\ (S(W,s).prim = c \/ <<W.home[c], c>> \in S(W,s).als)

RECURSIVE ReachR(_, _, _)
ReachR(W, X, ban) ==
  LET N == { t \in Servers \ (X \cup {ban}) :
               \E u \in X : <<u, t>> \in DP /\ W.up[LinkOf(u, t)] }
  IN IF N = {} THEN X ELSE ReachR(W, X \cup N, ban)
Side(W, s, f) == ReachR(W, {f}, s)               \* servers behind link s->f
Nbrs(W, s) == { t \in Servers : <<s, t>> \in DP /\ W.up[LinkOf(s, t)] }
Comp(W, s) == ReachR(W, {s}, 0)

(***************************************************************************)
(* Sending.  sendcmdto_serv_butone(.., cptr): every up link but `from`.   *)
(***************************************************************************)
Bcast(W, s, from, m) ==
  [W EXCEPT !.q = [p \in DP |-> IF p[1] = s /\ p[2] \in Nbrs(W, s) /\ p[2] # from
                                 THEN Append(W.q[p], m) ELSE W.q[p]]]
Send1(W, s, t, m) == [W EXCEPT !.q[<<s, t>>] = Append(@, m)]

RECURSIVE SeqOf(_)
SeqOf(X) == IF X = {} THEN <<>> ELSE
            LET x == CHOOSE y \in X : \A z \in X : y <= z IN <<x>> \o SeqOf(X \ {x})

Flag(W, f) == [W EXCEPT !.bad = @ \cup {f}]
\* A connection the user still has open is torn down by the server.
Gone(W, c, why) ==
  LET W1 == IF W.kind[c] \in {"live", "alias"} /\ why # "" THEN Flag(W, why) ELSE W
  IN [W1 EXCEPT !.kind[c] = "gone"]

\* remove_client_from_list sweep: null hs_client / alias_primary (list.c:568-569)
RemoveClient(W, s, c) ==
  LET W1 == [W EXCEPT !.vw[s][c] = NoV]
      W2 == IF W1.sess[s].ex /\ W1.sess[s].prim = c
              THEN [W1 EXCEPT !.sess[s].prim = 0] ELSE W1
  IN [W2 EXCEPT !.vw[s] = [x \in Clients |->
         IF W2.vw[s][x].ap = c THEN [W2.vw[s][x] EXCEPT !.ap = 0] ELSE W2.vw[s][x]]]

\* bounce_alias_untrack: by full numeric (home YY + XXX)
Untrack(W, s, c) ==
  IF W.sess[s].ex THEN [W EXCEPT !.sess[s].als = { e \in @ : e # <<W.home[c], c>> }]
  ELSE W

DropLocal(W, s, c, why) ==
  LET W1 == RemoveClient(W, s, c)
  IN IF W.home[c] = s THEN Gone(W1, c, why) ELSE W1

(***************************************************************************)
(* bounce_promote_alias (BS:4911-5180): winner among present aliases;     *)
(* activity rule abstracted to "lowest client id".  Broadcasts BX P and   *)
(* BS T (BS:5163-5170; T folded into P: receivers set origin).            *)
(***************************************************************************)
PromoCands(W, s) ==
  { e \in S(W,s).als : Pres(W, s, e[2]) /\ W.home[e[2]] = e[1] /\ V(W, s, e[2]).al }
CanPromote(W, s) == PromoCands(W, s) # {}
Promote(W, s) ==
  LET e   == CHOOSE x \in PromoCands(W, s) : \A y \in PromoCands(W, s) : x[2] <= y[2]
      n   == e[2]
      old == S(W,s).prim
      W1  == [W EXCEPT !.vw[s][n].al = FALSE, !.vw[s][n].ap = 0,
                       !.sess[s].prim = n, !.sess[s].st = "A",
                       !.sess[s].als = @ \ {e}, !.sess[s].org = W.home[n]]
      W2  == [W1 EXCEPT !.vw[s] = [x \in Clients |->
                IF W1.vw[s][x].pres /\ W1.vw[s][x].al /\ <<W1.home[x], x>> \in W1.sess[s].als
                  THEN [W1.vw[s][x] EXCEPT !.ap = n] ELSE W1.vw[s][x]]]
      W3  == IF W.home[n] = s THEN [W2 EXCEPT !.kind[n] = "live"] ELSE W2
  IN Bcast(W3, s, 0, Msg("BXP", IF old = 0 THEN n ELSE old, n, W.home[n],
                         S(W,s).sid, 0, "", 0, 0, 0, s))

(***************************************************************************)
(* bounce_kill_session (BS:2184-2215): exit every alias, BS X, destroy.   *)
(***************************************************************************)
RECURSIVE KillAliases(_, _, _)
KillAliases(W, s, A) ==
  IF A = {} THEN W ELSE
  LET e  == CHOOSE x \in A : TRUE
      a  == e[2]
      W1 == IF Pres(W, s, a) /\ W.home[a] = e[1]
              THEN LET Wb == Bcast(W, s, 0, Msg("BXX", a, 0, e[1], 0, 0, "", 0, 0, 0, s))
                   IN  DropLocal(Untrack(Wb, s, a), s, a, "liveKilledBySessionKill")
              ELSE W
  IN KillAliases(W1, s, A \ {e})
KillSession(W, s) ==
  LET W1 == KillAliases(W, s, S(W,s).als)
      W2 == [W1 EXCEPT !.sess[s].prim = 0]
      W3 == Bcast(W2, s, 0, Msg("BSX", 0, 0, 0, S(W,s).sid, S(W,s).tok, "", 0, 0, 0, s))
  IN [W3 EXCEPT !.sess[s] = NoS]
Destroy(W, s) == [W EXCEPT !.sess[s] = NoS]                    \* BS:2140-2161
DestroyBcast(W, s) ==
  Destroy(Bcast(W, s, 0, Msg("BSX", 0, 0, 0, S(W,s).sid, S(W,s).tok, "", 0, 0, 0, s)), s)

(***************************************************************************)
(* exit_one_client session logic (MI:338-395 alias, MI:406-460 held,     *)
(* MI:637-711 primary), followed by the list sweep.                       *)
(***************************************************************************)
ExitOne(W, s, c, killed, why) ==
  IF ~Pres(W, s, c) THEN W
  ELSE IF V(W, s, c).al THEN
    LET p  == V(W, s, c).ap
        W1 == Untrack(W, s, c)
        \* MI:356-379 KILL of an alias cascades to a LOCAL live primary;
        \* the primary's exit carries FLAG_KILLED so no Q is sent for it.
        W2 == IF killed /\ p # 0 /\ MyConn(W1, s, p) /\ W1.kind[p] = "live"
                THEN LET Wk == IF S(W1,s).ex /\ S(W1,s).prim = p
                                 THEN KillSession(W1, s) ELSE W1
                     IN DropLocal(Wk, s, p, "liveKilledByAliasCascade")
                ELSE W1
    IN DropLocal(W2, s, c, why)
  ELSE IF IsHold(W, s, c) /\ killed /\ InSess(W, s, c) THEN       \* MI:406-430
    DropLocal(KillSession(W, s), s, c, why)
  ELSE IF S(W,s).ex /\ S(W,s).prim = c THEN
    LET W1 ==
      IF S(W,s).st = "H" THEN
        IF killed THEN KillSession(W, s)                           \* MI:643-664
        ELSE IF S(W,s).als # {} /\ CanPromote(W, s) THEN Promote(W, s) \* MI:665-671
        ELSE DestroyBcast(W, s)                                    \* MI:672-682
      ELSE
        IF killed THEN KillSession(W, s)                           \* MI:686-700
        ELSE IF MyConn(W, s, c) /\ S(W,s).als = {} THEN DestroyBcast(W, s) \* MI:701-708
        ELSE [W EXCEPT !.sess[s].prim = 0]                         \* MI:683-684 remote ACTIVE: just null
    IN DropLocal(W1, s, c, why)
  ELSE DropLocal(W, s, c, why)

\* Kill x at s and tell the whole network (NK:910-918).
KillHere(W, s, x, why) ==
  ExitOne(Bcast(W, s, 0, Msg("KILL", x, 0, 0, 0, 0, "", 0, 0, 0, s)), s, x, TRUE, why)

(***************************************************************************)
(* Live primary -> alias demotion: bounce_demote_live_primary_to_alias    *)
(* (BS:6472-6564) + bounce_finish_live_primary_demote (BS:6566-6716).     *)
(* NB: neither checks MyConnect(acptr); alias entry and BX C numeric are  *)
(* built from cli_yxx(&me) (BS:6540-6543, 6650-6653).                     *)
(***************************************************************************)
Demote(W, s, x, np) ==
  IF ~(S(W,s).ex /\ S(W,s).prim = x /\ Hashed(W, s, x) /\ ~IsHold(W, s, x)
       /\ W.kind[x] # "gone")
  THEN W
  ELSE
  LET W0 == IF W.home[x] # s THEN Flag(W, "demoteOfRemotePrimary") ELSE W
      W1 == W0
      W2 == [W1 EXCEPT !.vw[s][x].al = TRUE, !.vw[s][x].ap = np,
                       !.vw[s][x].nick = V(W1, s, np).nick,
                       !.sess[s].org = W1.home[np], !.sess[s].prim = np,
                       !.sess[s].als = @ \cup {<<s, x>>}]
      W3 == IF W.home[x] = s THEN [W2 EXCEPT !.kind[x] = "alias"] ELSE W2
      W4 == Bcast(W3, s, 0, Msg("BXC", np, x, s, S(W,s).sid, 0, "", 0, 0, 0, s))
      \* FIX C: repoint sibling aliases at the new primary and re-announce
      \* the local ones (the real code leaves alias_primary = demoted alias)
      Sib == { a \in Clients : a # x /\ Pres(W4, s, a) /\ V(W4, s, a).al /\ V(W4, s, a).ap = x }
      W5 == [W4 EXCEPT !.vw[s] = [a \in Clients |->
               IF a \in Sib THEN [W4.vw[s][a] EXCEPT !.ap = np] ELSE W4.vw[s][a]]]
      LocSib == SeqOf({ a \in Sib : W.home[a] = s })
  IN IF "C" \notin Fixes THEN W4
     ELSE [W5 EXCEPT !.q = [p \in DP |->
             IF p[1] = s /\ p[2] \in Nbrs(W5, s)
               THEN W5.q[p] \o [i \in 1..Len(LocSib) |->
                       Msg("BXC", np, LocSib[i], s, S(W,s).sid, 0, "", 0, 0, 0, s)]
               ELSE W5.q[p]]]

Install(W, s, f, m) ==
  Bcast([W EXCEPT !.vw[s][m.c] = [pres |-> TRUE, al |-> FALSE, sid |-> m.sid,
                                   ap |-> 0, nick |-> m.nick]], s, f, m)

(***************************************************************************)
(* ms_nick collision handling for a server-introduced N (NK:360-920).     *)
(***************************************************************************)
Classic(W, s, f, m, x) ==                       \* NK:720-920 (differ forced 1, NK:820-840)
  IF m.ts > W.ts[x] THEN Send1(W, s, f, Msg("KILL", m.c, 0, 0, 0, 0, "", 0, 0, 0, s))
  ELSE IF m.ts < W.ts[x] THEN Install(KillHere(W, s, x, "liveKilledByCollision"), s, f, m)
  ELSE KillHere(Send1(W, s, f, Msg("KILL", m.c, 0, 0, 0, 0, "", 0, 0, 0, s)),
                s, x, "liveKilledByCollision")

RcvN(W, f, s, m) ==
  IF Pres(W, s, m.c) THEN W ELSE
  LET coll == { x \in Clients : Hashed(W, s, x) /\ V(W, s, x).nick = m.nick /\ x # m.c }
  IN IF coll = {} THEN Install(W, s, f, m)                          \* NK:432-434
  ELSE LET x == CHOOSE y \in coll : TRUE
           Ss == S(W, s) IN
  IF "G" \in Fixes /\ IsHold(W, s, x) /\ m.st = "H" /\ Ss.ex /\ Ss.prim = x
     /\ Ss.sid = m.sid /\ ~Conf(W.kc[x], m.kc)
  THEN \* FIX G: ghost vs ghost of the SAME session: older ghost stays, the
       \* younger side drops its ghost silently (BX X) and keeps the record
       IF W.ts[x] < m.ts \/ (W.ts[x] = m.ts /\ x < m.c) THEN W
       ELSE Install([DropLocal(Bcast(W, s, 0, Msg("BXX", x, 0, s, 0, 0, "", 0, 0, 0, s)),
                               s, x, "") EXCEPT !.sess[s].prim = m.c], s, f, m)
  ELSE IF "G" \in Fixes /\ ~IsHold(W, s, x) /\ HeldAt(W, s, x) /\ m.st = "H"
          /\ Ss.sid = m.sid /\ ~Conf(W.kc[x], m.kc)
  THEN \* FIX G at a hub: same rule, the younger ghost's home drops it
       IF W.ts[x] < m.ts \/ (W.ts[x] = m.ts /\ x < m.c) THEN W ELSE Install(W, s, f, m)
  ELSE IF IsHold(W, s, x) /\ Ss.ex /\ Ss.st = "H" /\ Ss.prim = x          \* NK:518-537
     /\ (Ss.org = m.src \/ Ss.sid = m.sid)                          \* BS:6327-6357, RA:9-24
     /\ ~Conf(W.kc[x], m.kc)                                        \* BS:6363-6371
  THEN \* bounce_rebind_ghost_to_remote_primary (BS:6378-6455): ghost struct
       \* re-keyed to the incoming numeric; NO broadcast (NK:527-537 return 0)
       LET Wr == [W EXCEPT !.vw[s][x] = NoV,
                 !.vw[s][m.c] = [pres |-> TRUE, al |-> FALSE, sid |-> Ss.sid,
                                 ap |-> 0, nick |-> m.nick],
                 !.kind[x] = "gone",
                 !.sess[s].st = "A", !.sess[s].prim = m.c]
       IN IF "I" \in Fixes   \* FIX I: retire the ghost numeric and pass the N on
            THEN Bcast(Bcast(Wr, s, 0, Msg("BXX", x, 0, s, 0, 0, "", 0, 0, 0, s)), s, f, m)
            ELSE Wr
  ELSE IF "A" \in Fixes /\ IsHold(W, s, x) /\ ~Conf(W.kc[x], m.kc) /\ m.st # "H"
          /\ ( x \in W.hab[<<s, f>>] \/ <<s, f>> \notin W.burst  \* we announced it held
               \/ W.ts[x] > m.ts                            \* announced live, lost D.2
               \/ (W.ts[x] = m.ts /\ <<s, x>> \in {<<a, b>> \in Servers \X Clients :
                                         a > W.home[m.c] \/ (a = W.home[m.c] /\ b > m.c)}) )
  THEN \* FIX A: a held ghost yields to a live same-id N (state outranks age)
       LET W1 == IF InSess(W, s, x) THEN KillSession(W, s) ELSE W
       IN Install(DropLocal(Bcast(W1, s, 0, Msg("BXX", x, 0, s, 0, 0, "", 0, 0, 0, s)),
                            s, x, ""), s, f, m)
  ELSE IF "A" \in Fixes /\ IsHold(W, s, x) /\ ~Conf(W.kc[x], m.kc) /\ m.st # "H"
  THEN W   \* FIX A: announced live and won D.2: the peer demoted its own; refuse
  ELSE IF "A" \in Fixes /\ ~IsHold(W, s, x) /\ HeldAt(W, s, x) /\ m.st # "H"
          /\ ~Conf(W.kc[x], m.kc) /\ (x \in W.hab[<<s, f>>] \/ <<s, f>> \notin W.burst)
  THEN Install(W, s, f, m)  \* FIX A at a hub: pass the live N on; the ghost's home retires it
  ELSE IF "A" \in Fixes /\ m.st = "H" /\ Hashed(W, s, x) /\ ~IsHold(W, s, x)
          /\ InSess(W, s, x) /\ ~Conf(SessKc(W, s), m.kc)
  THEN W   \* FIX A: never demote a live primary under an incoming held ghost
  ELSE IF ~IsHold(W, s, x) /\ InSess(W, s, x)                       \* NK:570-575
          /\ ~Conf(SessKc(W, s), m.kc)                              \* NK:576-586
          /\ Ss.prim = x                                            \* NK:587
  THEN LET ours   == W.ts[x]
           weLose == IF ours > m.ts THEN TRUE
                     ELSE IF ours < m.ts THEN FALSE
                     \* NK:606-612: our_full = cli_yxx(&me)+cli_yxx(acptr)
                     ELSE (s > W.home[m.c]) \/ (s = W.home[m.c] /\ x > m.c)
           WF == IF m.st = "H" THEN Flag(W, "liveDemotedUnderGhost") ELSE W
       IN IF weLose /\ "D" \in Fixes /\ W.home[x] # s
            THEN Install(W, s, f, m)   \* FIX D: not ours to demote; the home's BX C converts it
          ELSE IF weLose THEN Demote(Install(WF, s, f, m), s, x, m.c)     \* NK:617-640
          ELSE W                                                     \* NK:641-655 refuse silently
  ELSE Classic(W, s, f, m, x)

(***************************************************************************)
(* BS C (BS:4207-4544)                                                     *)
(***************************************************************************)
PeerPrims(W, s, f, sid) ==                                           \* BS:1182-1196
  { x \in Clients : Hashed(W, s, x) /\ W.home[x] \in Side(W, s, f) /\ V(W, s, x).sid = sid }
PeerConf(W, s, f, sid) ==
  \E x \in PeerPrims(W, s, f, sid) : Conf(SessKc(W, s), W.kc[x])
NewReplica(W, s, m) ==                                               \* BS:4471-4517
  [W EXCEPT !.sess[s] = [ex |-> TRUE, sid |-> m.sid, tok |-> m.tok, st |-> m.st,
                         prim |-> 0, als |-> {}, kc |-> IF "K" \in Fixes THEN m.kc ELSE 0,
                         org |-> m.src]]
Rename(W, s, sid) ==                                                 \* BS:4419-4455
  LET W1 == [W EXCEPT !.sess[s].sid = sid]
      mem == { x \in Clients : Pres(W1, s, x) /\
                 (x = W1.sess[s].prim \/ <<W1.home[x], x>> \in W1.sess[s].als) }
  IN [W1 EXCEPT !.vw[s] = [x \in Clients |->
        IF x \in mem THEN [W1.vw[s][x] EXCEPT !.sid = sid] ELSE W1.vw[s][x]]]

RcvBSC(W, f, s, m) ==
  LET Ss  == S(W, s)
      Fwd(X) == Bcast(X, s, f, m)                                    \* BS:4520-4533
  IN
  IF Ss.ex /\ Ss.tok = m.tok THEN                                    \* token match BS:4268
     IF LocalHolder(W, s) /\ Ss.st = "H" /\ m.st = "A" THEN
        IF Ss.org # m.src THEN W                                     \* BS:4282-4291
        ELSE IF PeerConf(W, s, f, m.sid) THEN W                      \* BS:4293-4302
        ELSE LET g  == Ss.prim
                 W1 == [W EXCEPT !.sess[s].org = m.src, !.sess[s].st = "A",
                                 !.sess[s].prim = 0]                 \* BS:4309-4318
             IN IF g # 0 /\ Pres(W1, s, g)                           \* BS:4333-4334 ghost exits
                  THEN DropLocal(Bcast(W1, s, 0, Msg("BXX", g, 0, s, 0, 0, "", 0, 0, 0, s)), s, g, "")
                  ELSE W1
     ELSE IF "J" \in Fixes /\ ~LocalHolder(W, s) /\ Ss.st = "H" /\ m.st = "A"
       THEN Bcast([W EXCEPT !.sess[s].st = m.st], s, f, m)   \* FIX J: a bare replica adopts the claim
     ELSE W                                                          \* BS:4337 return 0, no forward
  ELSE IF Ss.ex THEN
     IF Ss.sid = m.sid THEN Fwd(W)                                   \* BS:4363
     ELSE IF PeerConf(W, s, f, m.sid) THEN Fwd(W)                    \* BS:4374-4385
     ELSE IF "K" \in Fixes /\ Conf(SessKc(W, s), m.kc) THEN Fwd(W)
          \* FIX K: the id rides on BS C itself, so the gate does not depend on
          \* the peer primary having survived N-time collision handling
     ELSE IF "S" \in Fixes /\ Ss.st = "H" /\ m.st = "A" /\ <<s, f>> \in W.burst
             /\ PeerPrims(W, s, f, m.sid) = {} THEN Fwd(W)
             \* FIX S: in a burst, a peer session whose primary we refused at
             \* N-time (we won D.2) is stale: do not retire ours for it.
     ELSE IF Ss.st = "H" /\ m.st = "A" THEN                          \* BS:4394-4410
        IF LocalHolder(W, s)
          THEN LET g  == Ss.prim
                   W1 == KillSession(W, s)
                   W2 == IF g # 0 /\ Pres(W1, s, g)
                           THEN DropLocal(Bcast(W1, s, 0, Msg("BXX", g, 0, s, 0, 0, "", 0, 0, 0, s)), s, g, "liveKilledByRetire")
                           ELSE W1
               IN Fwd(NewReplica(W2, s, m))
          ELSE Fwd(NewReplica(Destroy(W, s), s, m))
     ELSE IF Ss.st = "A" /\ m.st = "H" THEN Fwd(W)                   \* BS:4411-4416
     ELSE IF Ss.sid > m.sid THEN Fwd(Rename(W, s, m.sid))            \* CV:33 peer lex-lower wins
     ELSE Fwd(W)
  ELSE Fwd(NewReplica(W, s, m))

(***************************************************************************)
(* BS A (BS:4546-4651).  The wire carries XXX only; the receiver prefixes  *)
(* the SENDER's YY (BS:4587-4590).  Modelled: resolves iff home = src.    *)
(***************************************************************************)
Resolve(W, s, c, pref) == IF c # 0 /\ Pres(W, s, c) /\ W.home[c] = pref THEN c ELSE 0
RcvBSA(W, f, s, m) ==
  IF ~(S(W,s).ex /\ S(W,s).sid = m.sid) THEN W                        \* BS:4549-4551 no forward
  ELSE
  LET p  == Resolve(W, s, m.c, IF m.srv # 0 THEN m.srv ELSE m.src)  \* FIX E: full numeric
      keep == "B" \in Fixes /\ S(W,s).prim # 0 /\ S(W,s).prim # p
              /\ MyConn(W, s, S(W,s).prim) /\ ~V(W, s, S(W,s).prim).al
              \* FIX B: never let a peer's BS A displace our own live primary
      W1 == IF p # 0 /\ ~keep /\ ~V(W, s, p).al /\ ~Conf(S(W,s).kc, W.kc[p])   \* BS:4595-4605, 2784-2824
              THEN [W EXCEPT !.sess[s].prim = p,
                             !.sess[s].kc = IF @ = 0 THEN m.kc ELSE @]
              ELSE W
      W2 == IF m.src \in W1.bsrv[s] THEN W1                           \* BS:4646 IsBurstOrBurstAck(sptr)
            ELSE [W1 EXCEPT !.sess[s].st = "A"]
  IN Bcast(W2, s, f, m)

RcvBSD(W, f, s, m) ==                                                 \* BS:4653-4723
  IF ~(S(W,s).ex /\ S(W,s).sid = m.sid) THEN W
  ELSE LET p  == Resolve(W, s, m.c, m.src)
           np == IF p = 0 THEN 0                                     \* BS:4713-4717
                 ELSE IF Conf(S(W,s).kc, W.kc[p]) THEN S(W,s).prim   \* assign_checked refuses
                 ELSE p
       IN Bcast([W EXCEPT !.sess[s].st = "H", !.sess[s].prim = np], s, f, m)

RcvBSX(W, f, s, m) ==                                                 \* BS:4725-4741
  Bcast(IF S(W,s).ex /\ S(W,s).sid = m.sid
           /\ ("X" \in Fixes => S(W,s).tok = m.tok)   \* FIX X: the immutable token, not the renamable sid
        THEN Destroy(W, s) ELSE W, s, f, m)

(***************************************************************************)
(* BX C (BS:8844-9353), BX X (BS:9411-9466), BX P (BS:8220-8403)          *)
(***************************************************************************)
RcvBXC(W, f, s, m) ==
  LET p  == IF Pres(W, s, m.c) THEN m.c ELSE 0                        \* BS:8895-8899
      a  == m.c2
      ok == p # 0 /\ W.home[a] = m.srv                                \* numeric YY must be a's server
      Wf(X) == Bcast(X, s, f, m)                                      \* BS:9294-9311
  IN IF p = 0 THEN Wf(W)
  ELSE IF ~ok THEN Wf(Flag(W, "bogusAliasNumeric"))
  ELSE IF Pres(W, s, a) /\ V(W, s, a).al THEN Wf(W)                   \* BS:8920-8924
  ELSE
  LET W1 == [W EXCEPT !.vw[s][a] = [pres |-> TRUE, al |-> TRUE, sid |-> m.sid,
                                    ap |-> p, nick |-> V(W, s, p).nick]]
      \* session: by sessid, else account fallback (BS:9123-9135), id gate (9136-9144)
      sOK == S(W1, s).ex /\ ~Conf(SessKc(W1, s), W1.kc[p])
      W2 == IF sOK THEN [W1 EXCEPT !.sess[s].als = @ \cup {<<m.srv, a>>},
                                   \* FIX D (hub half): follow the primary the home chose
                                   !.sess[s].prim = IF "D" \in Fixes /\ @ = a THEN p ELSE @]
            ELSE W1
      \* FIX C (convert-in-place half): siblings that pointed at the converted
      \* client follow it to the new primary; local ones are re-announced
      Sib == { b \in Clients : b # a /\ Pres(W2, s, b) /\ V(W2, s, b).al /\ V(W2, s, b).ap = a }
      W2b == IF "C" \in Fixes /\ Pres(W, s, a) /\ ~V(W, s, a).al
               THEN LET Wx == [W2 EXCEPT !.vw[s] = [b \in Clients |->
                                 IF b \in Sib THEN [W2.vw[s][b] EXCEPT !.ap = p] ELSE W2.vw[s][b]]]
                        L  == SeqOf({ b \in Sib : W.home[b] = s })
                    IN [Wx EXCEPT !.q = [pp \in DP |->
                          IF pp[1] = s /\ pp[2] \in Nbrs(Wx, s)
                            THEN Wx.q[pp] \o [i \in 1..Len(L) |->
                                   Msg("BXC", p, L[i], s, m.sid, 0, "", 0, 0, 0, s)]
                            ELSE Wx.q[pp]]]
               ELSE W2
      W3 == Wf(W2b)
  IN \* BS:9328-9340 session move: held local ghost primary -> promote alias
     IF sOK /\ S(W3, s).st = "H" /\ IsHold(W3, s, p) /\ S(W3,s).prim = p
       THEN IF CanPromote(W3, s)
              THEN DropLocal(Bcast(Promote(W3, s), s, 0, Msg("BXX", p, 0, s, 0, 0, "", 0, 0, 0, s)), s, p, "")
              ELSE W3
       ELSE W3

RcvBXX(W, f, s, m) ==
  LET a == IF Pres(W, s, m.c) /\ W.home[m.c] = m.srv THEN m.c ELSE 0
      W1 == IF a = 0 THEN W
            ELSE DropLocal(IF V(W, s, a).al THEN Untrack(W, s, a) ELSE W, s, a, "liveRemovedByBXX")
  IN Bcast(W1, s, f, m)

RcvBXP(W, f, s, m) ==
  LET o == m.c   n == m.c2
      Wf(X) == Bcast(X, s, f, m)
  IN IF ~(Pres(W, s, o) /\ Pres(W, s, n)) \/ o = n THEN Wf(W)          \* BS:8241-8254
  ELSE
  LET W0 == [W EXCEPT !.vw[s][n].al = FALSE, !.vw[s][n].ap = 0]
      W1 == IF W.home[n] = s /\ W.kind[n] = "alias" THEN [W0 EXCEPT !.kind[n] = "live"] ELSE W0
      W2 == IF S(W1, s).ex /\ S(W1, s).sid = m.sid /\ ~Conf(S(W1,s).kc, W1.kc[n])
              THEN LET Wp == [W1 EXCEPT !.sess[s].prim = n, !.sess[s].st = "A",
                              !.sess[s].org = W1.home[n],
                              !.sess[s].als = { e \in @ : e[2] # n }]
                   IN [Wp EXCEPT !.vw[s] = [a \in Clients |->         \* BS:8344-8349 siblings
                         IF Wp.vw[s][a].pres /\ Wp.vw[s][a].al /\ <<Wp.home[a], a>> \in Wp.sess[s].als
                           THEN [Wp.vw[s][a] EXCEPT !.ap = n] ELSE Wp.vw[s][a]]]
              ELSE W1
  IN Wf(DropLocal(W2, s, o, "liveRemovedByBXP"))                       \* BS:8394-8396

(***************************************************************************)
(* EB -> bounce_post_burst_reconcile (BS:1780-1902)                       *)
(***************************************************************************)
Reconcile(W, s) ==
  LET Ss == S(W, s)
      p  == Ss.prim
  IN IF ~(Ss.ex /\ p # 0 /\ MyConn(W, s, p) /\ ~V(W, s, p).al) THEN W  \* BS:1815-1818
  ELSE LET C == { x \in Clients : x # p /\ Hashed(W, s, x) /\ ~IsHold(W, s, x)
                                   /\ V(W, s, x).sid = Ss.sid
                                   /\ ~Conf(SessKc(W, s), W.kc[x]) }  \* BS:1824-1841
       IN IF Cardinality(C) # 1 THEN W
          ELSE LET x == CHOOSE y \in C : TRUE
                   weLose == IF W.ts[p] # W.ts[x] THEN W.ts[p] > W.ts[x]
                             ELSE (s > W.home[x]) \/ (s = W.home[x] /\ p > x)
               IN IF weLose
                    THEN Demote(IF W.kind[x] = "ghost" THEN Flag(W, "liveDemotedUnderGhostReconcile") ELSE W, s, p, x)
                    ELSE W
\* m_endburst.c: relay EB, ClearBurst(sptr), then bounce_post_burst_reconcile
RcvEB(W, f, s, m) ==
  Reconcile(Bcast([W EXCEPT !.burst = @ \ {<<s, f>>}, !.bsrv[s] = @ \ {m.src}], s, f, m), s)

RcvKILL(W, f, s, m) ==                                                \* m_kill.c
  IF ~Pres(W, s, m.c) THEN W
  ELSE ExitOne(Bcast(W, s, f, m), s, m.c, TRUE, "liveKilledByRemoteKill")

Handle(W, f, s, m) ==
  CASE m.t = "N"    -> RcvN(W, f, s, m)
    [] m.t = "BSC"  -> RcvBSC(W, f, s, m)
    [] m.t = "BSA"  -> RcvBSA(W, f, s, m)
    [] m.t = "BSD"  -> RcvBSD(W, f, s, m)
    [] m.t = "BSX"  -> RcvBSX(W, f, s, m)
    [] m.t = "BXC"  -> RcvBXC(W, f, s, m)
    [] m.t = "BXX"  -> RcvBXX(W, f, s, m)
    [] m.t = "BXP"  -> RcvBXP(W, f, s, m)
    [] m.t = "KILL" -> RcvKILL(W, f, s, m)
    [] m.t = "EB"   -> RcvEB(W, f, s, m)

(***************************************************************************)
(* Burst: server_finish_burst (SV:336-547): N for every non-alias user    *)
(* (held ghosts included), then bounce_burst (BS:3873-4081), then EB.     *)
(***************************************************************************)

BurstMsgs(W, a) ==
  LET Ns  == [i \in 1..Len(SeqOf({x \in Clients : Hashed(W, a, x)})) |->
                LET x == SeqOf({y \in Clients : Hashed(W, a, y)})[i]
                IN Msg("N", x, 0, 0, V(W, a, x).sid, 0, IF HeldAt(W, a, x) THEN "H" ELSE "", W.ts[x], W.kc[x],
                       V(W, a, x).nick, W.home[x])]                   \* SV:423-431 ,S hint
      Ss  == S(W, a)
      BSC == IF Ss.ex THEN <<Msg("BSC", 0, 0, 0, Ss.sid, Ss.tok, Ss.st, 0, SessKc(W, a), 0, a)>>
             ELSE <<>>                                                \* BS:3889-3905 sptr=&me
      BSA == IF Ss.ex /\ Ss.prim # 0               \* BS:3945-3952: XXX only, sent from &me
             THEN <<Msg("BSA", Ss.prim, 0, IF "E" \in Fixes THEN W.home[Ss.prim] ELSE 0,
                        Ss.sid, 0, "", 0, SessKc(W, a), 0, a)>>
             ELSE <<>>
      AL  == IF Ss.ex /\ (Ss.st = "A" \/ "H" \in Fixes) /\ Ss.prim # 0  \* BS:3975-4031 (FIX H: also HOLDING)
             THEN LET L == SeqOf({ e[2] : e \in { e \in Ss.als : Pres(W, a, e[2]) /\ V(W, a, e[2]).al
                                                         /\ W.home[e[2]] = e[1] } })
                  IN [i \in 1..Len(L) |-> Msg("BXC", Ss.prim, L[i], W.home[L[i]], Ss.sid,
                                              0, "", 0, 0, 0, a)]
             ELSE <<>>
  IN Ns \o BSC \o BSA \o AL \o <<Msg("EB", 0, 0, 0, 0, 0, "", 0, 0, 0, a)>>

(***************************************************************************)
(* Netsplit: exit_client(victim) at every server of each side (MI:955-988 *)
(* then exit_downlinks MI:763-783).  SQUIT propagation is atomic.        *)
(***************************************************************************)
\* bounce_prepare_squit_promotions (BS:5286-5368)
Prepare(W, s, v, far) ==
  LET gone == IF "M" \in Fixes THEN far ELSE {v}   \* FIX M: every departing server
      \* FIX M: decide by where the primary actually is, hs_origin only as fallback
      departing == IF "M" \in Fixes /\ S(W,s).prim # 0 /\ Pres(W, s, S(W,s).prim)
                     THEN W.home[S(W,s).prim] \in far
                     ELSE S(W,s).org \in gone
  IN
  IF ~(S(W,s).ex /\ departing) THEN [W EXCEPT !.prom[s] = FALSE]
  ELSE LET W1 == [W EXCEPT !.sess[s].als = { e \in @ : e[1] \notin gone }]
       IN IF W1.sess[s].als # {} THEN [W1 EXCEPT !.prom[s] = TRUE]
          ELSE LET W2 == [W1 EXCEPT !.sess[s].prim = 0, !.prom[s] = FALSE]
               IN IF ~LocalHolder(W2, s) THEN Destroy(W2, s) ELSE W2
\* bounce_execute_squit_promotions (BS:5370-5393)
Execute(W, s) ==
  IF ~W.prom[s] THEN W
  ELSE LET W1 == [W EXCEPT !.prom[s] = FALSE]
       IN IF S(W1, s).ex /\ CanPromote(W1, s) THEN Promote(W1, s)
          ELSE IF S(W1, s).ex THEN [W1 EXCEPT !.sess[s].prim = 0] ELSE W1

RECURSIVE ExitAll(_, _, _)
ExitAll(W, s, X) ==
  IF X = {} THEN W ELSE
  LET x == CHOOSE y \in X : \A z \in X : y <= z
  IN ExitAll(ExitOne(W, s, x, FALSE, "liveLostInSplit"), s, X \ {x})

SquitAt(W, s, v, far) ==
  ExitAll(Execute(Prepare(W, s, v, far), s), s, { x \in Clients : Pres(W, s, x) /\ W.home[x] \in far })

RECURSIVE SquitSide(_, _, _, _)
SquitSide(W, X, v, far) ==
  IF X = {} THEN W ELSE
  LET s == CHOOSE y \in X : TRUE IN SquitSide(SquitAt(W, s, v, far), X \ {s}, v, far)

(***************************************************************************)
(* Initial state and environment                                           *)
(***************************************************************************)
Init ==
  w = [ up    |-> [e \in E |-> StartLinked],
        q     |-> [p \in DP |-> <<>>],
        burst |-> {},
        home  |-> [c \in Clients |-> 0],
        kc    |-> [c \in Clients |-> 0],
        kind  |-> [c \in Clients |-> "none"],
        ts    |-> [c \in Clients |-> 0],
        vw    |-> [s \in Servers |-> [c \in Clients |-> NoV]],
        sess  |-> [s \in Servers |-> NoS],
        prom  |-> [s \in Servers |-> FALSE],
        hab   |-> [p \in DP |-> {}],
        bsrv  |-> [x \in Servers |-> {}],   \* servers s still sees IsBurst (no EB yet)
        clock |-> 1,
        nc    |-> 0,
        lev   |-> 0,
        dis   |-> 0,
        bad   |-> {} ]

InboundEmpty(W, s) == \A t \in Nbrs(W, s) : W.q[<<t, s>>] = <<>>

\* bounce_auto_resume (BS:1229-1565) for a fresh SASL login of kc k at s.
Login(s, k, n) ==
  LET W  == w
      c  == W.nc + 1
      Ss == S(W, s)
      Wc == [W EXCEPT !.nc = c, !.home[c] = s, !.kc[c] = k, !.ts[c] = W.clock,
                      !.clock = @ + 1]
      AsAlias(X) ==                                 \* BS:1440-1500 / setup_local_alias
        LET p == S(X, s).prim IN
        Bcast([X EXCEPT !.kind[c] = "alias",
                        !.vw[s][c] = [pres |-> TRUE, al |-> TRUE, sid |-> S(X,s).sid,
                                      ap |-> p, nick |-> V(X, s, p).nick],
                        !.sess[s].als = @ \cup {<<s, c>>}],
              s, 0, Msg("BXC", p, c, s, S(X,s).sid, 0, "", 0, 0, 0, s))
      Create(X) ==                                  \* BS:1530-1561, register_user
        LET sid == X.clock
            X1 == [X EXCEPT !.clock = @ + 1, !.kind[c] = "live",
                            !.sess[s] = [ex |-> TRUE, sid |-> sid, tok |-> sid, st |-> "A",
                                         prim |-> c, als |-> {}, kc |-> k, org |-> s],
                            !.vw[s][c] = [pres |-> TRUE, al |-> FALSE, sid |-> sid,
                                          ap |-> 0, nick |-> n]]
            X2 == Bcast(X1, s, 0, Msg("BSC", 0, 0, 0, sid, sid, "A", 0, k, 0, s))
            X3 == Bcast(X2, s, 0, Msg("N", c, 0, 0, sid, 0, "", X1.ts[c], k, n, s))
        IN Bcast(X3, s, 0, Msg("BSA", c, 0, 0, sid, 0, "", 0, k, 0, s))
  IN
  /\ W.nc < MaxC
  /\ ~(\E x \in Clients : Hashed(W, s, x) /\ V(W, s, x).nick = n /\ ~InSess(W, s, x))
  /\ IF Ss.ex /\ Conf(SessKc(W, s), k) THEN
        \* BS:1283-1325 bounce_kc_join: END_STALE only for an unused local hold
        /\ Ss.st = "H" /\ Ss.als = {} /\ Ss.prim # 0 /\ IsHold(W, s, Ss.prim)
        /\ InboundEmpty(W, s)
        /\ w' = Create(DropLocal(KillSession(Wc, s), s, Ss.prim, ""))
     ELSE IF Ss.ex /\ Ss.st = "H" /\ Ss.prim # 0 /\ IsHold(W, s, Ss.prim) THEN
        \* local revive: the socket is transplanted onto the ghost (bounce_revive /
        \* bounce_attach), BS A broadcast (BS:1418).  Ghost id keeps ts.
        LET g == Ss.prim IN
        w' = Bcast([Wc EXCEPT !.kind[g] = "live", !.sess[s].st = "A"],
                   s, 0, Msg("BSA", g, 0, 0, Ss.sid, 0, "", 0, k, 0, s))
     ELSE IF Ss.ex /\ Ss.prim # 0 /\ Pres(W, s, Ss.prim) THEN
        w' = AsAlias(Wc)                             \* HELD/ACTIVE alias paths
     ELSE IF Ss.ex /\ Ss.st = "A" /\ Ss.prim = 0 THEN
        \* BS:1486-1497 orphan reclaim: BS A goes out BEFORE the N.
        \* FIX R: defer like the create path (BS:1545-1552).
        /\ ("R" \in Fixes => InboundEmpty(W, s))
        /\ w' = LET X1 == [Wc EXCEPT !.kind[c] = "live", !.sess[s].prim = c,
                                  !.vw[s][c] = [pres |-> TRUE, al |-> FALSE, sid |-> Ss.sid,
                                                ap |-> 0, nick |-> n]]
                 X2 == Bcast(X1, s, 0, Msg("BSA", c, 0, 0, Ss.sid, 0, "", 0, k, 0, s))
             IN Bcast(X2, s, 0, Msg("N", c, 0, 0, Ss.sid, 0, "", X1.ts[c], k, n, s))
     ELSE IF Ss.ex THEN
        \* unattachable held replica: BS:1366-1376 discards it, then create
        /\ InboundEmpty(W, s)
        /\ w' = Create(Destroy(Wc, s))
     ELSE
        /\ InboundEmpty(W, s)                        \* BS:1545-1552 DEFER_PEER_INBOUND
        /\ w' = Create(Wc)

\* Local disconnect of a live primary: m_quit immediate local promote, else hold
\* (bounce_hold_client BS:5507-5617 broadcasts BS D).
DiscPrim(c) ==
  LET s == w.home[c] IN
  /\ w.kind[c] = "live" /\ w.dis < MaxDisc
  /\ S(w, s).ex /\ S(w, s).prim = c
  /\ LET W  == [w EXCEPT !.dis = @ + 1]
         loc == { e \in S(W, s).als : e[1] = s /\ Pres(W, s, e[2]) }
     IN IF loc # {}
          THEN w' = DropLocal(Promote([W EXCEPT !.sess[s].als = loc \cup {e \in @ : e[1] # s}], s), s, c, "")
          ELSE w' = Bcast([W EXCEPT !.kind[c] = "ghost", !.sess[s].st = "H"],
                          s, 0, Msg("BSD", c, 0, 0, S(W, s).sid, 0, "", 0, 0, 0, s))

DiscAlias(a) ==                                      \* alias exit: BX X (MI:996-1011)
  LET s == w.home[a] IN
  /\ w.kind[a] = "alias" /\ w.dis < MaxDisc /\ Pres(w, s, a)
  /\ w' = DropLocal(Untrack(Bcast([w EXCEPT !.dis = @ + 1], s, 0,
                     Msg("BXX", a, 0, s, 0, 0, "", 0, 0, 0, s)), s, a), s, a, "")

\* bounce_hold_expire: promote if possible, else BS X + ghost exit (BX X)
Expire(g) ==
  LET s == w.home[g] IN
  /\ w.kind[g] = "ghost" /\ w.dis < MaxDisc /\ Pres(w, s, g)
  /\ LET W == [w EXCEPT !.dis = @ + 1] IN
     w' = IF S(W, s).ex /\ S(W, s).prim = g /\ CanPromote(W, s)
            THEN DropLocal(Promote(W, s), s, g, "")
          ELSE LET W1 == IF S(W, s).ex /\ S(W, s).prim = g THEN DestroyBcast(W, s) ELSE W
               IN DropLocal(Bcast(W1, s, 0, Msg("BXX", g, 0, s, 0, 0, "", 0, 0, 0, s)), s, g, "")

AllQuiet == \A p \in DP : w.q[p] = <<>>
PromotePending(W) ==
  \E g \in Clients : LET s == W.home[g] IN
     s # 0 /\ W.kind[g] = "ghost" /\ Pres(W, s, g) /\ S(W, s).ex /\ S(W, s).st = "H"
     /\ S(W, s).prim = g /\ CanPromote(W, s)
PromoteTimer(g) ==
  LET s == w.home[g] IN
  /\ (QuietEnv => AllQuiet)
  /\ w.kind[g] = "ghost" /\ Pres(w, s, g)
  /\ S(w, s).ex /\ S(w, s).st = "H" /\ S(w, s).prim = g /\ CanPromote(w, s)
  /\ w' = DropLocal(Bcast(Promote(w, s), s, 0, Msg("BXX", g, 0, s, 0, 0, "", 0, 0, 0, s)), s, g, "")

LinkUp(e) ==
  /\ ~w.up[e] /\ w.lev < MaxLinkEv
  /\ LET a == e[1]  b == e[2]
         CA == Comp(w, a)  CB == Comp(w, b)
         W1 == [w EXCEPT !.up[e] = TRUE, !.lev = @ + 1,
                         !.burst = @ \cup {<<a, b>>, <<b, a>>},
                         !.bsrv = [x \in Servers |-> IF x \in CB THEN @[x] \cup {a}
                                                     ELSE IF x \in CA THEN @[x] \cup {b}
                                                     ELSE @[x]]]
     IN w' = [W1 EXCEPT !.q[<<a, b>>] = BurstMsgs(w, a),
                        !.q[<<b, a>>] = BurstMsgs(w, b),
                        !.hab[<<a, b>>] = IF "A" \in Fixes THEN { x \in Clients : HeldAt(w, a, x) } ELSE {},
                        !.hab[<<b, a>>] = IF "A" \in Fixes THEN { x \in Clients : HeldAt(w, b, x) } ELSE {}]

LinkDown(e) ==
  /\ w.up[e] /\ w.lev < MaxLinkEv
  /\ LET a == e[1]  b == e[2]
         W0 == [w EXCEPT !.up[e] = FALSE, !.lev = @ + 1,
                         !.q[<<a, b>>] = <<>>, !.q[<<b, a>>] = <<>>,
                         !.burst = @ \ {<<a, b>>, <<b, a>>}]
         SA == Comp(W0, a)  SB == Comp(W0, b)
         W1 == [W0 EXCEPT !.bsrv = [x \in Servers |->
                  IF x \in SA THEN @[x] \ SB ELSE @[x] \ SA]]
         \* each side sees exit_client(victim = the far end of the dead link)
         W2 == SquitSide(W1, SA, b, SB)
     IN w' = SquitSide(W2, SB, a, SA)

Deliver(f, s) ==
  /\ <<f, s>> \in DP /\ w.q[<<f, s>>] # <<>>
  /\ LET m == Head(w.q[<<f, s>>]) IN
     w' = Handle([w EXCEPT !.q[<<f, s>>] = Tail(@)], f, s, m)

Env ==
  /\ (QuietEnv => AllQuiet /\ ~PromotePending(w))
  /\ \/ \E s \in Servers, k \in KCs, n \in Nicks : Login(s, k, n)
     \/ \E c \in Clients : DiscPrim(c) \/ DiscAlias(c) \/ Expire(c)
     \/ \E e \in E : LinkUp(e) \/ LinkDown(e)

Next == (\E p \in DP : Deliver(p[1], p[2])) \/ (\E c \in Clients : PromoteTimer(c)) \/ Env

Spec == Init /\ [][Next]_vars /\ \A p \in DP : WF_vars(Deliver(p[1], p[2]))
             /\ \A c \in Clients : WF_vars(PromoteTimer(c))

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)
AllUp(W)     == \A e \in E : W.up[e]
Quiescent(W) == AllUp(W) /\ (\A p \in DP : W.q[p] = <<>>) /\ W.burst = {}
                /\ \A x \in Servers : W.bsrv[x] = {}
                /\ ~PromotePending(W)
LiveConns    == { c \in Clients : w.kind[c] \in {"live", "alias", "ghost"} }

\* Invariant 16: no session ever has a member of another Keycloak id.
KcBound ==
  \A s \in Servers : S(w, s).ex =>
     \A x \in Clients : (Pres(w, s, x) /\ (S(w,s).prim = x \/ <<w.home[x], x>> \in S(w,s).als))
                        => ~Conf(SessKc(w, s), w.kc[x])

\* Invariant 16 across servers: records of one session id never carry two ids.
KcAgree ==
  \A s, t \in Servers : S(w,s).ex /\ S(w,t).ex /\ S(w,s).sid = S(w,t).sid
                        => ~Conf(SessKc(w, s), SessKc(w, t))

\* No convergence step ever tears down a connection the user still has.
NoLiveLoss == w.bad \cap {"liveKilledByCollision", "liveKilledByRemoteKill",
                          "liveKilledBySessionKill", "liveKilledByAliasCascade",
                          "liveKilledByRetire", "liveRemovedByBXX",
                          "liveRemovedByBXP"} = {}
NoBadDemote == w.bad \cap {"demoteOfRemotePrimary", "liveDemotedUnderGhost",
                           "bogusAliasNumeric"} = {}

\* At quiescence (single Keycloak id): every server agrees on one session
\* (same sessid, same primary), there is one non-alias identity, every open
\* connection is a member, and no server keeps a phantom client.
Agree ==
  Quiescent(w) =>
   /\ LiveConns # {} =>
        /\ \A s \in Servers : S(w, s).ex
        /\ \A s, t \in Servers : S(w,s).sid = S(w,t).sid /\ S(w,s).prim = S(w,t).prim
        /\ \E s \in Servers : S(w,s).prim \in LiveConns
   /\ Cardinality({ c \in Clients : w.kind[c] \in {"live", "ghost"} }) <= 1
   /\ \A c \in Clients : w.kind[c] \in {"live", "alias"} =>
        \A s \in Servers : Pres(w, s, c) /\ (S(w,s).prim = c \/ <<w.home[c], c>> \in S(w,s).als)
   /\ \A s \in Servers, c \in Clients :
        Pres(w, s, c) => (w.kind[c] # "gone" /\ (V(w, s, c).al <=> w.kind[c] = "alias"))
   /\ LiveConns = {} => \A s \in Servers : ~S(w, s).ex

\* Replicas also agree on ACTIVE/HOLDING at quiescence (finding J family).
AgreeState ==
  Quiescent(w) => \A s, t \in Servers : S(w,s).ex /\ S(w,t).ex => S(w,s).st = S(w,t).st

\* Whenever nothing is in flight (links may be down): no session record is
\* left without a primary, and no open alias connection is left without one.
NoZombie ==
  (\A p \in DP : w.q[p] = <<>>) /\ ~PromotePending(w) =>
    /\ \A s \in Servers : S(w, s).ex => S(w, s).prim # 0
    /\ \A c \in Clients : w.kind[c] = "alias" => V(w, w.home[c], c).ap # 0

\* Liveness: once the environment stops and the network is healed, it settles.
Settles == <>[](AllUp(w) => Quiescent(w))

\* State constraint (keeps TLC finite: queues are bounded by budgets anyway)
Bound == \A p \in DP : Len(w.q[p]) <= 12
=============================================================================
