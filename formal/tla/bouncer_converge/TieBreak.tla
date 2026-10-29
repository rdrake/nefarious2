------------------------------ MODULE TieBreak ------------------------------
(***************************************************************************)
(* Exhaustive check of the pure tie-break bounce_converge_peer_wins()     *)
(* (ircd/bouncer_converge.c:16-33) over a small sessid domain that        *)
(* includes NULL and "" (both normalised to "" at :20-23).                *)
(*                                                                         *)
(* Sessids are modelled by their lexicographic rank: NULL and "" map to   *)
(* rank 0 (the empty string sorts first), "a" < "b" are ranks 1 < 2.      *)
(***************************************************************************)
EXTENDS Integers

Ids     == {"NULL", "", "a", "b"}
Rank(x) == CASE x = "NULL" -> 0 [] x = "" -> 0 [] x = "a" -> 1 [] x = "b" -> 2
Norm(x) == IF x = "NULL" THEN "" ELSE x          \* bouncer_converge.c:20-23

\* bouncer_converge.c:16-33, transliterated.
PeerWins(lh, ls, ph, ps) ==
  IF ~lh /\ ph THEN FALSE                         \* :26-27 live beats held
  ELSE IF lh /\ ~ph THEN TRUE                     \* :28-29
  ELSE Rank(ps) < Rank(ls)                        \* :33 strcmp(peer, local) < 0

\* Each side calls PeerWins(mine, theirs).  Consistency = exactly one of the
\* two records survives when they are DIFFERENT records, and both keep
\* "ours" (no retire) when they are the same record.
SameRecord(ls, ps) == Norm(ls) = Norm(ps)

Antisym ==
  \A lh, ph \in BOOLEAN : \A ls, ps \in Ids :
     LET a == PeerWins(lh, ls, ph, ps)   \* local's verdict about peer
         b == PeerWins(ph, ps, lh, ls)   \* peer's verdict about local
     IN  IF lh = ph /\ SameRecord(ls, ps)
           THEN ~a /\ ~b                 \* same session: nobody retires
           ELSE a # b                    \* exactly one side yields

\* Cases where the pure function is consistent only because of the
\* string normalisation: two DIFFERENT sessions, both with an empty/NULL
\* id, same state -> neither side yields (both keep "ours").
EmptyIdCollision ==
  { <<lh, ls, ps>> \in BOOLEAN \X Ids \X Ids :
       ls # ps /\ SameRecord(ls, ps) /\ ~PeerWins(lh, ls, lh, ps) /\ ~PeerWins(lh, ps, lh, ls) }

VARIABLE dummy
Init == dummy = 0
Next == UNCHANGED dummy
Spec == Init /\ [][Next]_dummy
Inv  == Antisym
=============================================================================
