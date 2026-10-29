#!/usr/bin/env python3
"""Generate the P10 seed corpus for fuzz_p10.

Every seed is: one flag byte (see fuzz_p10.c) followed by raw P10 lines as
the peer "hub.fuzz" (numeric AB, capacity A]] = 4096 clients) would send
them after its PASS/SERVER line.  We are fuzz.local, numeric AK; local
users (flag 0x08) are alice / bob, numerics AKAAA / AKAAB, in #fuzz.

  python3 gen_seeds.py <outdir>
"""
import os
import sys
import time

POST_EB, LEGACY, ULINE, LOCALS, TIMERS = 0x01, 0x02, 0x04, 0x08, 0x10

TS = 1760000000
NOW = int(time.time())

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"


def b64(n, width):
    s = ""
    for _ in range(width):
        s = B64[n & 63] + s
        n >>= 6
    return s


def ip4(a, b, c, d):
    return b64((a << 24) | (b << 16) | (c << 8) | d, 6)


def msgtag(ms=None, msgid="ABAAAAAAAAAAAB", extra=""):
    """Compact S2S tag prefix: @A<time7><msgid14>[,S..][,M..][,C..]"""
    if ms is None:
        ms = NOW * 1000
    return "@A" + b64(ms, 7) + msgid + extra + " "


def user(nick, num, modes="+i", acct=None, ip=None, host=None, extra=""):
    ip = ip or ip4(10, 0, 0, int(num[-1:], 36) % 250 + 1 if num[-1:].isalnum() else 1)
    host = host or (nick.lower() + ".example.net")
    params = ""
    if acct:
        if "r" not in modes:
            modes += "r"
        params = " " + acct
    return "AB N %s 2 %d %s %s %s%s%s %s %s :%s real\n" % (
        nick, TS, nick.lower(), host, modes, params, extra, ip, num, nick)


BASE_USERS = (
    user("Nick1", "ABAAA", "+iw") +
    user("Acct2", "ABAAB", "+ix", acct="acct2") +
    user("Oper3", "ABAAC", "+iowg") +
    user("Six4", "ABAAD", "+i", ip="_") )

BASE_BURST = (
    BASE_USERS +
    "AB B #test %d +nt ABAAA:o,ABAAB:v,ABAAC\n" % (TS - 100) +
    "AB B #fuzz %d +ntk key ABAAA:o,ABAAB\n" % (TS - 99999) +
    "AB B #bans %d +ntlim 10 ABAAC:ov,ABAAD :%%*!*@bad.host ~*!*@good.host\n" % TS)


def server_behind(name="leaf.fuzz", num="AC", hop=2, flags="+h6v"):
    return "AB S %s %d %d %d J10 %sA]] %s :leaf server\n" % (name, hop, TS, NOW, num, flags)


seeds = {}


def add(name, flags, body):
    seeds[name] = bytes([flags]) + body.encode("latin-1")


# --- plain bursts -----------------------------------------------------
add("burst_basic", 0, BASE_BURST + "AB EB\n")
add("burst_basic_post", POST_EB, BASE_BURST)
add("burst_locals", LOCALS, BASE_BURST + "AB EB\nABAAA P #fuzz :hello locals\nABAAA P AKAAA :hi alice\n")
add("burst_legacy", LEGACY, BASE_BURST + "AB EB\n")
add("burst_uline", ULINE | LOCALS, BASE_BURST + "AB EB\n")
add("burst_oplevels", POST_EB,
    BASE_USERS + "AB B #ol %d +ntAU apass upass ABAAA:o999,ABAAB:o50,ABAAC:100\n" % TS +
    "AB B #ol %d ABAAD:v\n" % TS)
add("burst_halfop", POST_EB,
    BASE_USERS + "AB B #half %d +ntl 5 ABAAA:h,ABAAB:oh,ABAAC:vh :%%*!*@x ~ *!*@y\n" % TS)
add("burst_continued", POST_EB,
    BASE_USERS + "AB B #big %d +nt ABAAA,ABAAB\nAB B #big %d ABAAC:o\nAB B #big %d :%%a!*@* b!*@* c!*@*\n" % (TS, TS, TS))
add("burst_zannel", POST_EB, BASE_USERS + "AB B #empty %d +ntP\nAB B #empty %d +ntP :%%ban!*@*\n" % (TS, TS))
add("burst_ts_older", LOCALS | POST_EB,
    BASE_USERS + "AB B #fuzz 1000000000 +smntilk 3 key ABAAA:o,ABAAB:v :%*!*@*\n")
add("burst_ts_newer", LOCALS,
    BASE_USERS + "AB B #fuzz 1900000000 +m ABAAA:o\nAB EB\n")
add("burst_ipv6", POST_EB,
    "AB N V6a 2 %d u v6.example +i _ ABAAE :v6\n" % TS +
    "AB N V6b 2 %d u v6.example +i AAAAAAAAAAAAAAAAAAAAAB ABAAF :v6\n" % TS +
    "AB N V6c 2 %d u v6.example +i AAAA_AAB ABAAG :v6\n" % TS)
add("nick_modes_params", POST_EB,
    "AB N Full 2 %d user real.host +rhfCcxoi acc vuser@vhost.net fake.host cloak.host cloak.ip %s ABAAH :full modes\n" % (TS, ip4(1, 2, 3, 4)) +
    "AB N Mark 2 %d user host +iI %s ABAAI :mark\n" % (TS, ip4(1, 2, 3, 5)))
add("nick_collision", LOCALS | POST_EB,
    "AB N alice 2 %d evil evil.host +i %s ABAAJ :collide\n" % (TS - 10, ip4(6, 6, 6, 6)) +
    "AB N bob 2 %d bob bob.host +i %s ABAAK :collide newer\n" % (NOW + 10, ip4(6, 6, 6, 7)))
add("nick_change", POST_EB,
    BASE_USERS + "ABAAA N NewNick %d\nABAAB N nick1 %d\nABAAC N Oper3 %d\n" % (NOW, NOW, NOW))

# --- servers behind the link -------------------------------------------
add("servers_tree", POST_EB,
    server_behind() + server_behind("leaf2.fuzz", "AD", 3).replace("AB S", "AC S") +
    "AC N Leafy 3 %d l leaf.host +i %s ACAAA :leaf user\n" % (TS, ip4(9, 9, 9, 9)) +
    "AD N Leafy2 4 %d l leaf.host +i %s ADAAA :leaf user\n" % (TS, ip4(9, 9, 9, 8)) +
    "AC EB\nAD EB\nAB SQ leaf.fuzz 0 :bye\n")
add("server_squit_ts", POST_EB,
    server_behind() + "AC N L 3 %d l h +i %s ACAAA :x\n" % (TS, ip4(9, 9, 9, 9)) +
    "AB SQ leaf.fuzz %d :bye\nAB SQ fuzz.local 0 :me\n" % NOW)
add("server_services", POST_EB,
    server_behind("services.fuzz", "]]", 2, "+s") +
    "]] N X3 3 %d x3 services.fuzz +oik %s ]]AAA :Services\n" % (TS, ip4(127, 0, 0, 1)) +
    "]] EB\n]]AAA P #test :hello from services\n")
add("server_dupe", POST_EB, server_behind() + server_behind() + server_behind("fuzz.local", "AK"))
add("server_jupe", POST_EB, "AB JU * +juped.fuzz %d %d :juped\nAB JU * -juped.fuzz %d %d :unjuped\n" % (NOW + 3600, NOW, NOW, NOW + 1))

# --- channel traffic ---------------------------------------------------
add("chan_ops", LOCALS | POST_EB, BASE_BURST +
    "ABAAA J #new %d\nABAAA C #created %d\nABAAB J #created\nABAAA M #created +o ABAAB %d\n"
    "ABAAA M #created +bkl *!*@x key 5\nABAAA M #created -o+v ABAAB ABAAB\n"
    "ABAAA T #created %d %d :new topic\nABAAA K #created ABAAB :kick\n"
    "ABAAA L #created :part\nABAAA I alice #fuzz\nAB OM #fuzz +o AKAAA\nAB CM #fuzz ovbk\n"
    "ABAAA J 0\n" % (TS, TS, TS, TS, NOW))
add("chan_modes_user", POST_EB, BASE_USERS +
    "ABAAA M Nick1 +iwg-x\nABAAC M Oper3 +s +12345\nABAAA M Nick1 :+R\n")
add("privmsg_mix", LOCALS | POST_EB, BASE_BURST +
    msgtag() + "ABAAA P #fuzz :tagged\n" +
    msgtag(extra=",CC+draft/reply=abc;+typing=active") + "ABAAA P AKAAA :client tags\n" +
    msgtag(extra=",Sabc-session-id") + "ABAAA O #fuzz :notice\n" +
    "ABAAA P $*.fuzz :mass\nABAAA P #fuzz,#test :multi\nABAAA P alice@fuzz.local :directed\n"
    "ABAAA P AKAAB :pm bob\nABAAA O AKAAA :notice alice\n")
add("tagmsg", LOCALS | POST_EB, BASE_BURST +
    msgtag(extra=",C+typing=active") + "ABAAA TG #fuzz\n" +
    "@+typing=paused ABAAA TG AKAAA\n" +
    msgtag(extra=",C+react=x") + "ABAAA TG AKAAB\n")
add("tags_weird", POST_EB, BASE_USERS +
    "@A ABAAA P #test :short tag\n@ ABAAA P #test :empty\n@Azzzzzzz%s,M+,S,C ABAAA P #test :x\n" % ("A" * 14) +
    "@A" + "]" * 7 + "ABAAA" + "+ABAAAAAAAAAAAC" * 5 + ",X,Y,Mc1,C" + " ABAAA P #test :many\n" +
    "@" + "x" * 8000 + " ABAAA P #test :long tags\n")
add("away_setname", LOCALS | POST_EB, BASE_BURST +
    "ABAAA A :gone\nABAAA A\nABAAA SR :new realname\nABAAA WA\n")

# --- accounts / services ----------------------------------------------
add("account", LOCALS | POST_EB | ULINE, BASE_USERS +
    "AB AC ABAAA R acc1 %d\nAB AC ABAAA M acc1b\nAB AC ABAAA U\n"
    "AB AC AKAAA R alice %d ZP-D7eraToi4r24EgSYing\nAB AC AKAAA U\n"
    "AB AC ABAAB acc2 %d\nAB AC ABAAC C .5.123 acc :pass\nAB AC AK A .5.123 acc\nAB AC AK D .5.123\n" % (TS, TS, TS))
add("services_cmds", LOCALS | POST_EB | ULINE, BASE_USERS +
    "AB SN AKAAA newalice %d\nAB SJ AKAAB #svsjoin\nAB SP AKAAB #svsjoin :bye\n"
    "AB SM AKAAB +x\nAB SW AKAAA :swhois text\nAB FA AKAAA fake.vhost\nAB SH AKAAA user host.x\n"
    "AB MK AKAAA DNSBL_DATA :mark\nAB MK AKAAA CVERSION :xchat\nAB SX AKAAB :svsquit\n" % NOW)
add("sasl", LOCALS | POST_EB | ULINE,
    "AB SASL AK AK!5.123 C +\nAB SASL AK AK!5.123 L acct %d\nAB SASL AK AK!5.123 D S\n"
    "AB SASL AK AK!5.124 M :PLAIN,EXTERNAL\nAB SASL * AB!1.1 S PLAIN\nAB SASL AK AK!99999.1 D F\n" % TS +
    "AB SASL AK AK!x C :" + "A" * 400 + "\n")
add("cacheinval", POST_EB,
    "AB CI someuser\nAB CI someuser ZP-D7eraToi4r24EgSYing\n"
    "AB CI a,b,c ZP-D7eraToi4r24EgSYing evt-1.2:3 D\nAB CI * * evt-2 P B\nAB CI x * evt-1.2:3 D\n"
    "AB CI acct2 * evt-9 X\n")
add("kill_quit", LOCALS | POST_EB, BASE_BURST +
    "ABAAA Q :quit\nAB D ABAAB :fuzz.hub!killer (die)\nABAAC D AKAAA :oper (bye)\nAB D AKAAB :x\nAB D ZZZZZ :gone\n")
add("glines", POST_EB, BASE_USERS +
    "AB GL * +*@bad.host %d %d %d :reason\nAB GL * -*@bad.host %d %d %d\n"
    "AB GL * +#chan* %d %d %d :badchan\nAB GL fuzz.local !+$Rrealname %d %d %d :rn\n"
    "AB ZL * +1.2.3.0/24 %d %d %d :zl\nAB ZL * -1.2.3.0/24 %d %d %d\n"
    "AB SU * +*@shun.host %d %d %d :shun\nAB SU * -*@shun.host %d %d %d\n"
    % ((3600, NOW, NOW + 3600) * 8))
add("settime_ping", POST_EB,
    "AB SE %d :hub.fuzz\nAB G !%d.123 fuzz.local\nAB G :fuzz.local\nAB Z AK :1 2 3\nAB EA\n" % (NOW, NOW))
add("numerics_wallops", LOCALS | POST_EB, BASE_USERS +
    "AB 401 AKAAA nick :No such nick\nAB 311 AKAAA nick u h * :r\nAB WA :wallops\nABAAC WU :wallusers\n"
    "ABAAC DS :desynch\nAB W AKAAA :Nick1\nABAAA W AK :alice\nABAAA V AK\nABAAA MO AK\n")
add("stats_etc", POST_EB, BASE_USERS +
    "ABAAC R d AK\nABAAC R u AK\nABAAA LI AK *\nABAAA A0 AK\nABAAA TI AK\nABAAA AD AK\nABAAA IN AK\nABAAA TR AK\n"
    "ABAAC CO leaf.fuzz 4400 AK\nABAAC RI AK :x\nABAAC RO AK :x\nABAAA CP 1.2.3.4 AK\nABAAC GET AK HUB\n")

# --- IRCv3 S2S extensions ---------------------------------------------
add("metadata", LOCALS | POST_EB, BASE_BURST +
    "AB MD ABAAA avatar :http://x/y.png\nAB MD ABAAA display-name P :Visible\nAB MD #test topic-url :http://t\n"
    "AB MD ABAAA avatar\nAB MD * avatar :x\nAB MD AKAAA color :red\nAB MD #fuzz k1 P :1\n"
    "AB MD *acct2 avatar :acct-level\nABAAA MD ABAAA key :v\nAB MD ABAAA " + "k" * 300 + " :v\n")
add("metadata_burst", 0, BASE_BURST +
    "AB MD ABAAA avatar :http://x\nAB MD #test k :v\nAB MD ABAAB k * :visible\nAB EB\n")
add("markread", LOCALS | POST_EB | ULINE, BASE_BURST +
    "AB MR alice #fuzz 2025-01-01T00:00:00.000Z\nAB MR acct2 #test 2025-01-01T00:00:00.000Z\n"
    "AB MR acct2 nick1 timestamp=2025-01-01T00:00:00.000Z\nAB MR acct2 #test *\nABAAB MR acct2 #test x\n")
add("multiline", LOCALS | POST_EB, BASE_BURST +
    "ABAAA ML +ab1 #fuzz :line one\nABAAA ML ab1 #fuzz :line two\nABAAA ML cab1 #fuzz :concat\nABAAA ML -ab1 #fuzz :\n"
    "ABAAA ML +ab2 AKAAA :dm one\nABAAA ML -ab2 AKAAA :\n" +
    msgtag(extra=",M+ab3") + "ABAAA ML #fuzz :new form\n" +
    msgtag(extra=",Mcab3") + "ABAAA ML #fuzz :concat new\n" +
    msgtag(extra=",M.ab3") + "ABAAA ML #fuzz :plain\n" +
    msgtag(extra=",M-ab3") + "ABAAA ML #fuzz :\n" +
    msgtag(extra=",M?") + "ABAAA ML #fuzz :bad\n" +
    "ABAAA ML ab9 #fuzz :orphan continuation\nABAAA ML -ab9 #fuzz :\n")
add("redact_rename", LOCALS | POST_EB, BASE_BURST +
    "ABAAA RD #fuzz ABAAAAAAAAAAAB :reason\nABAAA RD AKAAA ABAAAAAAAAAAAC\n"
    "ABAAA RN #test #renamed :why\nAB RN #fuzz #fuzz2 %d:reason\nABAAA RN #nonexist #x\n" % TS)
add("webpush_s2s", POST_EB,
    "AB WP V :BKey\nAB WP R acct2 ep k a %d x\nAB WP U acct2 x\nAB WP B acct2 ep k a %d x\nAB WP K acct2 1 2 x 3 :y\n" % (TS, TS))
add("chathistory_s2s", LOCALS | POST_EB, BASE_BURST +
    "ABAAA CH AK #fuzz LATEST * 10\nAB CH AK #fuzz BEFORE timestamp=2025-01-01T00:00:00.000Z 50\nAB HY AK x\n")
add("misc_tokens", POST_EB, BASE_USERS +
    "ABAAA TM #test\nABAAA BT C\nABAAA PR x\nABAAA BO x\nAB MX x\nAB TK x\nAB PN x\nAB VF x\nAB RG x\nAB SH x\n"
    "AB PRIVS ABAAC PRIV_A\nAB CC x\nAB XQ AK routing :query\nAB XR AK routing :reply\nAB SNO 1 :x\nAB RL x\nAB OPM x\n")

# --- bouncer BS / BX ---------------------------------------------------
SID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
TOK = "Tok0123456789abcdef"
BS_BASE = (
    user("Bnc", "ABAAL", "+ix", acct="bnc") +
    "AB B #bnc %d +nt ABAAL:o\n" % TS)
add("bs_create_active", POST_EB, BS_BASE +
    "AB BS C bnc %s %s active %d 3 1200 :#bnc,#test\n" % (SID, TOK, TS) +
    "AB BS A bnc %s ABAAL %d 0\nAB BX U ABAAL cc=4\nAB BX U ABAAL ta=3600\nAB BX U ABAAL kcid=ZP-D7eraToi4r24EgSYing\n" % (SID, NOW) +
    "AB BX U ABAAL la=%d\nAB BX U ABAAL aw=1\nAB BX U ABAAL aw=2\nAB BX U ABAAL caps=ff\n" % NOW)
add("bs_create_holding", POST_EB, BS_BASE +
    "AB BS C bnc %s %s holding %d %d 2 600 :#bnc\n" % (SID, TOK, TS, NOW - 60) +
    "AB BS D bnc %s %d :#bnc,#other\nAB BS U bnc %s name=profile2\n" % (SID, NOW, SID) +
    "AB BS O bnc %s %d operx\nAB BS O bnc %s\nAB BS T bnc %s AC\nAB BS X bnc %s\n" % (SID, NOW, SID, SID, SID))
add("bx_alias_lifecycle", LOCALS | POST_EB, BS_BASE +
    "AB BS C bnc %s %s active %d :#bnc\n" % (SID, TOK, TS) +
    "AB BX C ABAAL ABAAM bnc %s +ix :#bnc\n" % SID +
    "AB BX C ABAAL ABAAN bnc %s +ix prof1 :#bnc,#fuzz\n" % SID +
    "AB BX C ABAAL ABAAO bnc %s :#bnc\n" % SID +
    "AB BX U ABAAM host=new.host\nAB BX U ABAAM realhost=r.host\nAB BX U ABAAM realname=RN\n"
    "AB BX U ABAAM fakehost=f.h\nAB BX U ABAAM cloakhost=c.h\nAB BX U ABAAM cloakip=c.i\n"
    "AB BX U ABAAM username=uu\nAB BX U ABAAM account=other\nAB BX U ABAAM caps=1f\n"
    "AB BX N ABAAL BncNew %d\nAB BX V ABAAM +#bnc\nAB BX V ABAAM -#bnc\n" % NOW +
    "AB BX K ABAAL 1234 %d\nAB BX K ABAAM 0 %d\n" % (NOW, NOW) +
    "ABAAM P #bnc :from alias\nABAAM J #fuzz\nABAAM L #fuzz\nABAAM N ShouldFail %d\n" % NOW +
    "AB BX P ABAAL ABAAM %s Bnc\nAB BX X ABAAN\nAB BX X ABAAO\nABAAL Q :primary gone\n" % SID)
add("bx_echo", LOCALS | POST_EB, BS_BASE +
    "AB BS C bnc %s %s active %d :#bnc\nAB BX C ABAAL ABAAM bnc %s +ix :#bnc\n" % (SID, TOK, TS, SID) +
    "AB BX E ABAAM ABAALP AKAAA ABAAAAAAAAAAAB :echoed pm\nAB BX E ABAAL ABAAMO #bnc ABAAAAAAAAAAAC :echo notice\n"
    "AB BX M+b1 ABAAM ABAALP AKAAA ABAAAAAAAAAAAD :line1\nAB BX M b1 ABAAM :line2\nAB BX Mcb1 ABAAM :cc\n"
    "AB BX M-b1 ABAAM :https://paste/x\nAB BX M+b2 ABAAM ABAALP AKAAA ABAAAAAAAAAAAE @+draft/reply=x :x\n")
add("bx_burst_inburst", 0, BS_BASE +
    "AB BS C bnc %s %s active %d 1 10 :#bnc\nAB BX C ABAAL ABAAM bnc %s +ix :#bnc\n" % (SID, TOK, TS, SID) +
    "AB BX U ABAAM caps=3\nAB BX U ABAAM aw=0\nAB BX C ABAAL ABAAP bnc %s +i :\nAB EB\n" % SID)
add("bx_pending", POST_EB,
    "AB BX U ABAAZ host=x\nAB BX U ABAAZ la=1\nAB BX E ABAAZ ABAALP x y :z\nAB BX K ABAAZ 1 2\n" + BS_BASE +
    "AB BS C bnc %s %s active %d :#bnc\nAB BX C ABAAL ABAAZ bnc %s +i :#bnc\n" % (SID, TOK, TS, SID))
add("bs_local_session", LOCALS | POST_EB | ULINE,
    "AB AC AKAAA R alice %d\nAB BS C alice %s %s active %d :#fuzz\nAB BS A alice %s AKAAA %d 0\n" % (TS, SID, TOK, TS, SID, NOW) +
    "AB BX C AKAAA ABAAQ alice %s +i :#fuzz\nAB BX P AKAAA ABAAQ %s alice\nAB BS X alice %s\n" % (SID, SID, SID))
add("bs_bad", POST_EB,
    "AB BS C\nAB BS C a\nAB BS C a b c d e f g\nAB BS C a b c holding x\nAB BS A a b\nAB BS A a b ZZ\n"
    "AB BS D a b\nAB BS U a b\nAB BS U a b noeq\nAB BS O a b 1\nAB BS T a b\nAB BS Q a b c\n"
    "AB BX\nAB BX C\nAB BX C A B C D E\nAB BX X\nAB BX X A\nAB BX P A B\nAB BX N A\nAB BX U A\nAB BX E A\nAB BX M\nAB BX K\nAB BX V A\nAB BX Z unknown\n"
    "AB BX R x\nAB BX F x\nAB BX J x\nAB BT x\n")
add("bs_sqit_promote", POST_EB | TIMERS, server_behind() +
    "AC N Bnc 3 %d bnc h +ixr bnc %s ACAAA :bnc\n" % (TS, ip4(5, 5, 5, 5)) +
    "AC BS C bnc %s %s active %d :#x\nAB BX C ACAAA ABAAR bnc %s +i :#x\n" % (SID, TOK, TS, SID) +
    "AB SQ leaf.fuzz 0 :split\n")
add("timers_hold", LOCALS | POST_EB | ULINE | TIMERS,
    "AB AC AKAAA R alice %d\nAB BS C alice %s %s holding %d %d :#fuzz\n" % (TS, SID, TOK, TS, NOW - 10) +
    "AB D AKAAA :x\n")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "seeds")
    os.makedirs(out, exist_ok=True)
    for name, data in sorted(seeds.items()):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    print("wrote %d seeds to %s" % (len(seeds), out))
