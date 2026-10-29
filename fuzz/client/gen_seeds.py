#!/usr/bin/env python3
"""Generate the seed corpus for the client-protocol harness.

Each seed is: one mode byte, then '\n'-separated lines (see fuzz_client.c).
Mode bits: 0x01 register A, 0x02 all caps, 0x04 SASL login, 0x08 peer B on
#fuzz, 0x10 A is oper, 0x20 A over WebSocket, 0x40 A auto-joins #fuzz.
Line control bytes: 0x01 = line from B, 0x02 N = advance clock N seconds,
0x03 = A's connection drops, 0x04 = A reconnects, 0x05 = raw bytes.
"""
import base64
import os
import sys

REG, CAPS, SASL, PEER, OPER, WS, CHAN = 1, 2, 4, 8, 16, 32, 64
FULL = REG | CAPS | SASL | PEER | CHAN
B = "\x01"
T = lambda n: "\x02" + chr(n)
DROP = "\x03"
RECONNECT = "\x04"
RAW = "\x05"

def b64(s):
    return base64.b64encode(s.encode()).decode()

seeds = {}

def seed(name, mode, lines):
    data = bytes([mode]) + "\n".join(lines).encode("utf-8", "surrogateescape")
    seeds[name] = data

# --- unregistered state ---------------------------------------------------
seed("unreg_basic", 0, ["NICK a", "USER a 0 * :real", "PING :x", "PONG :x"])
seed("unreg_cap", 0, ["CAP LS 302", "CAP LIST", "CAP REQ :sasl message-tags",
                      "CAP REQ :-sasl", "CAP CLEAR", "CAP END", "NICK u1",
                      "USER u 0 * :u"])
seed("unreg_cap_bad", 0, ["CAP", "CAP FOO", "CAP REQ", "CAP REQ :" + "x" * 300,
                          "CAP LS 999999999999", "CAP REQ :draft/multiline=1"])
seed("unreg_sasl_plain", 0, ["CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN",
                             "AUTHENTICATE " + b64("\0fuzzacct\0fuzzpass"),
                             "NICK s1", "USER s 0 * :s", "CAP END"])
seed("unreg_sasl_badpw", 0, ["CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN",
                             "AUTHENTICATE " + b64("\0fuzzacct\0nope"),
                             "AUTHENTICATE PLAIN",
                             "AUTHENTICATE " + b64("authz\0fuzzalt\0fuzzpass"),
                             "CAP END", "NICK s2", "USER s 0 * :s"])
seed("unreg_sasl_split", 0, ["CAP LS 302", "CAP REQ :sasl", "AUTHENTICATE PLAIN",
                             "AUTHENTICATE " + "A" * 400, "AUTHENTICATE " + "A" * 400,
                             "AUTHENTICATE +", "AUTHENTICATE *"])
seed("unreg_sasl_mechs", 0, ["CAP LS 302", "CAP REQ :sasl",
                             "AUTHENTICATE EXTERNAL", "AUTHENTICATE +",
                             "AUTHENTICATE OAUTHBEARER",
                             "AUTHENTICATE " + b64("n,a=fuzzacct,\x01auth=Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig\x01\x01"),
                             "AUTHENTICATE SCRAM-SHA-256",
                             "AUTHENTICATE " + b64("n,,n=fuzzacct,r=abcdefghijklmnop"),
                             "AUTHENTICATE " + b64("c=biws,r=abcdefghijklmnopXYZ,p=AAAA"),
                             "AUTHENTICATE BOGUS", "AUTHENTICATE *"])
seed("unreg_pass_webirc", 0, ["PASS :secret", "WEBIRC fuzzwebirc gw host.example 192.0.2.55 :secure local-port=6697 remote-port=5555 certfp-sha-256=abcd",
                              "NICK w1", "USER w 0 * :w"])
seed("unreg_webirc_v6", 0, ["WEBIRC fuzzwebirc gw host6.example 2001:db8::1",
                            "WEBIRC bad gw h 1.2.3.4", "WEBIRC fuzzwebirc gw h notanip",
                            "NICK w2", "USER w 0 * :w"])
seed("unreg_register", 0, ["CAP LS 302", "CAP REQ :draft/account-registration",
                           "REGISTER * user@example.com :password123",
                           "REGISTER newacct * hunter22", "VERIFY newacct 123456",
                           "NICK r1", "USER r 0 * :r", "CAP END"])
seed("unreg_metadata_before", 0, ["CAP LS 302", "CAP REQ :draft/metadata-2",
                                  "METADATA * SET avatar :https://x/y.png",
                                  "METADATA * GET avatar", "METADATA * LIST",
                                  "CAP END", "NICK m1", "USER m 0 * :m"])
seed("unreg_badnick", 0, ["NICK", "NICK :", "NICK #chan", "NICK " + "n" * 40,
                          "NICK -bad", "NICK a\xe9b", "NICK ChanServ", "USER", "USER a",
                          "USER a b c", "NICK ok", "USER " + "u" * 40 + " 0 * :r"])
seed("unreg_server", 0, ["SERVER fake.server 1 123 456 J10 AB]]] +s :desc", "PASS x"])
seed("unreg_tags", 0, ["@label=1 CAP LS 302", "@" + "a" * 600 + " PING x",
                       "@a=b;c=d\\s\\:\\\\;e PING :x", "@;; PING x", "@ PING x",
                       "@+x=" + "\\" * 30 + " PING x"])
seed("unreg_starttls", 0, ["STARTTLS", "CAP LS 302", "STARTTLS"])
seed("unreg_long", 0, ["PING :" + "x" * 600, "PRIVMSG a :" + "y" * 9000, "NICK z"])
seed("unreg_crlf", 0, [RAW + "NICK a\rUSER a 0 * :x\r\n\r\n\n\n"])
seed("unreg_nonl", 0, [RAW + "NICK " + "q" * 9000])
seed("unreg_quit", 0, ["NICK q", "QUIT :bye", "NICK again"])

# --- registered basics ----------------------------------------------------
seed("reg_basic", REG, ["JOIN #a", "PRIVMSG #a :hi", "NOTICE #a :n", "PART #a :bye",
                        "MODE fuzzA +iw", "MODE fuzzA", "WHOIS fuzzA", "WHO fuzzA",
                        "AWAY :gone", "AWAY", "QUIT :done"])
seed("reg_join_many", REG, ["JOIN #a,#b,#c,&d k1,k2", "JOIN 0", "JOIN #a,#a,#a",
                            "JOIN " + ",".join("#c%d" % i for i in range(25)),
                            "JOIN #quarantined", "JOIN :", "JOIN #" + "x" * 250])
seed("reg_modes", REG | CHAN | PEER, [
    "MODE #fuzz", "MODE #fuzz +ntsk key", "MODE #fuzz +l 10", "MODE #fuzz +b *!*@*",
    "MODE #fuzz +b", "MODE #fuzz -b *!*@*", "MODE #fuzz +ov fuzzB fuzzB",
    "MODE #fuzz +imMNCcDdHPQRrSsTtZz", "MODE #fuzz +L #fuzz2", "MODE #fuzz -L",
    "MODE #fuzz +bbbbbbb a b c d e f g", "MODE #fuzz +e x!y@z", "MODE #fuzz +I *!*@*",
    "MODE #fuzz +a", "MODE #fuzz +O", "MODE #fuzz +H 5:60",
    "MODE fuzzA +xRDdgwso", "MODE fuzzA -x", "MODE fuzzB +i"])
seed("reg_chanops", FULL, [
    B + "MODE #fuzz +o fuzzA", "TOPIC #fuzz :new topic", "TOPIC #fuzz",
    "KICK #fuzz fuzzB :out", B + "JOIN #fuzz", "INVITE fuzzB #fuzz", "INVITE",
    "KICK #fuzz fuzzA", B + "KICK #fuzz fuzzA :x", "JOIN #fuzz",
    "CLEARMODE #fuzz ovbkl", "OPMODE #fuzz +o fuzzA", "REMOVE #fuzz fuzzB :r",
    "NAMES #fuzz", "NAMES", "LIST", "LIST >0,<100,C>1,T<99999999", "LIST #fuzz",
    "LIST :#f*"])
seed("reg_privmsg", FULL, [
    "PRIVMSG fuzzB :hello", "PRIVMSG fuzzB,fuzzB,#fuzz :multi", "PRIVMSG @#fuzz :ops",
    "PRIVMSG +#fuzz :voices", "PRIVMSG $*.net :mass", "PRIVMSG #*.net :mass",
    "PRIVMSG nobody :x", "PRIVMSG", "PRIVMSG #fuzz", "PRIVMSG X :help",
    "PRIVMSG X@services.fuzz.test.net :hi", "PRIVMSG fuzzB@fuzz.test.net :hi",
    "PRIVMSG fuzzB%fuzz.test.net :hi", "NOTICE fuzzB :n", "CPRIVMSG fuzzB #fuzz :x",
    "CNOTICE fuzzB #fuzz :x", "WALLCHOPS #fuzz :x", "WALLVOICES #fuzz :x",
    "WALLHOPS #fuzz :x", "PRIVMSG #fuzz :\x01ACTION waves\x01",
    "PRIVMSG fuzzB :\x01VERSION\x01", "TAGMSG fuzzB", "@+typing=active TAGMSG #fuzz",
    "@+draft/reply=abc;+draft/react=:) TAGMSG #fuzz", "CHANSERV help", "LOGIN a b"])
seed("reg_tags", FULL, [
    "@label=abc PRIVMSG #fuzz :labeled", "@label=x;+typing=done PRIVMSG fuzzB :t",
    "@label=" + "L" * 70 + " PING x", "@time=2020-01-01T00:00:00.000Z;msgid=fake PRIVMSG #fuzz :spoof",
    "@batch=nope PRIVMSG #fuzz :x", "@+draft/channel-context=#fuzz PRIVMSG fuzzB :ctx",
    "@+evilnet.github.io/ssid=abc;+evilnet.github.io/rsid=def PRIVMSG fuzzB :x",
    "@" + ";".join("+k%d=%s" % (i, "v" * 40) for i in range(60)) + " TAGMSG #fuzz",
    "@+a=\\:\\s\\r\\n\\\\\\ PRIVMSG #fuzz :esc", "@label=1 WHO #fuzz %tcuhnfdlaor,123",
    "@label=2 LUSERS", "@label=3 NAMES #fuzz", "@label=4 PRIVMSG #fuzz,fuzzB :x"])
seed("reg_queries", REG | PEER, [
    "WHO #fuzz", "WHO * %nuhsrfdlaotc,1", "WHO fuzz* o", "WHO 0 o", "WHO #fuzz %",
    "WHO :x y z", "WHOIS fuzzB fuzzB", "WHOIS *", "WHOIS fuzz.test.net fuzzB",
    "WHOWAS fuzzB", "WHOWAS fuzzB 5 fuzz.test.net", "ISON fuzzB nobody fuzzA",
    "USERHOST fuzzA fuzzB x", "USERIP fuzzB", "LUSERS", "LUSERS * fuzz.test.net",
    "MOTD", "VERSION", "ADMIN", "TIME", "INFO", "LINKS", "LINKS * *.net", "MAP",
    "TRACE", "TRACE fuzzB", "STATS", "STATS u", "STATS m", "STATS p", "STATS webpush",
    "STATS chathistory", "STATS metadata", "STATS f", "HELP", "HELP PRIVMSG",
    "ISUPPORT", "RULES", "OPERMOTD", "PRIVS fuzzA", "IRCOPS", "ISNEF"])
seed("reg_silence_watch_monitor", REG | PEER, [
    "SILENCE +*!*@*", "SILENCE -*!*@*", "SILENCE fuzzA", "SILENCE +~a:x",
    "WATCH +fuzzB +nobody l L", "WATCH S", "WATCH C", "WATCH -fuzzB",
    "MONITOR + fuzzB,nobody,#bad", "MONITOR L", "MONITOR S", "MONITOR - fuzzB",
    "MONITOR C", "MONITOR + " + ",".join("n%d" % i for i in range(140)),
    B + "NICK fuzzB2", B + "QUIT :gone"])
seed("reg_nick", REG | PEER, ["NICK fuzzA2", "NICK fuzzB", "NICK fuzza2", "NICK 0",
                              "NICK fuzzA", T(40), "NICK a" * 10, "SETNAME :new name",
                              "SETNAME", "SETNAME :" + "r" * 300])
seed("reg_oper", REG | OPER, [
    "OPER fuzzoper fuzzoperpass", "MODE fuzzA +s +cdk", "SNO +x", "WALLOPS :hi",
    "WALLUSERS :hi", "GLINE +*@1.2.3.4 600 :bad", "GLINE", "GLINE -*@1.2.3.4",
    "ZLINE +1.2.3.0/24 600 :z", "SHUN +*@1.2.3.5 600 :s", "JUPE +fake.server 600 :j",
    "TEMPSHUN fuzzA :t", "KILL fuzzA :k", "CHECK fuzzA", "CHECK #fuzz", "CHECK fuzz.test.net",
    "SETHOST fuzz.spoofed.host spoofpass", "SETHOST undo", "SWHOIS fuzzA :sw",
    "CLOSE", "STATS F", "STATS c", "STATS k", "STATS z", "STATS memory", "STATS x",
    "STATS chathistoryads", "STATS webpush", "STATS dnsbl", "STATS gitsync",
    "CONNECT fake.server 4400", "SQUIT fake.server :x", "UPING fuzz.test.net",
    "SET MAXCONNECTIONS 10", "RESET MAXCONNECTIONS", "GET MAXCONNECTIONS", "DIE",
    "RESTART", "REHASH", "MKPASSWD hunter2", "MKPASSWD hunter2 smd5", "STORE INFO",
    "XQUERY fuzz.test.net abc :q", "HASH", "DNS l", "PRIVS fuzzA", "OPMODE #fuzz +o fuzzA",
    "SVSNICK fuzzA x", "SVSJOIN fuzzA #o", "FAKE fuzzA fake.host", "MARK fuzzA x y",
    "GITSYNC", "DESYNCH :d", "ASLL fuzz.test.net"])

# --- IRCv3 fork features ---------------------------------------------------
seed("chathistory", FULL, [
    "PRIVMSG #fuzz :one", "PRIVMSG #fuzz :two", B + "PRIVMSG #fuzz :three",
    "PRIVMSG fuzzB :pm", B + "PRIVMSG fuzzA :pm back",
    "CHATHISTORY LATEST #fuzz * 10", "CHATHISTORY LATEST fuzzB * 50",
    "CHATHISTORY BEFORE #fuzz timestamp=2030-01-01T00:00:00.000Z 5",
    "CHATHISTORY AFTER #fuzz timestamp=2000-01-01T00:00:00.000Z 5",
    "CHATHISTORY AROUND #fuzz timestamp=2026-10-29T00:00:00.000Z 3",
    "CHATHISTORY BETWEEN #fuzz timestamp=2000-01-01T00:00:00.000Z timestamp=2030-01-01T00:00:00.000Z 100",
    "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z timestamp=2030-01-01T00:00:00.000Z 10",
    "CHATHISTORY BEFORE #fuzz msgid=AAAAAAAAAAAAAA 10", "CHATHISTORY LATEST #fuzz msgid=x 0",
    "CHATHISTORY LATEST #nochan * 10", "CHATHISTORY", "CHATHISTORY BOGUS #fuzz * 1",
    "CHATHISTORY LATEST #fuzz timestamp=garbage -5", "CHATHISTORY LATEST * * 10",
    "SEARCH in=#fuzz;text=one;limit=5", "SEARCH from=fuzzB", "SEARCH :"])
seed("multiline", FULL, [
    "BATCH +ml1 draft/multiline #fuzz", "@batch=ml1 PRIVMSG #fuzz :line one",
    "@batch=ml1;draft/multiline-concat PRIVMSG #fuzz :cont", "@batch=ml1 PRIVMSG #fuzz :",
    "BATCH -ml1",
    "BATCH +ml2 draft/multiline fuzzB", "@batch=ml2 NOTICE fuzzB :a", "@batch=ml2 PRIVMSG fuzzB :b",
    "BATCH -ml2", "BATCH -ml2", "BATCH +ml3 draft/multiline", "BATCH +ml3 bogus #fuzz",
    "BATCH +ml4 draft/multiline #fuzz", "@batch=wrong PRIVMSG #fuzz :x",
    "@batch=ml4 PRIVMSG #other :x", "BATCH -ml4",
    "BATCH +ml5 draft/multiline #fuzz"] + ["@batch=ml5 PRIVMSG #fuzz :" + "z" * 400] * 45 +
    ["BATCH -ml5", "BATCH", "BATCH +", "BATCH -", "BATCH +x draft/multiline #fuzz", T(60)])
seed("redact", FULL, [
    "@label=m1 PRIVMSG #fuzz :to be redacted", "CHATHISTORY LATEST #fuzz * 1",
    "REDACT #fuzz AHAAAaGIXmLBGV :oops", "REDACT #fuzz nosuchmsgid", "REDACT fuzzB x :r",
    "REDACT", "REDACT #fuzz", "REDACT #nochan abc", B + "REDACT #fuzz abc :x"])
seed("markread", FULL, [
    "MARKREAD #fuzz", "MARKREAD #fuzz timestamp=2026-10-29T12:00:00.000Z",
    "MARKREAD fuzzB timestamp=2026-10-29T12:00:00.000Z", "MARKREAD #fuzz timestamp=bad",
    "MARKREAD", "MARKREAD #fuzz *", "MARKREAD #nochan timestamp=2026-10-29T12:00:00.000Z"])
seed("metadata", FULL, [
    "METADATA * SET avatar :https://example.com/a.png", "METADATA * SET display-name :Fuzzy",
    "METADATA * GET avatar display-name nokey", "METADATA * LIST", "METADATA fuzzB LIST",
    "METADATA #fuzz SET url :https://x", "METADATA #fuzz LIST", "METADATA * SUB avatar color",
    "METADATA * SUBS", "METADATA * UNSUB avatar", "METADATA * SYNC", "METADATA #fuzz SYNC",
    "METADATA * CLEAR", "METADATA * SET bad key :v", "METADATA * SET " + "k" * 100 + " :v",
    "METADATA * SET avatar :" + "v" * 400, "METADATA * BOGUS", "METADATA", "METADATA nobody LIST",
    B + "METADATA * SET status :busy", "METADATA fuzzB GET status"])
seed("webpush", FULL, [
    "WEBPUSH VAPID", "WEBPUSH REGISTER https://push.example.com/abc BOrIiG5V2T6t8W4wQ4pqJ2HqYJwNw9w7FhJm2xJqCq1Q-0r0pH1tJm8b9h8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8 AAAAAAAAAAAAAAAAAAAAAA",
    "WEBPUSH REGISTER http://insecure.example/x a b", "WEBPUSH REGISTER", "WEBPUSH UNREGISTER https://push.example.com/abc",
    "WEBPUSH LIST", "WEBPUSH BOGUS", "@+draft/webpush/mute=#fuzz WEBPUSH VAPID",
    "METADATA * SET draft/webpush/idle :60", B + "PRIVMSG fuzzA :wake up fuzzA", T(120),
    B + "PRIVMSG #fuzz :fuzzA: mention"])
seed("bouncer", FULL, [
    "BOUNCER INFO", "BOUNCER LISTSESSIONS", "BOUNCER LISTCLIENTS", "BOUNCER SETTINGS",
    "BOUNCER SET hold 1", "BOUNCER SET autoreplay 0", "BOUNCER HOLD", "BOUNCER STATUS",
    "BOUNCER TOKEN", "BOUNCER RESUME badtoken", "BOUNCER SETNAME main", "BOUNCER HELP",
    "BOUNCER DISCONNECT fuzzA", "BOUNCER RESET", "BOUNCER ORESET fuzzacct", "BOUNCER HISTORY",
    "BOUNCER", "BOUNCER BOGUS", DROP, T(5)])
seed("persistence", FULL, [
    "PERSISTENCE STATUS", "PERSISTENCE GET", "PERSISTENCE SET ON", "PERSISTENCE SET OFF",
    "PERSISTENCE SET DEFAULT", "PERSISTENCE LIST", "PERSISTENCE DETACH", "PERSISTENCE ATTACH",
    "PERSISTENCE CREATE work", "PERSISTENCE RENAME work play", "PERSISTENCE DELETE play",
    "PERSISTENCE PROFILE", "PERSISTENCE REPLAY", "PERSISTENCE BOGUS", "PERSISTENCE",
    "PERSISTENCE SET ON", "QUIT :hold me", RECONNECT, "PERSISTENCE STATUS",
    "PERSISTENCE ATTACH * AHAAAaGIXmLBGV", "CHATHISTORY LATEST #fuzz * 5"])
seed("bouncer_drop_resume", FULL | OPER, [
    "PERSISTENCE SET ON", "PRIVMSG #fuzz :before drop", DROP, B + "PRIVMSG fuzzA :while held",
    B + "PRIVMSG #fuzz :chan while held", T(3), RECONNECT, "BOUNCER LISTCLIENTS",
    "PRIVMSG #fuzz :after", RECONNECT, "BOUNCER LISTSESSIONS", "QUIT", T(200)])
seed("rename_relocate", FULL | OPER, [
    "RENAME #fuzz #fuzz2 :moving", "RENAME #fuzz2", "RELOCATE #fuzz2 #fuzz3", "LIST",
    "RENAME #nochan #x", "RENAME #fuzz3 &local"])
seed("authtoken", FULL, ["TOKEN", "TOKEN GENERATE", "TOKEN LIST", "TOKEN REVOKE x",
                         "AUTHENTICATE PLAIN", "SASL x y z"])
seed("pre_away", REG | CAPS, ["AWAY :pre", "AWAY *", "AWAY"])
seed("ws_basic", REG | CAPS | WS, ["PRIVMSG fuzzA :ws", "JOIN #w", "PING :x",
                                    RAW + "\x89\x80\x00\x00\x00\x00",
                                    RAW + "\x88\x82\x00\x00\x00\x00\x03\xe8"])
seed("ws_frames", WS, ["NICK wsx", RAW + "\x01\x83abcXYZ", RAW + "\x80\x80\x00\x00\x00\x00",
                       RAW + "\x81\xfe\x00\x05\x01\x02\x03\x04abcde",
                       RAW + "\x82\x85\x00\x00\x00\x00NICK\n", "USER w 0 * :w"])
seed("flood", REG | CAPS, ["PRIVMSG fuzzA :x"] * 60 + [T(30), "PING :after flood"])
seed("timeouts", 0, ["NICK t1", T(250), "USER t 0 * :t", T(250)])
seed("ctcp_dcc", REG | PEER, ["PRIVMSG fuzzB :\x01DCC SEND file 3232235521 5000 100\x01",
                              "PRIVMSG fuzzB :\x01PING 123\x01", "NOTICE fuzzB :\x01PING 1\x01"])
seed("utf8", FULL, ["PRIVMSG #fuzz :café \U0001F600", "SETNAME :éè",
                    "TOPIC #fuzz :\xff\xfe invalid", "JOIN #été"])
seed("history_pm_targets", FULL, [B + "PRIVMSG fuzzA :a", "PRIVMSG fuzzB :b", "NICK fuzzA3",
                                  "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z timestamp=2100-01-01T00:00:00.000Z 50",
                                  "CHATHISTORY LATEST fuzzB * 10", "CHATHISTORY LATEST fuzzacct * 10"])

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, data in seeds.items():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
    # every seed again under a few other mode bytes, so each command is
    # also tried unregistered / registered-without-caps / with everything.
    for name, data in seeds.items():
        for m in (0x00, 0x01, 0x07, 0x5f):
            if data[0] != m:
                with open(os.path.join(outdir, "%s_m%02x" % (name, m)), "wb") as f:
                    f.write(bytes([m]) + data[1:])
    print(len(os.listdir(outdir)), "seeds in", outdir)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "seeds")
