#!/usr/bin/env python3
"""Generate seed corpora and the conf dictionary for the config fuzzers.

  python3 -I fuzz/config/gen_seeds.py OUTDIR

Writes OUTDIR/conf/ (conf + REHASH-pair seeds), OUTDIR/feature/ and
fuzz/config/conf.dict.  Bouncer-record seeds come from gen_bouncer_seeds
(a C helper built by build.sh, since the layouts are C structs).
"""
import hashlib, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
SEP = b'\n#@REHASH@\n'
out = sys.argv[1]

def rd(p):
    with open(os.path.join(REPO, p), 'rb') as f:
        return f.read()

def put(d, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, hashlib.sha1(data).hexdigest()), 'wb') as f:
        f.write(data)

def blocks(text):
    """Split a conf into top-level statements (blocks and `include`s)."""
    res, cur, depth, i, n = [], bytearray(), 0, 0, len(text)
    while i < n:
        c = text[i:i+1]
        if c == b'#':                       # comment to EOL
            j = text.find(b'\n', i)
            j = n if j < 0 else j
            i = j
            continue
        if c == b'"':                       # quoted string
            j = text.find(b'"', i + 1)
            j = n - 1 if j < 0 else j
            cur += text[i:j+1]
            i = j + 1
            continue
        cur += c
        if c == b'{':
            depth += 1
        elif c == b'}':
            depth -= 1
        elif c == b';' and depth == 0:
            s = bytes(cur).strip()
            if s and s != b';':
                res.append(s + b'\n')
            cur = bytearray()
        i += 1
    return res

HEADER = (b'General { name = "fuzz.example.net"; description = "fuzz"; '
          b'numeric = 1; };\n')

docker = rd('tools/docker/base.conf-dist')
for k, v in {b'IRCD_GENERAL_NAME': b'fuzz.example.net',
             b'IRCD_GENERAL_DESCRIPTION': b'fuzz server',
             b'IRCD_GENERAL_NUMERIC': b'1',
             b'IRCD_ADMIN_LOCATION': b'Earth',
             b'IRCD_ADMIN_CONTACT': b'admin@example.net'}.items():
    docker = docker.replace(b'%' + k + b'%', v)
docker = re.sub(rb'%[A-Z0-9_]+%', b'x', docker)

sources = [rd('doc/example.conf'), docker]
for p in sorted(os.listdir(os.path.join(REPO, 'ircd/test'))):
    if p.endswith('.conf'):
        sources.append(rd('ircd/test/' + p))
for p in ('ircd.conf', 'ircd-docker.conf', 'linesync.conf', 'gitsync.conf'):
    try:
        sources.append(rd('tools/docker/' + p))
    except OSError:
        pass

conf_dir = os.path.join(out, 'conf')
allblocks = []
for s in sources:
    put(conf_dir, s)
    bl = blocks(s)
    allblocks += bl
    for b in bl:
        put(conf_dir, HEADER + b)
# group by block keyword; REHASH pairs: same kind of block, before/after
bykind = {}
for b in allblocks:
    m = re.match(rb'\s*([A-Za-z_]+)', b)
    if m:
        bykind.setdefault(m.group(1).lower(), []).append(b)
for kind, bl in bykind.items():
    for i, b in enumerate(bl):
        nxt = bl[(i + 1) % len(bl)]
        put(conf_dir, HEADER + b + SEP + HEADER + nxt)
        put(conf_dir, HEADER + b + SEP + HEADER)     # block removed on rehash
        put(conf_dir, HEADER + SEP + HEADER + b)     # block added on rehash
# whole example conf, then rehash to the docker one and back
put(conf_dir, sources[0] + SEP + docker + SEP + sources[0])

# Extra hand-written seeds for fork blocks that the shipped confs may miss.
for f in sorted(os.listdir(os.path.join(HERE, 'seeds-extra'))):
    with open(os.path.join(HERE, 'seeds-extra', f), 'rb') as fh:
        data = fh.read()
    put(conf_dir, data)
    put(conf_dir, data + SEP + HEADER)
    put(conf_dir, data + SEP + data)

# Feature seeds: every Features-block entry from the confs, as tab-separated
# fields, one per line.
feat_dir = os.path.join(out, 'feature')
feats = []
for s in sources:
    for m in re.finditer(rb'features\s*\{(.*?)\};', s, re.S | re.I):
        body = re.sub(rb'#[^\n]*', b'', m.group(1))
        for ent in re.finditer(rb'"([^"]*)"\s*=\s*((?:"[^"]*"\s*)+);', body):
            vals = re.findall(rb'"([^"]*)"', ent.group(2))
            feats.append(b'\t'.join([ent.group(1)] + vals))
feats = sorted(set(feats))
for i in range(0, len(feats), 8):
    put(feat_dir, b'\n'.join(feats[i:i+8]) + b'\n')
# all feature names from ircd_features.c, with odd values
src = rd('ircd/ircd_features.c')
names = sorted(set(re.findall(rb'F_[A-Z]\(\s*([A-Za-z0-9_]+)\s*,', src)))
odd = [b'', b'0', b'-1', b'4294967296', b'TRUE', b'FALSE', b'x' * 600,
       b'%s%n', b'*', b'a,b,,c']
for i, n in enumerate(names):
    put(feat_dir, n + b'\t' + odd[i % len(odd)] + b'\n' + n + b'\n')

# Dictionary: lexer keywords plus syntax.
lex = rd('ircd/ircd_lexer.l').decode()
words = set(re.findall(r'TOKEN\(([A-Z_0-9]+)\)', lex))
words |= set(re.findall(r'\{\s*"([^"]+)"\s*,\s*[A-Z_]+\s*\}', lex))
with open(os.path.join(HERE, 'conf.dict'), 'w') as f:
    f.write('# ircd.conf keywords (ircd_lexer.l tokens) and syntax\n')
    for w in sorted(words):
        f.write('kw_%s="%s"\n' % (re.sub(r'\W', '_', w), w))
        f.write('kwl_%s="%s"\n' % (re.sub(r'\W', '_', w), w.lower()))
    for i, s in enumerate(['{', '};', ' = ', ';', '"', '\\"', ' yes', ' no',
                           ' minutes', ' seconds', ' hours', ' days',
                           ' weeks', ' kbytes', ' mbytes', ' gbytes',
                           '\\x0a#@REHASH@\\x0a', 'include "', '*', '!',
                           '0.0.0.0', '::', '/32', '/128', '@']):
        f.write('syn%d="%s"\n' % (i, s))
with open(os.path.join(HERE, 'feature.dict'), 'w') as f:
    f.write('# feature names (ircd_features.c)\n')
    for n in names:
        f.write('f_%s="%s"\n' % (n.decode(), n.decode()))
    f.write('tab="\\x09"\nnl="\\x0a"\nt="TRUE"\nfl="FALSE"\n')
print('conf seeds:', len(os.listdir(conf_dir)),
      'feature seeds:', len(os.listdir(feat_dir)), 'dict words:', len(words))
