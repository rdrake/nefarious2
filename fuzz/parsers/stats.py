#!/usr/bin/env python3
"""stats.py [WORKDIR] - per-target totals from the campaign logs.

Reads $FUZZ_WORK/logs/<target>.<n>.log (fork-mode libFuzzer output from
run.sh) and prints, per target: total executions (sum of each run's final
count), fuzzing seconds, best edge coverage / features seen, corpus size,
and crash/timeout/oom counts libFuzzer reported.  Markdown table.
"""
import glob
import os
import re
import sys

work = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('FUZZ_WORK', '/tmp/nefarious-fuzz')
rows = {}
pat = re.compile(r'^#(\d+): cov: (\d+) ft: (\d+) corp: (\d+) exec/s: (\d+) '
                 r'oom/timeout/crash: (\d+)/(\d+)/(\d+) time: (\d+)s')
for log in sorted(glob.glob(os.path.join(work, 'logs', '*.log'))):
    t = os.path.basename(log).rsplit('.', 2)[0]
    last = None
    with open(log, errors='replace') as f:
        for line in f:
            m = pat.match(line)
            if m:
                last = m
    r = rows.setdefault(t, dict(execs=0, secs=0, cov=0, ft=0, corp=0, oom=0, to=0, crash=0, runs=0))
    r['runs'] += 1
    if last:
        n, cov, ft, corp, _, oom, to, cr, secs = map(int, last.groups())
        r['execs'] += n
        r['secs'] += secs
        r['cov'] = max(r['cov'], cov)
        r['ft'] = max(r['ft'], ft)
        r['corp'] = max(r['corp'], corp)
        r['oom'] += oom
        r['to'] += to
        r['crash'] += cr
print('| target | runs | fuzz time | execs | cov (edges) | ft | corpus | crash/timeout/oom |')
print('|---|---|---|---|---|---|---|---|')
tot_e = tot_s = 0
for t in sorted(rows, key=lambda k: -rows[k]['secs']):
    r = rows[t]
    tot_e += r['execs']
    tot_s += r['secs']
    print('| %s | %d | %dm | %s | %d | %d | %d | %d/%d/%d |' % (
        t, r['runs'], r['secs'] // 60, f"{r['execs']:,}", r['cov'], r['ft'], r['corp'],
        r['crash'], r['to'], r['oom']))
print('| **total** | | %dh%02dm core-time | %s | | | | |' % (tot_s // 3600, tot_s % 3600 // 60, f'{tot_e:,}'))
