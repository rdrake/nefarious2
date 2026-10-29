# ircd/dbuf.c

## CBMC: did not scale (recorded honestly)

`dbuf_harness.c` (real dbuf.c `#include`d, stubs for feature_int/bool,
flush_connections, DoMalloc, and the EOL bits of the char-attribute
table) states: put/put/getmsg over arbitrary bytes, `DBufLength`
bookkeeping, and `dbuf_getmsg` returns exactly the first non-empty line
(leading CR/LF skipped, NUL-terminated, shorter than the caller's
length) or 0. Every configuration tried ran out of memory in the SAT
back-end or crashed CBMC (`--arrays-uf-always`: invariant violation):
each `struct DBufBuffer` carries `char data[2048]`, and even a single
fresh block with 2-byte puts exceeded 9.5 GB (CaDiCaL and MiniSat;
byte-loop memcpy model; with and without the 2 KB filler). No CBMC
verdict is claimed for dbuf.

## Bounded-exhaustive concrete check (what is actually established)

`exhaustive_boundary.c` drives the **real** dbuf.c under ASan+UBSan.
dbuf.c distinguishes only EOL (`\r`, `\n`) from other bytes, so the
alphabet {a, b, \r, \n} covers every control path while still checking
that the right bytes are copied. For every filler offset putting the
data 0..4 bytes before the end of the first block, every string of
length 0..7 (4^7 per length), every split into two `dbuf_put` calls,
and every caller length L = 1..9, it checks `DBufLength`, then drains
with repeated `dbuf_getmsg`, comparing each line, its NUL terminator,
the 0-return when no complete line fits in L-1 bytes, and the remaining
length after the EOL flush against a reference model.

Result: **23,729,850 checks, 0 mismatches, no sanitizer report.**

No findings in dbuf.c. (Its callers' line-length handling was not in
scope.)
