# CBMC: ircd/exit_reason.c

Real module `#include`d unmodified. Run `./run.sh`.

| Harness | Property | Bound | Result |
|---|---|---|---|
| `harness_contract` | memory safety on every string, and the header contract restated independently: 1 iff `"Write error: "` followed by >= 1 byte, or exactly `"Max sendQ exceeded"` / `"Buffer allocation error"`; NULL -> 0 | len <= 24 (covers all three literals and their prefixes/extensions) | VERIFIED |

No findings. (Mutation check: negating the expected value makes CBMC
report a counterexample, so the proof is not vacuous.)
