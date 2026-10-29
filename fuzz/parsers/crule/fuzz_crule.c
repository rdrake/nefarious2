/*
 * fuzz_crule.c - libFuzzer harness for ircd/crule.c, the connect-rule
 * (CRULE) expression parser used for Connect blocks' "rule" (config and
 * REHASH; operator-controlled, so low exposure).  Parses, evaluates
 * against an empty server list (the lookups are autostubbed) and frees.
 */
#include "config.h"
#include "crule.h"
#include "fuzz_util.h"

/* Known bugs (FINDINGS.md), stepped around unless FUZZ_STRICT=1:
 *   F23  more than CR_MAXARGS (3) arguments to one function overflow
 *        CRuleNode.arg[]
 *   F24  an and/or node whose operand failed to parse ("&&") is freed
 *        through a NULL / uninitialized child */
static int known(const char *s)
{
  int depth = 0, commas = 0;
  if (fuzz_strict()) return 0;
  if (strpbrk(s, "&|")) return 1;     /* the tokenizer reads "& &" as && */
  for (; *s; s++) {
    if (*s == '(') { depth++; commas = 0; }
    else if (*s == ')') { if (depth) depth--; commas = 0; }
    else if (*s == ',' && ++commas >= 3) return 1;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *s = strndup((const char *)data, size);
  struct CRuleNode *r = known(s) ? NULL : crule_parse(s);
  if (r) {
    (void)crule_eval(r);
    crule_free(&r);
    CHECK(r == NULL);
  }
  free(s);
  return 0;
}
