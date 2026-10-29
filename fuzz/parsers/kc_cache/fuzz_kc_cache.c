/*
 * fuzz_kc_cache.c - libFuzzer harness for ircd/kc/kc_cache.c, the
 * username -> user-id and user-id -> representation caches that sit in
 * front of Keycloak (keys are client-supplied usernames).  The input is
 * an op stream checked against a model: after put(k,v) a get(k) returns v
 * or (evicted) NULL, never another value; after remove(k) get(k) is NULL.
 * The model follows the cache's contract: keys compare ASCII-case-
 * insensitively (strcasecmp) and are at most 63 bytes (the entry size).
 * Representations are JSON objects from the input.
 */
#include <kc/kc.h>
#include <kc/kc_cache.h>
#include <jansson.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "CHECK failed: %s (%s:%d)\n", #c, __FILE__, __LINE__); abort(); } } while (0)

#define NK 8
static char *mk[NK], *mv[NK];

static char *take(const uint8_t **p, const uint8_t *end)
{
  size_t n;
  char *s;
  if (*p >= end) return strdup("");
  n = **p % 48; (*p)++;   /* < 64: entries hold 63 bytes */
  if ((size_t)(end - *p) < n) n = end - *p;
  s = strndup((const char *)*p, n);
  *p += n;
  return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const uint8_t *p = data, *end = data + size;
  int i;
  kc_cache_init();
  memset(mk, 0, sizeof mk); memset(mv, 0, sizeof mv);
  while (p < end) {
    int op = *p % 6, slot = (*p >> 3) % NK;
    p++;
    switch (op) {
    case 0: {                     /* userid put */
      char *k = take(&p, end), *v = take(&p, end);
      if (!*k || !*v) { free(k); free(v); break; }
      for (i = 0; i < NK; i++)
        if (mk[i] && !strcasecmp(mk[i], k)) { free(mk[i]); free(mv[i]); mk[i] = mv[i] = NULL; }
      free(mk[slot]); free(mv[slot]);
      mk[slot] = k; mv[slot] = v;
      kc_userid_cache_put(k, v);
      break;
    }
    case 1: {                     /* userid get */
      if (mk[slot]) {
        const char *g = kc_userid_cache_get(mk[slot]);
        if (g) CHECK(!strcmp(g, mv[slot]));
      } else {
        char *k = take(&p, end);
        (void)kc_userid_cache_get(k);
        free(k);
      }
      break;
    }
    case 2:                       /* userid remove */
      if (mk[slot]) {
        kc_userid_cache_remove(mk[slot]);
        CHECK(kc_userid_cache_get(mk[slot]) == NULL);
        free(mk[slot]); free(mv[slot]); mk[slot] = mv[slot] = NULL;
      }
      break;
    case 3: {                     /* repr put */
      char *id = take(&p, end), *js = take(&p, end);
      json_t *j = json_loads(js, 0, NULL);
      if (!j) j = json_object();
      kc_user_repr_cache_put(id, j);
      json_decref(j);
      free(id); free(js);
      break;
    }
    case 4: {                     /* repr get */
      char *id = take(&p, end);
      json_t *j = kc_user_repr_cache_get(id);   /* borrowed */
      if (j) CHECK(json_is_object(j) && !json_object_get(j, "credentials"));
      free(id);
      break;
    }
    case 5: {
      char *id = take(&p, end);
      kc_user_repr_cache_remove(id);
      free(id);
      break;
    }
    }
  }
  for (i = 0; i < NK; i++) { free(mk[i]); free(mv[i]); }
  kc_cache_cleanup();
  return 0;
}
