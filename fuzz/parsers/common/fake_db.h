/* fake_db.h - in-memory stand-in for the ircd db_* layer (see fake_db.c) */
#ifndef FUZZ_FAKE_DB_H
#define FUZZ_FAKE_DB_H
#include <stddef.h>
struct db_env;
struct db_cf;
/* the CF the ircd opened under NAME (NULL if it never did) */
struct db_cf *fake_db_cf(const char *name);
/* put a row directly, bypassing write batches */
void fake_db_put(struct db_cf *cf, const void *k, size_t kl, const void *v, size_t vl);
/* drop every row in every CF (CFs stay open) */
void fake_db_clear(void);
/* number of CFs opened, and the i-th one's name */
int fake_db_cf_count(void);
const char *fake_db_cf_name(int i);
struct db_cf *fake_db_cf_at(int i);
#endif
