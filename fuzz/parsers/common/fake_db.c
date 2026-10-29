/*
 * fake_db.c - an in-memory implementation of the ircd's storage API
 * (include/db_env.h, db_txn.h, db_cursor.h), standing in for
 * ircd/db_rocksdb.c in the fuzz builds so the real record encoders and
 * decoders in history.c, ml_content.c, metadata.c, webpush_store.c and
 * bouncer_session.c can be driven with arbitrary persisted rows.
 *
 * Semantics follow db_rocksdb.c: bytewise key order, seek = first key >=,
 * DB_OK / DB_NOTFOUND returns, write batches applied in order at commit.
 * Like RocksDB, values handed out (db_get, db_iter_key/value) are exact-
 * length heap copies with NO trailing NUL, so a decoder that treats a
 * stored value as a C string is caught by ASan.  Snapshots are accepted
 * and ignored (reads see live rows).
 */
#include "db_types.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_cursor.h"
#include "fake_db.h"
#include <stdlib.h>
#include <string.h>

struct row { char *k; size_t kl; char *v; size_t vl; };
struct db_cf { char name[64]; struct row *rows; size_t n, cap; };
struct db_env { int dummy; };
struct db_snapshot { int dummy; };
struct db_iter { struct db_cf *cf; long pos; char *kcopy, *vcopy; };
enum { OP_PUT, OP_DEL };
struct op { int kind; struct db_cf *cf; char *k; size_t kl; char *v; size_t vl; };
struct db_writebatch { struct op *ops; size_t n, cap; };

#define MAX_CF 64
static struct db_cf *cfs[MAX_CF];
static int ncf;
static struct db_env the_env;

static char *dup_bytes(const void *p, size_t n)
{
  char *d = malloc(n ? n : 1);
  if (n) memcpy(d, p, n);
  return d;
}

static int bcmp_keys(const char *a, size_t al, const char *b, size_t bl)
{
  size_t m = al < bl ? al : bl;
  int c = m ? memcmp(a, b, m) : 0;
  if (c) return c;
  return al < bl ? -1 : al > bl ? 1 : 0;
}

static size_t lower_bound(const struct db_cf *cf, const char *k, size_t kl)
{
  size_t lo = 0, hi = cf->n;
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (bcmp_keys(cf->rows[mid].k, cf->rows[mid].kl, k, kl) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

void fake_db_put(struct db_cf *cf, const void *k, size_t kl, const void *v, size_t vl)
{
  size_t i;
  if (!cf) return;
  i = lower_bound(cf, k, kl);
  if (i < cf->n && !bcmp_keys(cf->rows[i].k, cf->rows[i].kl, k, kl)) {
    free(cf->rows[i].v);
    cf->rows[i].v = dup_bytes(v, vl);
    cf->rows[i].vl = vl;
    return;
  }
  if (cf->n == cf->cap) {
    cf->cap = cf->cap ? cf->cap * 2 : 16;
    cf->rows = realloc(cf->rows, cf->cap * sizeof(*cf->rows));
  }
  memmove(cf->rows + i + 1, cf->rows + i, (cf->n - i) * sizeof(*cf->rows));
  cf->rows[i].k = dup_bytes(k, kl);
  cf->rows[i].kl = kl;
  cf->rows[i].v = dup_bytes(v, vl);
  cf->rows[i].vl = vl;
  cf->n++;
}

static void cf_del(struct db_cf *cf, const void *k, size_t kl)
{
  size_t i = lower_bound(cf, k, kl);
  if (i < cf->n && !bcmp_keys(cf->rows[i].k, cf->rows[i].kl, k, kl)) {
    free(cf->rows[i].k);
    free(cf->rows[i].v);
    memmove(cf->rows + i, cf->rows + i + 1, (cf->n - i - 1) * sizeof(*cf->rows));
    cf->n--;
  }
}

void fake_db_clear(void)
{
  int c;
  size_t i;
  for (c = 0; c < ncf; c++) {
    for (i = 0; i < cfs[c]->n; i++) { free(cfs[c]->rows[i].k); free(cfs[c]->rows[i].v); }
    cfs[c]->n = 0;
  }
}

struct db_cf *fake_db_cf(const char *name)
{
  int c;
  for (c = 0; c < ncf; c++)
    if (!strcmp(cfs[c]->name, name)) return cfs[c];
  return NULL;
}
int fake_db_cf_count(void) { return ncf; }
const char *fake_db_cf_name(int i) { return cfs[i]->name; }
struct db_cf *fake_db_cf_at(int i) { return cfs[i]; }

/* ---- env / cf ---- */
int db_env_open(const char *path, const struct db_env_opts *opts,
                unsigned int max_cfs, struct db_env **out)
{ (void)path; (void)opts; (void)max_cfs; *out = &the_env; return DB_OK; }
void db_env_close(struct db_env *env) { (void)env; }
int db_cf_open(struct db_env *env, const char *name, const struct db_cf_opts *opts,
               struct db_cf **out)
{
  struct db_cf *cf;
  (void)env; (void)opts;
  if (!name) name = "default";
  if ((cf = fake_db_cf(name))) { *out = cf; return DB_OK; }
  if (ncf == MAX_CF) return DB_ERR_OTHER;
  cf = calloc(1, sizeof(*cf));
  strncpy(cf->name, name, sizeof(cf->name) - 1);
  cfs[ncf++] = cf;
  *out = cf;
  return DB_OK;
}
void db_cf_close(struct db_env *env, struct db_cf *cf) { (void)env; (void)cf; }
int db_env_sync(struct db_env *env) { (void)env; return DB_OK; }
int db_env_compact(struct db_env *env, struct db_cf *cf) { (void)env; (void)cf; return DB_OK; }
int db_env_stats(struct db_env *env, struct db_env_stats *out)
{ (void)env; memset(out, 0, sizeof(*out)); return DB_OK; }
int db_cf_stats(struct db_env *env, struct db_cf *cf, struct db_cf_stats *out)
{ (void)env; memset(out, 0, sizeof(*out)); if (cf) out->approx_keys = cf->n; return DB_OK; }
int db_env_reap_dead_readers(struct db_env *env) { (void)env; return 0; }
int db_env_warmup(struct db_env *env) { (void)env; return DB_OK; }
const char *db_strerror(int rc) { return rc == DB_OK ? "ok" : rc == DB_NOTFOUND ? "not found" : "error"; }
const char *db_env_last_error(struct db_env *env) { (void)env; return ""; }

void db_val_free(struct db_val *v) { if (v && v->base) { free(v->base); v->base = NULL; v->len = 0; } }

/* ---- batches ---- */
struct db_writebatch *db_writebatch_new(struct db_env *env) { (void)env; return calloc(1, sizeof(struct db_writebatch)); }
static struct op *wb_push(struct db_writebatch *wb)
{
  if (wb->n == wb->cap) {
    wb->cap = wb->cap ? wb->cap * 2 : 8;
    wb->ops = realloc(wb->ops, wb->cap * sizeof(*wb->ops));
  }
  return &wb->ops[wb->n++];
}
int db_writebatch_put(struct db_writebatch *wb, struct db_cf *cf,
                      const void *key, size_t klen, const void *val, size_t vlen)
{
  struct op *o;
  if (!wb || !cf) return DB_ERR_OTHER;
  o = wb_push(wb);
  o->kind = OP_PUT; o->cf = cf;
  o->k = dup_bytes(key, klen); o->kl = klen;
  o->v = dup_bytes(val, vlen); o->vl = vlen;
  return DB_OK;
}
int db_writebatch_put_append(struct db_writebatch *wb, struct db_cf *cf,
                             const void *key, size_t klen, const void *val, size_t vlen)
{ return db_writebatch_put(wb, cf, key, klen, val, vlen); }
int db_writebatch_del(struct db_writebatch *wb, struct db_cf *cf, const void *key, size_t klen)
{
  struct op *o;
  if (!wb || !cf) return DB_ERR_OTHER;
  o = wb_push(wb);
  o->kind = OP_DEL; o->cf = cf;
  o->k = dup_bytes(key, klen); o->kl = klen;
  o->v = NULL; o->vl = 0;
  return DB_OK;
}
static void wb_clear(struct db_writebatch *wb)
{
  size_t i;
  for (i = 0; i < wb->n; i++) { free(wb->ops[i].k); free(wb->ops[i].v); }
  wb->n = 0;
}
int db_writebatch_commit(struct db_writebatch *wb, int sync_durably)
{
  size_t i;
  (void)sync_durably;
  if (!wb) return DB_ERR_OTHER;
  for (i = 0; i < wb->n; i++) {
    struct op *o = &wb->ops[i];
    if (o->kind == OP_PUT) fake_db_put(o->cf, o->k, o->kl, o->v, o->vl);
    else cf_del(o->cf, o->k, o->kl);
  }
  wb_clear(wb);
  return DB_OK;
}
unsigned int db_writebatch_count(const struct db_writebatch *wb) { return wb ? (unsigned)wb->n : 0; }
void db_writebatch_destroy(struct db_writebatch *wb)
{
  if (!wb) return;
  wb_clear(wb);
  free(wb->ops);
  free(wb);
}

/* ---- reads ---- */
struct db_snapshot *db_snapshot_new(struct db_env *env) { (void)env; return calloc(1, sizeof(struct db_snapshot)); }
void db_snapshot_destroy(struct db_snapshot *s) { free(s); }

int db_get(struct db_env *env, struct db_cf *cf, const void *key, size_t klen,
           struct db_snapshot *snap, struct db_val *out)
{
  size_t i;
  (void)env; (void)snap;
  if (!cf || !out) return DB_ERR_OTHER;
  out->base = NULL; out->len = 0;
  i = lower_bound(cf, key, klen);
  if (i < cf->n && !bcmp_keys(cf->rows[i].k, cf->rows[i].kl, key, klen)) {
    out->base = dup_bytes(cf->rows[i].v, cf->rows[i].vl);
    out->len = cf->rows[i].vl;
    return DB_OK;
  }
  return DB_NOTFOUND;
}
int db_exists(struct db_env *env, struct db_cf *cf, const void *key, size_t klen,
              struct db_snapshot *snap)
{
  struct db_val v = { NULL, 0 };
  int rc = db_get(env, cf, key, klen, snap, &v);
  db_val_free(&v);
  return rc;
}

static void it_refresh(struct db_iter *it)
{
  free(it->kcopy); free(it->vcopy);
  it->kcopy = it->vcopy = NULL;
  if (it->pos >= 0 && (size_t)it->pos < it->cf->n) {
    it->kcopy = dup_bytes(it->cf->rows[it->pos].k, it->cf->rows[it->pos].kl);
    it->vcopy = dup_bytes(it->cf->rows[it->pos].v, it->cf->rows[it->pos].vl);
  }
}
static int it_obs(struct db_iter *it)
{
  it_refresh(it);
  return db_iter_valid(it) ? DB_OK : DB_NOTFOUND;
}
struct db_iter *db_iter_open(struct db_env *env, struct db_cf *cf, struct db_snapshot *snap)
{
  struct db_iter *it;
  (void)env; (void)snap;
  if (!cf) return NULL;
  it = calloc(1, sizeof(*it));
  it->cf = cf;
  it->pos = -1;
  return it;
}
void db_iter_close(struct db_iter *it) { if (it) { free(it->kcopy); free(it->vcopy); free(it); } }
int db_iter_seek(struct db_iter *it, const void *key, size_t klen)
{ if (!it) return DB_ERR_OTHER; it->pos = (long)lower_bound(it->cf, key, klen); return it_obs(it); }
int db_iter_seek_first(struct db_iter *it) { if (!it) return DB_ERR_OTHER; it->pos = 0; return it_obs(it); }
int db_iter_seek_last(struct db_iter *it) { if (!it) return DB_ERR_OTHER; it->pos = (long)it->cf->n - 1; return it_obs(it); }
int db_iter_next(struct db_iter *it)
{ if (!it) return DB_ERR_OTHER; if (db_iter_valid(it)) it->pos++; return it_obs(it); }
int db_iter_prev(struct db_iter *it)
{ if (!it) return DB_ERR_OTHER; if (db_iter_valid(it)) it->pos--; return it_obs(it); }
int db_iter_valid(const struct db_iter *it)
{ return it && it->pos >= 0 && (size_t)it->pos < it->cf->n; }
const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  if (!db_iter_valid(it)) { if (klen) *klen = 0; return NULL; }
  if (klen) *klen = it->cf->rows[it->pos].kl;
  return it->kcopy;
}
const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  if (!db_iter_valid(it)) { if (vlen) *vlen = 0; return NULL; }
  if (vlen) *vlen = it->cf->rows[it->pos].vl;
  return it->vcopy;
}
