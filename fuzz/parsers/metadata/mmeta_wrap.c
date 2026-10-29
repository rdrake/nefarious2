/* mmeta_wrap.c - expose m_metadata.c's static key validator to the
 * metadata harness (separate TU: its statics clash with metadata.c's). */
#include "../../../ircd/m_metadata.c"
int fz_is_valid_key(const char *key);
int fz_is_valid_key(const char *key) { return is_valid_key(key); }
