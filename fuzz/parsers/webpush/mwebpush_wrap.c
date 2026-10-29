/* mwebpush_wrap.c - expose m_webpush.c's static WEBPUSH REGISTER input
 * checks to the webpush harness (separate TU from webpush.c). */
#include "../../../ircd/m_webpush.c"
int fz_is_valid_endpoint(const char *e);
int fz_is_valid_endpoint(const char *e) { return is_valid_endpoint(e); }
int fz_parse_keys(const char *k, char *p, size_t ps, char *a, size_t as);
int fz_parse_keys(const char *k, char *p, size_t ps, char *a, size_t as)
{ return parse_keys(k, p, ps, a, as); }
