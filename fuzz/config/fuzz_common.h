/* Shared boot code for the Nefarious config / persisted-record fuzzers. */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <stddef.h>
#include <stdint.h>

/* Fixed clock so persisted-record expiry checks are deterministic. */
#define FUZZ_NOW 1800000000

/* Boot the ircd far enough to parse a conf and run REHASH: features,
 * hashes, classes, event engine, &me as a server.  Creates and chdirs to a
 * private sandbox directory.  conf_text is the initial (valid) conf. */
void fuzz_ircd_boot(const char *conf_text);

/* Path of the conf file the lexer reads (configfile). */
const char *fuzz_conf_path(void);

/* Write buf to the conf file. */
void fuzz_write_conf(const char *buf, size_t len);

/* Truncate files the input made the ircd write into the sandbox. */
void fuzz_sandbox_trim(void);

/* Minimal conf restored after every iteration. */
extern const char fuzz_baseline_conf[];
#endif
