/* libFuzzer target: ircd_features.c F: line handling.
 *
 * Input: NUL- or newline-separated fields handed to feature_set(NULL, ...)
 * the way a Features { "NAME" = "value"; }; block does, several lines per
 * input.  feature_unmark()/feature_mark() afterwards resets every feature
 * to its default, as read_configuration_file() does around a REHASH.
 */
#include "config.h"
#include "ircd.h"
#include "client.h"
#include "ircd_features.h"
#include "fuzz_common.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FIELDS 8

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc; (void)argv;
  fuzz_ircd_boot(fuzz_baseline_conf);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char *buf = malloc(size + 1);
  char *line, *rest;

  memcpy(buf, data, size);
  buf[size] = '\0';
  CurrentTime = FUZZ_NOW;
  feature_unmark();
  /* One feature_set call per line; fields within a line split on '\t'
   * (empty fields kept: "NAME" = ""). */
  rest = buf;
  while ((line = strsep(&rest, "\n")) != NULL) {
    const char *fields[MAX_FIELDS];
    int n = 0;
    char *f;
    if (!*line)
      continue;
    while (n < MAX_FIELDS && (f = strsep(&line, "\t")) != NULL)
      fields[n++] = f;
    feature_set(NULL, fields, n);
  }
  feature_mark();
  free(buf);
  fuzz_sandbox_trim();
  return 0;
}
