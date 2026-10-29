/*
 * fuzz/client/replay_main.c -- standalone driver for the client harness,
 * used by the "plain" (ASan only, no libFuzzer, no freelist patch) build to
 * confirm that a crash reproduces outside the fuzzing configuration.
 *
 *   ./fuzz_client_plain crash-file [crash-file...]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
  int i;

  LLVMFuzzerInitialize(&argc, &argv);
  for (i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    long n;
    uint8_t *buf;

    if (!f) {
      perror(argv[i]);
      return 1;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n ? (size_t)n : 1);
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) {
      perror(argv[i]);
      return 1;
    }
    fclose(f);
    fprintf(stderr, "replay: %s (%ld bytes)\n", argv[i], n);
    LLVMFuzzerTestOneInput(buf, (size_t)n);
    free(buf);
  }
  fprintf(stderr, "replay: done, no crash\n");
  return 0;
}
