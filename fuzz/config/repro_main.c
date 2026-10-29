/* Standalone driver for the plain-ASan (non-libFuzzer) builds: runs each
 * file given on the command line through LLVMFuzzerTestOneInput once. */
#define _DEFAULT_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
  int i;
  /* The harness chdirs into its sandbox: resolve the inputs first. */
  for (i = 1; i < argc; i++) {
    char *abs = realpath(argv[i], NULL);
    if (abs)
      argv[i] = abs;
  }
  LLVMFuzzerInitialize(&argc, &argv);
  for (i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    long n;
    uint8_t *buf;
    if (!f) { perror(argv[i]); return 1; }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(n ? n : 1);
    if (fread(buf, 1, n, f) != (size_t)n) { perror("read"); return 1; }
    fclose(f);
    fprintf(stderr, "Running: %s (%ld bytes)\n", argv[i], n);
    LLVMFuzzerTestOneInput(buf, n);
    free(buf);
  }
  fprintf(stderr, "Done: %d inputs, no crash\n", argc - 1);
  return 0;
}
