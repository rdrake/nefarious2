/* Standalone driver for the non-libFuzzer builds (repro_p10, cov_p10):
 *   repro_p10 file|dir ...
 * runs every file once through LLVMFuzzerTestOneInput, in order, in one
 * process (so state carried between inputs behaves as under libFuzzer). */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void run_file(const char *path)
{
  FILE *f = fopen(path, "rb");
  long n;
  uint8_t *buf;

  if (!f) { perror(path); return; }
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = malloc(n ? n : 1);
  if (fread(buf, 1, n, f) != (size_t)n) { perror(path); fclose(f); free(buf); return; }
  fclose(f);
  if (getenv("FUZZ_VERBOSE"))
    fprintf(stderr, "running %s (%ld bytes)\n", path, n);
  LLVMFuzzerTestOneInput(buf, n);
  free(buf);
}

int main(int argc, char **argv)
{
  int i;
  LLVMFuzzerInitialize(&argc, &argv);
  for (i = 1; i < argc; i++) {
    struct stat st;
    if (stat(argv[i], &st) == 0 && S_ISDIR(st.st_mode)) {
      struct dirent **ents;
      int n = scandir(argv[i], &ents, NULL, alphasort), j;
      for (j = 0; j < n; j++) {
        char p[4096];
        if (ents[j]->d_name[0] != '.') {
          snprintf(p, sizeof(p), "%s/%s", argv[i], ents[j]->d_name);
          run_file(p);
        }
        free(ents[j]);
      }
      free(ents);
    } else
      run_file(argv[i]);
  }
  fprintf(stderr, "repro: ran %d input(s), no crash\n", argc - 1);
  return 0;
}
