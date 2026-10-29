/*
 * standalone_main.c - replay driver for the fuzz harnesses without
 * libFuzzer.  Links a harness's LLVMFuzzerTestOneInput into a plain
 * (ASan/UBSan, no -fsanitize=fuzzer) binary so a crash can be confirmed
 * outside the fuzzing engine.  Arguments are files or directories.
 */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>

/* weak: the coverage build (common/../coverage.sh) has no sanitizer runtime */
__attribute__((weak)) void __sanitizer_print_stack_trace(void);

/* A harness oracle calls abort(); say so with a stack, like libFuzzer. */
static void on_abort(int sig)
{
  (void)sig;
  fprintf(stderr, "==ABORT== harness oracle or assert failed\n");
  if (__sanitizer_print_stack_trace)
    __sanitizer_print_stack_trace();
  _exit(134);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

static int run_file(const char *path)
{
  FILE *f = fopen(path, "rb");
  uint8_t *buf;
  long n;

  if (!f) { perror(path); return 1; }
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = malloc(n > 0 ? n : 1);
  if (n > 0 && fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); return 1; }
  fclose(f);
  fprintf(stderr, "Running: %s (%ld bytes)\n", path, n);
  LLVMFuzzerTestOneInput(buf, (size_t)n);
  free(buf);
  return 0;
}

static void run_path(const char *path)
{
  struct stat st;
  if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
    DIR *d = opendir(path);
    struct dirent *e;
    char sub[4096];
    if (!d) return;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      snprintf(sub, sizeof sub, "%s/%s", path, e->d_name);
      run_path(sub);
    }
    closedir(d);
  } else {
    run_file(path);
  }
}

int main(int argc, char **argv)
{
  int i;
  signal(SIGABRT, on_abort);
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  for (i = 1; i < argc; i++)
    run_path(argv[i]);
  fprintf(stderr, "Done: %d input path(s)\n", argc - 1);
  return 0;
}
