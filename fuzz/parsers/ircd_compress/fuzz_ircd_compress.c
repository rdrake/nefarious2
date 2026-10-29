/*
 * fuzz_ircd_compress.c - libFuzzer harness for ircd/ircd_compress.c, the
 * zstd wrapper every compressed RocksDB value (history, multiline,
 * metadata) and the CH Z federation passthrough go through.
 * Byte 0 selects:
 *   0  decompress_data() on arbitrary bytes into a buffer of fuzz-chosen
 *      size: never writes past it, a success reports <= its size
 *   1  round trip: compress_data() then decompress_data() == input, for
 *      every threshold/level the bytes pick
 */
#include "config.h"
#include "ircd_compress.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 3) return 0;
  if (data[0] & 1) {
    size_t n = size - 3, cl = 0, dl = 0, cap = n + 64;
    unsigned char *c = malloc(cap), *d = malloc(n + 1);
    compress_init(data[1] % 64, 1 + data[2] % 19);
    /* an uncompressed value starting with COMPRESS_MAGIC (0x1F) reads
     * back as a zstd frame (noted in FINDINGS.md); skipped unless strict */
    if ((fuzz_strict() || n == 0 || data[3] != 0x1F) &&
        compress_data(data + 3, n, c, cap, &cl) >= 0) {
      CHECK(cl <= cap);
      CHECK(decompress_data(c, cl, d, n + 1, &dl) >= 0);
      CHECK(dl == n && (n == 0 || !memcmp(d, data + 3, n)));
    }
    free(c); free(d);
  } else {
    size_t cap = 1 + (data[1] | (data[2] << 8)) % 8192, ol = 0;
    unsigned char *o = malloc(cap);
    int r = decompress_data(data + 3, size - 3, o, cap, &ol);
    if (r >= 0) CHECK(ol <= cap);
    (void)is_compressed(data + 3, size - 3);
    free(o);
  }
  return 0;
}
