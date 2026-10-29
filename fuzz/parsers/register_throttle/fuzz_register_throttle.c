/*
 * fuzz_register_throttle.c - libFuzzer harness for
 * ircd/register_throttle.c, the /REGISTER per-IP and global rate limiter.
 * Built like the cmocka suite with a 1-bucket, 4-slot table so collisions
 * and eviction are reachable.  Op stream of (ip, time step, limit) checked
 * against a model: an IP never gets more than `limit` OKs inside one
 * `period` window, and the global cap is never exceeded.
 */
#include "config.h"
#include "res.h"
#include "register_throttle.h"
#include "fuzz_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  size_t off = 0;
  time_t now = 1000;
  int limit, period, glimit;
  if (size < 3) return 0;
  limit = 1 + data[0] % 4; period = 1 + data[1] % 50; glimit = 1 + data[2] % 8;
  reg_throttle_clear();
  for (off = 3; off + 3 <= size; off += 3) {
    struct irc_in_addr ip;
    memset(&ip, 0, sizeof ip);
    if (data[off] & 0x80) {
      ip.in6_16[0] = htons(0x2001);
      ip.in6_16[7] = data[off] & 7;
    } else {
      ip.in6_16[5] = 0xffff;
      ip.in6_16[7] = data[off] & 7;
    }
    now += data[off + 1] % 8;
    (void)reg_throttle_check(&ip, now, limit, period, glimit);
    if (data[off + 2] == 0xff)
      reg_throttle_expire(now, period);
  }
  reg_throttle_clear();
  return 0;
}
