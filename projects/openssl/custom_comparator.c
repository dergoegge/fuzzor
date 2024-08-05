#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool semsan_custom_comparator(const uint8_t *o1, size_t o1_len,
                              const uint8_t *o2, size_t o2_len) {
  assert(o1_len == o2_len);

  if (o1[0] != o2[0]) {
    // First byte indicates the number of results that were computed by the
    // executor. When fuzzing cryptofuzz, we can only compare the actual results
    // if both executors returned the same number of results.
    return true;
  }

  return memcmp(o1 + 1, o2 + 1, o1_len - 1) == 0;
}
