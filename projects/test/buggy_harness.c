#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

uint32_t buggy_fn(const uint8_t *data, size_t size) {
  if (size > 0 && data[0] == 'f') {
    if (size > 1 && data[1] == 'u') {
      if (size > 2 && data[2] == 'z') {
        if (size > 3 && data[3] == 'z') {
          if (size > 5) {
            switch (data[4]) {
            case 'c':
              assert(0); // crash
            case 'u': {
              uint32_t i = 0xffffffff << data[5]; // invalid-shift-exponent
              return i;
            }
            case 'o': {
              for (uint8_t i = 6;; ++i) { // integer-overflow
                if (i == 5) {
                  break;
                }
              }
              break;
            }
            case 'a': {
              int *ptr = 0;
              *ptr = 0xdeadbeef; // nullptr deref/write
              break;
            }
            case 's': {
              sleep(10);
              break;
            }
            }
          }
        }
      }
    }
  }
  return 0;
}

#ifndef __AFL_LOOP
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  buggy_fn(data, size);
  return 0;
}
#else
__AFL_FUZZ_INIT();
int main(int argc, char **argv) {
  __AFL_INIT();
  const uint8_t *buffer = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(100000)) {
    int buffer_len = __AFL_FUZZ_TESTCASE_LEN;
    buggy_fn(buffer, buffer_len);
  }

  return 0;
}
#endif
