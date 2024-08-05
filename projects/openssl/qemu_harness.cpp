#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                   size_t max_size) {
  return 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  LLVMFuzzerInitialize(&argc, &argv);
  uint8_t buf[1024 * 1024];
  memset(buf, 0, sizeof(buf));

  if (std::getenv("QEMU_HARNESS_READ_FILE")) {
    assert(argc > 1);
    std::ifstream ifs(argv[1], std::ios::binary);
    ifs.seekg(0, std::ios::end);
    size_t length_of_the_file = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    ifs.read((char *)buf, length_of_the_file);
  }

  LLVMFuzzerTestOneInput(buf, sizeof(buf));
#ifdef NEVER_EXIT
  assert(false);
#endif
}
