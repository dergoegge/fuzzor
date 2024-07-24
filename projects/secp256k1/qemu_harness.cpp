#include <cstdint>
#include <cstddef>

extern "C" size_t LLVMFuzzerMutate(uint8_t* data, size_t size, size_t max_size) { return 0; }

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    uint8_t buf[1024 * 1024];
    LLVMFuzzerTestOneInput(buf, sizeof(buf));
}
