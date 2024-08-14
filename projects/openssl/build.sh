#!/bin/bash

set -ex

pushd openssl

rm -rf ./*
git checkout .

if [[ $FUZZING_ENGINE =~ semsan_Custom0 ]]; then
  CC=gcc-${GCC_V} CXX=g++-${GCC_V} LD=gcc-${GCC_V} AR=gcc-ar-${GCC_V} ./config linux-armv4 enable-md2 enable-rc5 --cross-compile-prefix=arm-linux-gnueabihf-
elif [[ $FUZZING_ENGINE =~ semsan_Custom1 ]]; then
  CC=gcc-${GCC_V} CXX=g++-${GCC_V} LD=gcc-${GCC_V} AR=gcc-ar-${GCC_V} ./config linux-x86_64 enable-md2 enable-rc5 --cross-compile-prefix=x86_64-linux-gnu-
else
  ./config enable-md2 enable-rc5
fi

make -j$(nproc)
export OPENSSL_INCLUDE_PATH=`realpath include/`
export OPENSSL_LIBCRYPTO_A_PATH=`realpath libcrypto.a`
export CXXFLAGS="$CXXFLAGS -I $OPENSSL_INCLUDE_PATH"

popd # openssl

pushd cryptofuzz

rm -rf ./*
git checkout .

git apply ../shmem.patch # Makes cryptofuzz write to semsan's shmem buffer
git apply ../gcc.patch # Allows us to build cryptofuzz with gcc

# Force cpu_features to compile for the right architecure
if [[ $FUZZING_ENGINE =~ semsan_Custom0 ]]; then
  export CC=arm-linux-gnueabihf-gcc-${GCC_V}
  export CXX=arm-linux-gnueabihf-g++-${GCC_V}
  export LD=arm-linux-gnueabihf-gcc-${GCC_V}
  export AR=arm-linux-gnueabihf-gcc-ar-${GCC_V}
  git apply ../cpu_feartues_arm32.patch
elif [[ $FUZZING_ENGINE =~ semsan_Custom1 ]]; then
  export CC=x86_64-linux-gnu-gcc-${GCC_V}
  export CXX=x86_64-linux-gnu-g++-${GCC_V}
  export LD=x86_64-linux-gnu-gcc-${GCC_V}
  export AR=x86_64-linux-gnu-gcc-ar-${GCC_V}
  git apply ../cpu_feartues_x86_64.patch
fi

export CXXFLAGS="$CXXFLAGS -Wno-psabi"

python3 ./gen_repository.py

# TODO Inject cryptofuzz options at compile time, to limit to openssl ops

if [[ $FUZZING_ENGINE =~ semsan_Custom[0-1] ]]; then
  $CXX -DNEVER_EXIT -static ../qemu_harness.cpp -c -o qemu_harness.o
  $AR rcs qemu_harness.a qemu_harness.o
  export LIB_FUZZING_ENGINE="./qemu_harness.a"
elif [[ $FUZZING_ENGINE =~ "aflpp" || $FUZZING_ENGINE =~ "semsan" ]]; then
  # Use afl++'s libfuzzer driver because cryptofuzz doesn't provide a native
  # afl harness.
  export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
fi

export LIBFUZZER_LINK=$LIB_FUZZING_ENGINE

pushd modules/openssl
make -j$(nproc)
popd # modules/openssl

if [[ $FUZZING_ENGINE =~ semsan_Custom[0-1] ]]; then
  # Link staticly for qemu targets
  export LINK_FLAGS="-static"
fi
make -j$(nproc)

cp cryptofuzz $OUT/

popd # cryptofuzz
