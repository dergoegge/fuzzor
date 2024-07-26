#!/bin/bash

set -ex

if [[ $FUZZING_ENGINE =~ semsan_Custom0 ]]; then
  export CC=arm-linux-gnueabihf-gcc-14
  export CXX=arm-linux-gnueabihf-g++-14
  export LD=arm-linux-gnueabihf-gcc-14
  export AR=arm-linux-gnueabihf-ar
elif [[ $FUZZING_ENGINE =~ semsan_Custom1 ]]; then
  export CC=x86_64-linux-gnu-gcc-14
  export CXX=x86_64-linux-gnu-g++-14
  export LD=x86_64-linux-gnu-gcc-14
  export AR=x86_64-linux-gnu-ar
fi

pushd openssl

rm -rf ./*
git checkout .

./config enable-md2 enable-rc5
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
  git apply ../cpu_feartues_arm32.patch
elif [[ $FUZZING_ENGINE =~ semsan_Custom1 ]]; then
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
