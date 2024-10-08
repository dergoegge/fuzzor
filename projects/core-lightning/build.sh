#!/bin/bash

set -ex

pushd lightning

echo "unsigned-integer-overflow:ccan/" >> ../ubsan_suppressions

./configure --enable-fuzzing --disable-valgrind CC=clang CONFIGURATOR_CC=clang CWARNFLAGS="-Wno-error=gnu-folding-constant $CFLAGS"

make -j$(nproc)

rm -rf ./tests/fuzz/fuzz-*.c
rm -rf ./tests/fuzz/fuzz-*.o
cp ./tests/fuzz/fuzz-* $OUT/

git checkout ./tests/fuzz/
make clean

popd

