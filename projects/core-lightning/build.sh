#!/bin/bash

set -ex

pushd lightning

./configure --enable-fuzzing --disable-valgrind CC=clang CONFIGURATOR_CC=clang

make -j$(nproc)

rm -rf ./tests/fuzz/fuzz-*.c
rm -rf ./tests/fuzz/fuzz-*.o
cp ./tests/fuzz/fuzz-* $OUT/

git checkout ./tests/fuzz/
make clean

popd

