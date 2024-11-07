#!/bin/bash

set -ex

pushd lightning

git checkout .

git apply ../all-fuzz-programs.patch

echo "unsigned-integer-overflow:ccan/" >> ../ubsan_suppressions

EXTRA_CONF_OPTS=
if [[ "$FUZZING_ENGINE" = *"_asan"* ]]; then
  EXTRA_CONF_OPTS="--enable-address-sanitizer"
fi

if [[ "$FUZZING_ENGINE" = *"_ubsan"* ]]; then
  EXTRA_CONF_OPTS="--enable-ub-sanitizer"
fi

if [[ "$FUZZING_ENGINE" = *"coverage"* ]]; then
  EXTRA_CONF_OPTS="--enable-coverage"
fi

echo "leak:ccan/" >> lsan_suppr.txt
export LSAN_OPTIONS=suppressions=lsan_suppr.txt

./configure $EXTRA_CONF_OPTS --enable-fuzzing --disable-rust --disable-valgrind CC=$CC CONFIGURATOR_CC=$CC CWARNFLAGS="-Wno-error=gnu-folding-constant"

make -j$(nproc) all-fuzz-programs

find tests/fuzz/ -type f -executable -name "fuzz-*" -exec cp '{}' $OUT/ ';'

make clean

popd

