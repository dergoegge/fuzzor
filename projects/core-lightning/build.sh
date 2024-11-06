#!/bin/bash

set -ex

pushd lightning

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

./configure $EXTRA_CONF_OPTS --enable-fuzzing --disable-valgrind CC=$CC CONFIGURATOR_CC=$CC CWARNFLAGS="-Wno-error=gnu-folding-constant"

# Hack to only build the fuzz harness bins
echo "#!/bin/bash" > tests/fuzz/check-fuzz.sh
chmod +x tests/fuzz/check-fuzz.sh
make -j$(nproc) check-fuzz

rm -rf ./tests/fuzz/fuzz-*.c
rm -rf ./tests/fuzz/fuzz-*.o
cp ./tests/fuzz/fuzz-* $OUT/

git checkout ./tests/fuzz/
make clean

popd

