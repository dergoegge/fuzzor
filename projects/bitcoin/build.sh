#!/bin/bash

set -ex

pushd bitcoin

# This build script is executed repeatedly. Make sure there are no left over
# build artifacts from previous executions.
rm -rf ./*
git checkout .

# Restore the depends download
cp -r ../bitcoin_depends_sources ./depends/sources

# Build dependencies using the Bitcoin Core depends system.
sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./depends/funcs.mk  # Keep extracted source
make -C depends DEBUG=1 NO_QT=1 NO_BDB=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 NO_USDT=1 \
     AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip \
     CPPFLAGS="$CPPFLAGS" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LDFLAGS" -j$(nproc)

./autogen.sh

CONFIG_SITE="$PWD/depends/$(./depends/config.guess)/share/config.site" \
  ./configure --enable-fuzz SANITIZER_LDFLAGS="$LIB_FUZZING_ENGINE"

make -j$(nproc)

# Normally, fuzzor requires one binary per harness but Bitcoin Core gets a
# carve out since creating individual binaries ends up with a giant image
# (>100GB).
#
# Fuzzor will use the FUZZ env variable to the select the active harness
# (hopefully this can change once Bitcoin Core has CMake).
cp ./src/test/fuzz/fuzz $OUT/
chmod +x $OUT/fuzz

# Create an empty file for each harness in $OUT. Fuzzor uses this to get the
# list of available harnesses.
WRITE_ALL_FUZZ_TARGETS_AND_ABORT="/tmp/a" "./src/test/fuzz/fuzz" || true
readarray FUZZ_TARGETS < "/tmp/a"
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  touch "$OUT/$fuzz_target"
done

popd
