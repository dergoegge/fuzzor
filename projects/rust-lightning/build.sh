#!/bin/bash

set -xe

pushd $REPO/fuzz

ls src/bin/*.rs | sed "s/src\/bin\///g" | sed "s/\.rs//g" > /tmp/a

# Takes a ton of RAM and time
sed -i "s/lto = true/lto = false/g" Cargo.toml

readarray FUZZ_TARGETS < "/tmp/a"
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  if [ "$FUZZING_ENGINE" = "coverage" ]; then
    RUSTFLAGS="--cfg=secp256k1_fuzz --cfg=hashes_fuzz" cargo +nightly fuzz coverage $fuzz_target --sanitizer none
    cp target/$(uname -m)-unknown-linux-gnu/coverage/$(uname -m)-unknown-linux-gnu/release/$fuzz_target $OUT/
  else
    RUSTFLAGS="--cfg=secp256k1_fuzz --cfg=hashes_fuzz" cargo +nightly fuzz build --features "libfuzzer_fuzz" $fuzz_target --sanitizer none
    cp target/$(uname -m)-unknown-linux-gnu/release/$fuzz_target $OUT/
  fi
done

popd # $REPO/fuzz
