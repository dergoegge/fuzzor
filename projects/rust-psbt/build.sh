#!/bin/bash

set -xe

pushd $REPO/fuzz

# Query the pinned nightly version from upstream's Cargo.toml metadata
NIGHTLY=$(cargo rbmt toolchains --nightly)

ls fuzz_targets/*.rs | sed "s/fuzz_targets\///g" | sed "s/\.rs//g" > /tmp/a

readarray FUZZ_TARGETS < "/tmp/a"
for fuzz_target in ${FUZZ_TARGETS[@]}; do
  if [ "$FUZZING_ENGINE" = "coverage" ]; then
    cargo +$NIGHTLY fuzz coverage $fuzz_target --sanitizer none
    cp target/$(uname -m)-unknown-linux-gnu/coverage/$(uname -m)-unknown-linux-gnu/release/$fuzz_target $OUT/
  else
    cargo +$NIGHTLY fuzz build $fuzz_target --sanitizer none
    cp target/$(uname -m)-unknown-linux-gnu/release/$fuzz_target $OUT/
  fi
done

popd
