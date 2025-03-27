#!/bin/bash

set -ex

# Check that we are on an x86_64 machine.
if [[ $(uname -m) != "x86_64" ]]; then
  echo "Error: The fuzzamoto project is only supported on x86 machines due to Nyx's dependency on x86"
  exit 1
fi

pushd bitcoin

# Build dependencies using the Bitcoin Core depends system.
sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./depends/funcs.mk  # Keep extracted source
make -C depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
     SOURCES_PATH=$SOURCES_PATH \
     AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip \
     CPPFLAGS="$CPPFLAGS" CXXFLAGS="$CXXFLAGS" LDFLAGS="$LDFLAGS" -j$(nproc)

EXTRA_BUILD_OPTIONS=""
if [[ "$FUZZING_ENGINE" = *"aflpp_asan"* ]]; then
  # Do nothing
elif [[ "$FUZZING_ENGINE" = *"aflpp"* ]]; then
  # Build with address sanitizer in the regular afl++ build as well, so that
  # reproductions work as expected.
  EXTRA_BUILD_OPTIONS="-DSANITIZERS=address"
fi

cmake -B build_fuzz \
  --toolchain depends/$(./depends/config.guess)/toolchain.cmake \
  `# Setting these flags to an empty string ensures that the flags set by the Fuzzor environment remain unaltered` \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="" \
  -DENABLE_HARDENING=OFF \
  -DWITH_BDB=ON \
  -DAPPEND_CPPFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DABORT_ON_FAILED_ASSUME" \
  $EXTRA_BUILD_OPTIONS

cmake --build build_fuzz -j$(nproc) --target bitcoind

# Decide which fuzzamoto features to enable. The assumption is that the afl++
# address sanitizer build is used for fuzzing with nyx and the plain afl++
# build is used for reproduction builds.
FUZZAMOTO_FEATURES="reduced_pow"
if [[ "$FUZZING_ENGINE" = *"aflpp_asan"* ]]; then
  FUZZAMOTO_FEATURES="$FUZZAMOTO_FEATURES,nyx"

  # Build the nyx crash handler (only needed when fuzzing with nyx)
  clang -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
    ../fuzzamoto/fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so
elif [[ "$FUZZING_ENGINE" = *"aflpp"* ]]; then
  # Add inherit_stdout features to make all output (stdout & stderr)
  # available during reproduction of solutions.
  FUZZAMOTO_FEATURES="$FUZZAMOTO_FEATURES,inherit_stdout"
fi

CC="" CXX="" CFLAGS="" CXXFLAGS="" LDFLAGS="" BITCOIND_PATH=$PWD/build_fuzz/bin/bitcoind cargo build --release --workspace \
  --manifest-path ../fuzzamoto/Cargo.toml \
  --features "$FUZZAMOTO_FEATURES"

for scenario in ../fuzzamoto/target/release/scenario-*; do
  if [ -f "$scenario" ] && [ -x "$scenario" ]; then
    scenario_name=$(basename $scenario)

    if [[ "$FUZZING_ENGINE" = *"aflpp_asan"* ]]; then
      export SCENARIO_NYX_DIR="$OUT/fuzzamoto_${scenario_name}"

      # Initialize the scenario nyx share directory
      ../fuzzamoto/target/release/fuzzamoto-cli init \
        --sharedir $SCENARIO_NYX_DIR \
        --crash-handler ./libnyx_crash_handler.so \
        --bitcoind ./build_fuzz/bin/bitcoind \
        --scenario $scenario
      # Copy 64-bit nyx helper bins
      cp /AFLplusplus/nyx_mode/packer/packer/linux_x86_64-userspace/bin64/* $SCENARIO_NYX_DIR
      # Generate nyx config
      python3 /AFLplusplus/nyx_mode/packer/packer/nyx_config_gen.py $SCENARIO_NYX_DIR Kernel -m 4096
    elif [[ "$FUZZING_ENGINE" = *"aflpp"* ]]; then
      mkdir $OUT/fuzzamoto_${scenario_name}
      cp ../fuzzamoto/target/release/${scenario_name} $OUT/fuzzamoto_${scenario_name}
      cp ./build_fuzz/bin/bitcoind $OUT/fuzzamoto_${scenario_name}
    fi
  fi
done

# This build script is executed repeatedly. Make sure there are no left over
# build artifacts from previous executions, and that no build artifacts
# are in the final image.
rm -rf build_fuzz
make clean -C depends

popd
