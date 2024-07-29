#!/bin/bash

set -ex

if [[ $FUZZING_ENGINE =~ semsan_Custom[0-1] ]]; then
  export CC=arm-linux-gnueabihf-gcc-14
  export CXX=arm-linux-gnueabihf-g++-14
  export LD=arm-linux-gnueabihf-gcc-14
  export AR=arm-linux-gnueabihf-ar
  export CMAKE_TOOLCHAIN_FILE=/toolchains/arm32.cmake
elif [[ $FUZZING_ENGINE =~ semsan_Custom[2-3] ]]; then
  export CC=x86_64-linux-gnu-gcc-14
  export CXX=x86_64-linux-gnu-g++-14
  export LD=x86_64-linux-gnu-gcc-14
  export AR=x86_64-linux-gnu-ar
  export CMAKE_TOOLCHAIN_FILE=/toolchains/x86_64.cmake
fi

pushd secp256k1

rm -rf ./*
git checkout .

./autogen.sh
COMMON_CONF_OPTS="--enable-static --disable-tests --disable-benchmark --disable-exhaustive-tests --enable-module-recovery --enable-module-schnorrsig --enable-experimental --enable-module-ecdh"
COMMON_ARM32_CONF_OPTS="--host=arm-linux-gnueabihf --with-test-override-wide-multiply=int128_struct"
COMMON_X86_CONF_OPTS="--host=x86-64-linux-gnu"
if [[ $FUZZING_ENGINE =~ "semsan_Custom0" ]]; then
  ./configure $COMMON_CONF_OPTS $COMMON_ARM32_CONF_OPTS --with-asm=no # Disable hand-rolled assembly
elif [[ $FUZZING_ENGINE =~ "semsan_Custom1" ]]; then
  ./configure $COMMON_CONF_OPTS $COMMON_ARM32_CONF_OPTS --with-asm=arm32 # Enable hand-rolled assembly
elif [[ $FUZZING_ENGINE =~ "semsan_Custom2" ]]; then
  ./configure $COMMON_CONF_OPTS $COMMON_X86_CONF_OPTS --with-asm=no # Disable hand-rolled assembly
elif [[ $FUZZING_ENGINE =~ "semsan_Custom3" ]]; then
  ./configure $COMMON_CONF_OPTS $COMMON_X86_CONF_OPTS --with-asm=x86_64 # Enable hand-rolled assembly
elif [[ $FUZZING_ENGINE =~ "semsan_Custom6" ]]; then
  ./configure $COMMON_CONF_OPTS --with-test-override-wide-multiply=int64
elif [[ $FUZZING_ENGINE =~ "semsan_Custom7" ]]; then
  ./configure $COMMON_CONF_OPTS --with-test-override-wide-multiply=int128
elif [[ $FUZZING_ENGINE =~ "semsan_Custom8" ]]; then
  ./configure $COMMON_CONF_OPTS --with-test-override-wide-multiply=int128_struct
else
  ./configure $COMMON_CONF_OPTS
fi

make -j$(nproc)

export SECP256K1_INCLUDE_PATH=$(realpath .)
export LIBSECP256K1_A_PATH=$(realpath .libs/libsecp256k1.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SECP256K1"

popd # secp256k1

pushd cryptofuzz

rm -rf ./*
git checkout .

git apply ../shmem.patch # Makes cryptofuzz write to semsan's shmem buffer
git apply ../gcc.patch # Allows us to build cryptofuzz with gcc

export CXXFLAGS="$CXXFLAGS -Wno-psabi"

python3 ./gen_repository.py

# Inject cryptofuzz options at compile time
rm extra_options.h
echo -n '"' >>extra_options.h
echo -n '--operations=' >>extra_options.h
echo -n 'Digest,' >>extra_options.h
echo -n 'HMAC,' >>extra_options.h
echo -n 'KDF_HKDF,' >>extra_options.h
echo -n 'SymmetricEncrypt,' >>extra_options.h
echo -n 'SymmetricDecrypt,' >>extra_options.h
echo -n 'ECC_PrivateToPublic,' >>extra_options.h
echo -n 'ECC_ValidatePubkey,' >>extra_options.h
echo -n 'ECC_Point_Add,' >>extra_options.h
echo -n 'ECC_Point_Mul,' >>extra_options.h
echo -n 'ECC_Point_Dbl,' >>extra_options.h
echo -n 'ECC_Point_Neg,' >>extra_options.h
echo -n 'ECDSA_Sign,' >>extra_options.h
echo -n 'ECDSA_Verify,' >>extra_options.h
echo -n 'ECDSA_Recover,' >>extra_options.h
echo -n 'Schnorr_Sign,' >>extra_options.h
echo -n 'Schnorr_Verify,' >>extra_options.h
echo -n 'ECDH_Derive,' >>extra_options.h
echo -n 'BignumCalc_Mod_2Exp256 ' >>extra_options.h
echo -n 'BignumCalc_Mod_SECP256K1 ' >>extra_options.h
echo -n '--curves=secp256k1 ' >>extra_options.h
echo -n '--digests=NULL,SHA1,SHA256,SHA512,RIPEMD160,SHA3-256,SIPHASH64 ' >>extra_options.h
echo -n '--ciphers=CHACHA20,AES_256_CBC ' >>extra_options.h
echo -n '--calcops=' >>extra_options.h
# Bitcoin Core arith_uint256.cpp operations
echo -n 'Add,And,Div,IsEq,IsGt,IsGte,IsLt,IsLte,IsOdd,Mul,NumBits,Or,Set,Sub,Xor,' >>extra_options.h
# libsecp256k1 scalar operations
echo -n 'IsZero,IsOne,IsEven,Add,Mul,InvMod,IsEq,CondSet,Bit,Set,RShift ' >>extra_options.h
echo -n '"' >>extra_options.h

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL"

if [[ $FUZZING_ENGINE =~ semsan_Custom[0-5] ]]; then
  $CXX -DNEVER_EXIT -static ../qemu_harness.cpp -c -o qemu_harness.o
  $AR rcs qemu_harness.a qemu_harness.o
  export LIB_FUZZING_ENGINE="./qemu_harness.a"
elif [[ $FUZZING_ENGINE =~ "aflpp" || $FUZZING_ENGINE =~ "semsan" ]]; then
  # Use afl++'s libfuzzer driver because cryptofuzz doesn't provide a native
  # afl harness.
  export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
fi

export LIBFUZZER_LINK=$LIB_FUZZING_ENGINE

pushd modules/secp256k1
make -j$(nproc)
popd # modules/secp256k1

if [[ $FUZZING_ENGINE =~ semsan_Custom[0-5] ]]; then
  # Link staticly for qemu targets
  export LINK_FLAGS="-static"
fi
make -j$(nproc)

cp cryptofuzz $OUT/

popd # cryptofuzz
