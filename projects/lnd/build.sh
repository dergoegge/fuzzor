#!/bin/bash

set -xe

pushd $REPO

if [ "$(uname -m)" = "x86_64" ]; then
  curl -L https://go.dev/dl/go1.22.4.linux-amd64.tar.gz > go.tar.gz
elif [ "$(uname -m)" = "aarch64" ]; then
  curl -L https://go.dev/dl/go1.22.4.linux-arm64.tar.gz > go.tar.gz
else
  echo "Architecture not supported"
  exit 1
fi

rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz
export PATH=$PATH:/usr/local/go/bin:$PWD/go-118-fuzz-build

go env -w GOCACHE=/go-cache

git clone --depth 1 https://github.com/AdamKorcz/go-118-fuzz-build
pushd go-118-fuzz-build
go build
popd

go get github.com/AdamKorcz/go-118-fuzz-build/testing

build_pkg_fuzzers () {
  path=$1
  prefix=$2
  pushd $path

  if [ -f ./go.mod ]; then
    echo "Found Go module, adding github.com/AdamKorcz/go-118-fuzz-build/testing as dependency"
    go get github.com/AdamKorcz/go-118-fuzz-build/testing
  fi

  # Write the list of harnesses for this package to a file
  git grep -h -e "func Fuzz.*(" | sed "s/func//g" | sed "s/(.*//g" > /tmp/harnesses

  # Rename _test.go files, required by go-118-fuzz-build
  for x in *_test.go ; do mv "$x" "${x%_test.go}_mv_fuzz.go" ; done

  readarray FUZZ_TARGETS < "/tmp/harnesses"
  for fuzz_target in ${FUZZ_TARGETS[@]}; do
    # Build a fuzz binary for each harness
    go-118-fuzz-build -o fuzz_$fuzz_target.a -func $fuzz_target github.com/lightningnetwork/lnd/$path
    clang++ -o $OUT/"$prefix"_$fuzz_target fuzz_$fuzz_target.a -fsanitize=fuzzer
  done

  popd # $path
}

# Delete test package idiom tests. Otherwise we get errors like: "found
# packages lnwire (accept_channel.go) and lnwire_test (message_mv_fuzz.go) in
# /workdir/lnd/lnwire".
rm $(git grep -e "package [a-zA-Z0-9]*_test" | sed "s/:.*//g")

build_pkg_fuzzers zpay32 zpay32
build_pkg_fuzzers brontide brontide
build_pkg_fuzzers lnwire lnwire
build_pkg_fuzzers tlv tlv
# TODO build_pkg_fuzzers routing routing
build_pkg_fuzzers watchtower/wtwire watchtower_wire
build_pkg_fuzzers watchtower/wtclient watchtower_client
build_pkg_fuzzers htlcswitch/hop htlcswitch_hop

popd # $REPO
