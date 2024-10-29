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
export PATH=$PATH:/usr/local/go/bin

go env -w GOCACHE=/go-cache

lnd_packages=$(go list ./...)

for package in $lnd_packages; do
  echo "Running fuzz tests for package: $package"

  # Remove the github prefix and replace "/" with "_"
  binary_prefix=$(sed "s/github.com\/lightningnetwork\/lnd[\/]*//g" <<< "$package")

  if [[ -z $binary_prefix ]]; then
    continue
  fi

  binary_prefix=fuzz_$(sed "s/\//_/g" <<< "$binary_prefix")
  echo "binary prefix: $binary_prefix"

  go test -c -fuzz=. $package -o ./$binary_prefix
  fuzz_tests=$(./$binary_prefix -test.list . | grep ^Fuzz || true) # grep returns 1 if there are no finds

  # Run each fuzz test
  for fuzz_test in $fuzz_tests; do
    echo "$PWD/$binary_prefix -test.run=\"^$fuzz_test\$\" -test.fuzz=\"^$fuzz_test\$\" -test.fuzzcachedir=\$1" > $OUT/${binary_prefix}_$fuzz_test
    chmod +x $OUT/${binary_prefix}_$fuzz_test
  done
done

popd # $REPO
