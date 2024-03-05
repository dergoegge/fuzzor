#!/bin/bash

set -xe

$CC -O0 buggy_harness.c $CFLAGS -c -o buggy_harness.o
$CC buggy_harness.o $LIB_FUZZING_ENGINE -o $OUT/buggy_harness
