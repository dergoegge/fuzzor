FROM fuzzor-base

COPY ./build.sh ./
COPY ./config.yaml .
COPY ./buggy_harness.c .

RUN builder $PWD/config.yaml ./build.sh $FUZZOR_HARNESSES
