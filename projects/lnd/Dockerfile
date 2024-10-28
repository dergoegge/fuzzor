FROM fuzzor-base

ARG OWNER=lightningnetwork
ARG REPO=lnd
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/go-cache \
  builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES

# Fuzzor uses out/libfuzzer to gather the harness list (this should change)
RUN ln -s out/native_go out/libfuzzer
