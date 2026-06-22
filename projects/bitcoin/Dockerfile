ARG BASE_IMAGE=fuzzor-base
FROM ${BASE_IMAGE}

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=
ARG PR_NUMBER=

ENV SOURCES_PATH=/depends_sources

RUN if [ -n "$PR_NUMBER" ]; then \
      git clone https://github.com/bitcoin/bitcoin.git bitcoin && \
      cd bitcoin && \
      git fetch origin pull/$PR_NUMBER/head:pr-branch && \
      git checkout pr-branch && \
      cd ..; \
    else \
      git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git; \
    fi
RUN make -C bitcoin/depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 NO_IPC=1 download-linux SOURCES_PATH=$SOURCES_PATH

RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions

COPY ./config.yaml .
COPY ./build.sh .

ENV FUZZOR_HONGGFUZZ_NO_MINIMIZE=1

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    --mount=type=cache,target=/ccache_asan/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
