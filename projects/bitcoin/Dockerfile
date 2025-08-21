FROM fuzzor-base

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=

ENV SOURCES_PATH=/depends_sources

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN make -C bitcoin/depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 NO_IPC=1 download-linux SOURCES_PATH=$SOURCES_PATH

RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions

# Globally suppress unsigned-integer-overflow in FuzzedDataProvider.h. Symbolized
# suppression is working, however sometimes the stacktrace seems to be missing symbols
# (see https://github.com/dergoegge/fuzzor/issues/49).
RUN echo "unsigned-integer-overflow:FuzzedDataProvider.h" >> ./ubsan_suppressions
RUN echo "unsigned-integer-overflow:InsecureRandomContext::InsecureRandomContext" >> ./ubsan_suppressions

COPY ./config.yaml .
COPY ./build.sh .

ENV FUZZOR_HONGGFUZZ_NO_MINIMIZE=1

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    --mount=type=cache,target=/ccache_asan/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
