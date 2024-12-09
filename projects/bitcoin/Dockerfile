FROM fuzzor-base

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=

ENV SOURCES_PATH=/depends_sources

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN make -C bitcoin/depends NO_QT=1 NO_BDB=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 NO_USDT=1 download-linux SOURCES_PATH=$SOURCES_PATH

RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions

RUN echo "unsigned-integer-overflow:FuzzedDataProvider::ConsumeIntegral" >> ./ubsan_suppressions

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    --mount=type=cache,target=/ccache_asan/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
