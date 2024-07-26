FROM fuzzor-base

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN cd bitcoin/depends && make NO_QT=1 NO_BDB=1 NO_ZMQ=1 NO_UPNP=1 NO_NATPMP=1 NO_USDT=1 download-linux
RUN mv bitcoin/depends/sources ./bitcoin_depends_sources

RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions
# No idea why this is needed but the existing file based suppression
# "secp256k1/" does not seem to work.
RUN echo "unsigned-integer-overflow:secp256k1_*" >> ./ubsan_suppressions

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
