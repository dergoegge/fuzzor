FROM fuzzor-base

RUN apt-get update && apt-get install -y \
  libgtk-3-dev pax-utils python3-msgpack \
  python3-jinja2 libcapstone-dev

# Install rust
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN rustup install nightly && rustup default nightly

# Build qemu-nyx and libnyx
# Avoid "libcapstone.so.4 not found ld error" by setting lib path (not sure why this is necessary)
RUN cd /AFLplusplus/nyx_mode/ && \
  LIBRARY_PATH=/AFLplusplus/nyx_mode/QEMU-Nyx/capstone_v4/tests/:$LIBRARY_PATH ./build_nyx_support.sh
# Compile nyx htools
RUN cd /AFLplusplus/nyx_mode/packer/packer/linux_x86_64-userspace && \
  ./compile_64.sh
ENV FUZZOR_AFLPP_BIN_PATH=/AFLplusplus
ENV ENSEMBLE_FUZZ_IGNORE_HANGS=1
ENV FUZZOR_DOCKER_NO_STACK_LIMIT=1

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=

ENV SOURCES_PATH=/depends_sources

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN make -C bitcoin/depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 download-linux SOURCES_PATH=$SOURCES_PATH

RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions

# Globally suppress unsigned-integer-overflow in FuzzedDataProvider.h. Symbolized
# suppression is working, however sometimes the stacktrace seems to be missing symbols
# (see https://github.com/dergoegge/fuzzor/issues/49).
RUN echo "unsigned-integer-overflow:FuzzedDataProvider.h" >> ./ubsan_suppressions

RUN git clone --depth 1 --branch master https://github.com/dergoegge/fuzzamoto.git

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    --mount=type=cache,target=/ccache_asan/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
