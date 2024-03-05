FROM fuzzor-base

ARG OWNER=lightningdevkit
ARG REPO=rust-lightning
ARG BRANCH=main
ARG REVISION=

RUN rustup install nightly
RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN cd $REPO/fuzz && cargo update && cargo install --force cargo-fuzz

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workdir/rust-lightning/fuzz/target \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
