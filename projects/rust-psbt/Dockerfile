ARG BASE_IMAGE=fuzzor-base
FROM ${BASE_IMAGE}

# Install rust
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain stable

ARG OWNER=rust-bitcoin
ARG REPO=rust-psbt
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://git.rust-bitcoin.org/$OWNER/$REPO.git

# Install cargo rbmt
# cargo rbmt installs cargo fuzz
RUN cd $REPO && \
    cargo install --git https://git.rust-bitcoin.org/rust-bitcoin/rust-bitcoin-maintainer-tools \
                  --rev $(cat rbmt-version) cargo-rbmt && \
    cargo rbmt toolchains && \
    cd fuzz && cargo rbmt tools

COPY ./config.yaml .
COPY ./build.sh .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workdir/rust-psbt/fuzz/target \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
