FROM fuzzor-base:latest

ARG GCC_V
ENV GCC_V=$GCC_V

ARG OWNER=bitcoin-core
ARG REPO=secp256k1
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN git clone --branch 1_fixups https://github.com/fanquake/cryptofuzz.git
RUN curl https://archives.boost.io/release/1.86.0/source/boost_1_86_0.tar.bz2 -o boost_1_86_0.tar.bz2 && \
    tar jxf boost_1_86_0.tar.bz2 && \
    cp -R boost_1_86_0/boost/ /usr/include/ && \
    rm boost_1_86_0.tar.bz2

COPY ./build.sh .
COPY ./shmem.patch .
COPY ./gcc.patch .
COPY ./qemu_harness.cpp .
COPY ./config.yaml .

RUN builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
