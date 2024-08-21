FROM fuzzor-base:latest

RUN cd /semsan && cargo install --features qemu_arm --bin semsan-arm --path .
RUN cd /semsan && cargo install --features qemu_x86_64 --bin semsan-x86_64 --path .

ARG OWNER=openssl
ARG REPO=openssl
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN git clone https://github.com/guidovranken/cryptofuzz.git
RUN curl https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.bz2 -o boost_1_84_0.tar.bz2

COPY ./build_boost.sh .
RUN bash ./build_boost.sh # build and install boost

COPY ./build.sh .
COPY ./shmem.patch .
COPY ./gcc.patch .
COPY ./qemu_harness.cpp .
COPY ./config.yaml .
COPY ./custom_comparator.c .

RUN clang -shared -fPIC -o custom_comparator.so custom_comparator.c
ENV SEMSAN_CUSTOM_COMPARATOR=/workdir/custom_comparator.so

RUN builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
