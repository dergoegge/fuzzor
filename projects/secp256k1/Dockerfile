FROM fuzzor-base:latest

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  wget \
  python3-venv \
  gcc-14-arm-linux-gnueabihf \
  g++-14-arm-linux-gnueabihf \
  gcc-14-x86-64-linux-gnu \
  g++-14-x86-64-linux-gnu

# Avoid gcc version incompatability caused by apt upgrade
RUN cd /AFLplusplus && make clean && make PERFORMANCE=1 -j$(nproc) install

RUN cd /semsan && cargo install --features qemu_arm --bin semsan-arm --path .
RUN cd /semsan && cargo install --features qemu_x86_64 --bin semsan-x86_64 --path .


ARG OWNER=bitcoin-core
ARG REPO=secp256k1
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN git clone https://github.com/guidovranken/cryptofuzz.git
RUN wget https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.bz2

COPY ./build_boost.sh .
RUN bash ./build_boost.sh # build and install boost

COPY ./build.sh .
COPY ./shmem.patch .
COPY ./gcc.patch .
COPY ./cpu_feartues_arm32.patch .
COPY ./cpu_feartues_x86_64.patch .
COPY ./qemu_harness.cpp .
COPY ./config.yaml .

RUN builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
