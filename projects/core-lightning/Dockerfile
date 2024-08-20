FROM fuzzor-base

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  dirmngr \
  gettext \
  gnupg \
  libpq-dev \
  libtool \
  libffi-dev \
  libssl-dev \
  protobuf-compiler \
  python3.8 \
  python3-dev \
  python3-mako \
  python3-pip \
  python3-venv \
  python3-setuptools \
  python3-grpcio \
  libev-dev \
  libevent-dev \
  qemu-user-static \
  clang-16 \
  jq

# TODO clang-18 from base

RUN pip3 install --break-system-packages --user grpcio-tools

COPY ./config.yaml .
COPY ./build.sh .

ARG OWNER=ElementsProject
ARG REPO=lightning
ARG BRANCH=master
ARG REVISION=

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_cmplog/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES
