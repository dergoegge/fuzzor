ARG BASE_IMAGE=fuzzor-base
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  jq \
  libffi-dev \
  libsodium-dev \
  libssl-dev \
  libsqlite3-dev \
  lowdown \
  python3-mako \
  python3-setuptools

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
