FROM fuzzor-base

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
  jq \
  libffi-dev \
  libssl-dev \
  libsqlite3-dev \
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
