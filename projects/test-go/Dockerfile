FROM fuzzor-base

ENV REPO buggy

COPY ./build.sh ./
COPY ./config.yaml .
COPY ./buggy ./buggy

RUN builder $PWD/config.yaml ./build.sh $FUZZOR_HARNESSES

RUN ln -s $PWD/out/native_go $PWD/out/libfuzzer
