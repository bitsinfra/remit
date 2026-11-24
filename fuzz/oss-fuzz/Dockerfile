FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y cmake pkg-config
RUN git clone --depth 1 https://github.com/bitsinfra/remit remit
WORKDIR remit
COPY build.sh $SRC/
