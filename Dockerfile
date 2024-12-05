FROM rust:1.64 as build

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    software-properties-common \
    cmake \
    libclang-dev \
    libudev-dev

RUN USER=root cargo new --bin solana
WORKDIR /solana

COPY . /solana

RUN cargo build --release



FROM rust:1.64

RUN mkdir -p /solana

WORKDIR /solana

COPY --from=build /solana/target/release/block-encoder-service .

EXPOSE 8899

ENV RUST_LOG=info
CMD ["./block-encoder-service"]