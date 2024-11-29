FROM rust:1.64 as build

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    software-properties-common \
    cmake \
    libclang-dev \
    libudev-dev

RUN USER=root cargo new --bin solana
WORKDIR /solana

COPY . .

ARG TARGETARCH
RUN rustup target add ${TARGETARCH}-unknown-linux-gnu

RUN cargo build --release --target ${TARGETARCH}-unknown-linux-gnu



FROM rust:1.64

RUN mkdir -p /solana
WORKDIR /solana

ARG TARGETARCH
COPY --from=build /solana/target/${TARGETARCH}-unknown-linux-gnu/release/block-encoder-service .

EXPOSE 8899

ENV RUST_LOG=info

CMD ["./block-encoder-service"]