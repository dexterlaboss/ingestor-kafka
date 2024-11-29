FROM rust:1.70 as build

RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-utils \
    software-properties-common \
    cmake \
    libclang-dev \
    libudev-dev

ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        echo "x86_64-unknown-linux-gnu" > /target_arch; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        echo "aarch64-unknown-linux-gnu" > /target_arch; \
    else \
        echo "Unsupported architecture: $TARGETARCH" && exit 1; \
    fi && \
    rustup target add $(cat /target_arch)

RUN USER=root cargo new --bin solana
WORKDIR /solana

COPY . .

RUN RUST_TARGET=$(cat /target_arch) && \
    cargo build --release --target $RUST_TARGET && \
    cp /solana/target/$RUST_TARGET/release/block-encoder-service /solana/block-encoder-service



FROM rust:1.70

RUN mkdir -p /solana
WORKDIR /solana

COPY --from=build /solana/block-encoder-service .

EXPOSE 8899

ENV RUST_LOG=info

CMD ["./block-encoder-service"]