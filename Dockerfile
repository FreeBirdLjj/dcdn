# The rust:alpine image's default target is musl (x86_64-unknown-linux-musl /
# aarch64-unknown-linux-musl, matching the image architecture automatically), so
# buildx multi-platform builds compile natively per platform without cross targets.
# build-base = gcc + musl-dev + make; ring's small amount of C code needs cc.
# The result is a fully static musl binary that runs on scratch.
FROM rust:1-alpine AS build
WORKDIR /app
RUN apk add --no-cache build-base
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM scratch
WORKDIR /app
COPY --from=build /app/target/release/dcdn /app/dcdn
ENTRYPOINT ["/app/dcdn"]
