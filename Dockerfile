# syntax=docker/dockerfile:1

# --- Builder: static MUSL binary ---
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev build-base \
 && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Prime dependency cache without compiling a placeholder binary
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && printf "fn main() {}\n" > src/main.rs \
 && cargo fetch --locked

# Copy real sources and build
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

# --- Runtime: empty image, just the static binary and the web assets ---
FROM scratch
WORKDIR /app

# Non-root user for safety
USER 65532:65532

# Copy binary and static web assets
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rsDrop /app/rsDrop
COPY --from=builder /app/web /app/web

EXPOSE 8080 8443

ENTRYPOINT ["/app/rsDrop"]
