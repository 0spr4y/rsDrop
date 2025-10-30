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
 && cargo fetch

# Copy real sources and build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Runtime: minimal, no shell ---
FROM alpine:3.20
WORKDIR /app

# Non-root user for safety
USER 65532:65532

# Copy binary and static web assets
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rsDrop /app/rsDrop
COPY --from=builder /app/web /app/web

EXPOSE 8080 8443

ENTRYPOINT ["/app/rsDrop"]
# Uncomment to override the default address provided by Clap
# CMD ["--addr", "0.0.0.0:8080"]

# Optional: copy TLS certs into the image (uncomment and provide files)
# COPY certs/cert.pem /app/certs/cert.pem
# COPY certs/key.pem /app/certs/key.pem


# To run with HTTPS by default (uncomment to use baked-in cert paths)
# CMD ["--addr", "0.0.0.0:8443", "--cert", "/app/certs/cert.pem", "--key", "/app/certs/key.pem"]
