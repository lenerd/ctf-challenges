# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

FROM rust:latest as cargo-build

RUN apt-get update

RUN apt-get install musl-tools -y

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/3des-hmac

RUN mkdir src templates
COPY src/* src/
COPY templates/* templates/
ADD Cargo.toml Cargo.lock ./

RUN ls -lR

RUN RUSTFLAGS=-Clinker=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl

RUN rm -f target/x86_64-unknown-linux-musl/release/deps/3des-hmac*

COPY . .

RUN RUSTFLAGS=-Clinker=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM alpine:latest

LABEL maintainer="lenerd <lenerd@localhost>"

ENV VERSION 1.0

EXPOSE 8080

WORKDIR /home/user
COPY --from=cargo-build /usr/src/3des-hmac/target/x86_64-unknown-linux-musl/release/3des-hmac .
RUN mkdir -p static/css static/js
COPY static/css/* static/css/
COPY static/js/* static/js/
COPY flag.txt ./
RUN adduser -D -s /bin/sh user && \
    chown -R user:user .

USER user
ENV HOME /home/user
ENTRYPOINT ["./3des-hmac"]
