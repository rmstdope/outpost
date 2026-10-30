FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.23
ARG REVISION
RUN test -n "$REVISION" && adduser -D -H -u 10001 outpost
COPY --from=build /src/target/release/outpost /usr/local/bin/outpost
ENV OUTPOST_REVISION=$REVISION
USER 10001:10001
EXPOSE 8080 8081 3478/udp 3478/tcp
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD wget -q --spider http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/outpost"]
