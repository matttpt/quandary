FROM rust:1.63-bullseye AS builder
RUN apt-get -y update && apt-get -y install libcap2-bin
WORKDIR /usr/src/quandary
COPY . .
RUN cargo install --path .
RUN setcap cap_net_bind_service+ep /usr/local/cargo/bin/quandaryd

FROM gcr.io/distroless/cc-debian11:nonroot
WORKDIR /etc/quandary
COPY --from=builder /usr/local/cargo/bin/quandaryd /usr/local/bin/quandaryd
ENV RUST_LOG=info
EXPOSE 53/tcp
EXPOSE 53/udp
CMD ["quandaryd", "run", "--config", "/etc/quandary/config.toml"]
