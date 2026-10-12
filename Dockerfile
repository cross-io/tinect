# This Dockerfile uses standard OCI-compatible instructions and can be built by
# either Docker (`docker build`) or Podman (`podman build`).
FROM docker.io/library/rust:1.97-alpine3.24 AS builder

RUN apk add --no-cache \
        build-base \
        bzip2 \
        curl \
        file \
        linux-headers \
        musl-utils \
        pkgconf \
        xz

# Match the release workflow: build the Linux netfilter dependencies as static
# libraries, then link them and Rust's C runtime into the executable.
RUN set -eux; \
    workdir=/tmp/tinect-static-libs; \
    prefix="$workdir/native"; \
    mkdir -p "$workdir"; \
    cd "$workdir"; \
    curl --fail --location --remote-name https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2; \
    curl --fail --location --remote-name https://netfilter.org/projects/libnftnl/files/libnftnl-1.3.1.tar.xz; \
    tar -xf libmnl-1.0.5.tar.bz2; \
    tar -xf libnftnl-1.3.1.tar.xz; \
    cd libmnl-1.0.5; \
    ./configure --disable-shared --enable-static --prefix="$prefix"; \
    make -j"$(getconf _NPROCESSORS_ONLN)"; \
    make install; \
    cd ../libnftnl-1.3.1; \
    PKG_CONFIG_PATH="$prefix/lib/pkgconfig" \
      CPPFLAGS="-I$prefix/include" \
      LDFLAGS="-L$prefix/lib" \
      ./configure --disable-shared --enable-static --prefix="$prefix"; \
    make -j"$(getconf _NPROCESSORS_ONLN)"; \
    make install

WORKDIR /usr/src/tinect
COPY . .
RUN LIBMNL_LIB_DIR=/tmp/tinect-static-libs/native/lib \
    LIBNFTNL_LIB_DIR=/tmp/tinect-static-libs/native/lib \
    sh -euxc 'target="$(rustc -vV | awk "/^host:/ { print \$2 }")"; \
      target_env="$(echo "$target" | tr "[:lower:]-" "[:upper:]_")"; \
      export "CARGO_TARGET_${target_env}_RUSTFLAGS=-C target-feature=+crt-static -C link-arg=-static -C link-arg=-Wl,--start-group -C link-arg=-lmnl -C link-arg=-lnftnl -C link-arg=-Wl,--end-group"; \
      cargo build --release --locked --target "$target"; \
      file "target/$target/release/tinect" | grep -E "static.*linked"'

FROM docker.io/library/alpine:3.24

LABEL org.opencontainers.image.title="tinect" \
      org.opencontainers.image.description="A static, policy-driven layer-3 overlay network" \
      org.opencontainers.image.source="https://github.com/cross-io/tinect"

COPY --from=builder /usr/src/tinect/target/*/release/tinect /usr/local/bin/tinect

ENTRYPOINT ["tinect"]
CMD ["--help"]
