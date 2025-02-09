# Preparition stage
FROM golang:1.22.2 AS builder

ARG DEBUG=0

RUN apt update -qq && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    if [ "$DEBUG" -eq 1 ]; then \
        DEBIAN_FRONTEND=noninteractive apt install -y build-essential \
                pkg-config \
                clang \
                llvm \
                m4 \
                git \
                libelf-dev \
                libpcap-dev \
                iproute2 \
                iputils-ping \
                libbpf-dev \
                linux-libc-dev \
                cmake \
                libcap-ng-dev \
                libcap-dev \
                tshark; \
    else \
        DEBIAN_FRONTEND=noninteractive apt install -y libbpf-dev linux-libc-dev clang llvm; \
    fi

RUN ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm \
	&& ln -sf /usr/include/$(uname -m)-linux-gnu/bits /usr/include/bits

RUN mkdir /sources/
WORKDIR /sources/

RUN if [ "$DEBUG" -eq 1 ]; then \
        git clone --recurse-submodules https://github.com/libbpf/bpftool.git \
        && make -C bpftool/src/ install \
        && git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git \
        && make -C xdp-tools/ install; \
    fi

# Build stage
FROM builder AS build-linux

WORKDIR /build
COPY ./ /build/
RUN make

# Final Stage
FROM debian:12-slim AS final

ARG DEBUG=0

RUN if [ "${DEBUG}" -eq 1 ]; then \
        apt update -qq && \
        echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
        DEBIAN_FRONTEND=noninteractive apt install -y tshark; \
    fi

COPY --from=build-linux /build/build/texporter /app/texporter

ENTRYPOINT [ "/app/texporter" ]
