FROM alpine:3.23.4

ARG SYFT_VERSION=v1.44.0
ARG GRYPE_VERSION=v0.112.0

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    jq

RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin "${SYFT_VERSION}"
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin "${GRYPE_VERSION}"

RUN mkdir -p /scanner

COPY scan-from-tar.sh /scanner/scan-from-tar.sh
RUN chmod +x /scanner/scan-from-tar.sh

ENTRYPOINT []
