FROM python:3.12-alpine

ARG GRYPE_VERSION=v0.112.0

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    jq

RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin "${GRYPE_VERSION}"

RUN addgroup -S monitor && adduser -S monitor -G monitor

WORKDIR /app

RUN mkdir -p /cache/grype /results \
    && chown -R monitor:monitor /app /cache /results \
    && chmod -R u+rwX,g+rwX /app /cache /results

COPY monitor/ /app/monitor/

RUN chmod -R u+rwX,g+rwX /app/monitor

ENV PYTHONUNBUFFERED=1
ENV GRYPE_DB_CACHE_DIR=/cache/grype/db
ENV GRYPE_CHECK_FOR_APP_UPDATE=false

ENTRYPOINT []
