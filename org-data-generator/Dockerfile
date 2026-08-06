FROM python:3.12-alpine

ARG GRYPE_VERSION=v0.112.0

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    jq

RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin "${GRYPE_VERSION}"

RUN addgroup -S orgdata && adduser -S orgdata -G orgdata

WORKDIR /app
COPY orgdata/ /app/orgdata/

RUN chmod -R u+rwX,g+rwX /app/orgdata

ENV PYTHONUNBUFFERED=1
ENV GRYPE_DB_CACHE_DIR=/cache/grype/db
ENV GRYPE_CHECK_FOR_APP_UPDATE=false

ENTRYPOINT []
