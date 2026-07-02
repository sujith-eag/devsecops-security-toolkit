# =============================================================
# Stage 1: Fetch Syft + Grype binaries (ARM64-aware)
# =============================================================
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS binaries

ARG TARGETARCH
ARG SYFT_VERSION=1.4.1
ARG GRYPE_VERSION=0.79.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-$(uname -m)}" in \
      arm64|aarch64) ARCH="arm64" ;; \
      amd64|x86_64)  ARCH="amd64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -sSfL \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz" \
      -o /tmp/syft.tar.gz \
    && tar -xzf /tmp/syft.tar.gz -C /tmp syft \
    && mv /tmp/syft /usr/local/bin/syft \
    && chmod +x /usr/local/bin/syft \
    && syft version

RUN set -eux; \
    case "${TARGETARCH:-$(uname -m)}" in \
      arm64|aarch64) ARCH="arm64" ;; \
      amd64|x86_64)  ARCH="amd64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz" \
      -o /tmp/grype.tar.gz \
    && tar -xzf /tmp/grype.tar.gz -C /tmp grype \
    && mv /tmp/grype /usr/local/bin/grype \
    && chmod +x /usr/local/bin/grype \
    && grype version

# =============================================================
# Stage 2: Final image
# =============================================================
FROM python:3.12-slim

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl ca-certificates jq git awscli \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 \
        libgdk-pixbuf-2.0-0 libffi-dev \
        shared-mime-info fonts-liberation fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    Jinja2==3.1.4 \
    weasyprint==68.1 \
    boto3==1.34.0 \
    requests==2.31.0 \
    PyYAML==6.0.1

# Copy Go binaries from Stage 1
COPY --from=binaries /usr/local/bin/syft  /usr/local/bin/syft
COPY --from=binaries /usr/local/bin/grype /usr/local/bin/grype

# Copy the two toolkit components directly from the repo (no clone needed)
# Build context = repo root, so these paths resolve to sibling directories
COPY image-sbom-vuln-scanner/ /toolkit/image-sbom-vuln-scanner/
COPY reporter-analyzer/       /toolkit/reporter-analyzer/

RUN chmod +x /toolkit/image-sbom-vuln-scanner/scan-from-dir.sh \
    && chmod +x /toolkit/image-sbom-vuln-scanner/scan-from-tar.sh

# Install reporter-analyzer Python dependencies if present
RUN if [ -f /toolkit/reporter-analyzer/requirements.txt ]; then \
        pip install --no-cache-dir -r /toolkit/reporter-analyzer/requirements.txt; \
    fi

ENV PYTHONPATH="/toolkit/reporter-analyzer:${PYTHONPATH:-}"
ENV GRYPE_CHECK_FOR_APP_UPDATE=false
ENV PYTHONUNBUFFERED=1

COPY devsecops-scanner/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /output

ENTRYPOINT ["/entrypoint.sh"]
