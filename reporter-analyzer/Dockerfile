FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libjpeg-dev \
    libopenjp2-7-dev \
    libffi-dev \
    libcairo2 \
    fonts-liberation \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
    Jinja2 \
    weasyprint==68.1

RUN addgroup --system analyzer && adduser --system --ingroup analyzer analyzer

WORKDIR /app

COPY analyzer/ /app/analyzer/

RUN chmod -R u+rwX,g+rwX /app/analyzer

ENTRYPOINT []