FROM python:3.12-alpine

RUN addgroup -S inventory && adduser -S inventory -G inventory

WORKDIR /app

COPY inventory/ /app/inventory/

RUN chmod -R u+rwX,g+rwX /app/inventory

ENV PYTHONUNBUFFERED=1

ENTRYPOINT []
