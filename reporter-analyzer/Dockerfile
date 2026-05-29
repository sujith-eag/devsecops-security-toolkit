FROM python:3.12-alpine

RUN addgroup -S analyzer && adduser -S analyzer -G analyzer

WORKDIR /app

COPY analyzer/ /app/analyzer/

RUN chmod -R u+rwX,g+rwX /app/analyzer

ENTRYPOINT []
