FROM python:3.12-alpine

RUN addgroup -S console && adduser -S console -G console

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY console/ /app/console/

RUN chmod -R u+rwX,g+rwX /app/console

ENV PYTHONUNBUFFERED=1
ENV ORG_DATA_CURRENT_DIR=/org-data/current
ENV REPORTS_DIR=/reports
ENV CONSOLE_HOST=0.0.0.0
ENV CONSOLE_PORT=8080
ENV HOME=/tmp

ENTRYPOINT []


CMD ["gunicorn", \
     "--bind", "0.0.0.0:8080", \
     "--workers", "1", \
     "--threads", "4", \
     "--timeout", "300", \
     "--worker-tmp-dir", "/tmp", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "console.main:app"]
