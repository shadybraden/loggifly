ARG PYTHON_VERSION=3.11.4
FROM python:${PYTHON_VERSION}-slim AS base

WORKDIR /app

COPY requirements.txt .

LABEL org.opencontainers.image.source="https://github.com/clemcer/loggifly"

RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh .
COPY app/load_config.py .
COPY app/notifier.py .
COPY app/app.py .
COPY app/docker_monitor.py .
COPY app/line_processor.py .

ARG IMAGE_SOURCE_ARG
ENV IMAGE_SOURCE=${IMAGE_SOURCE_ARG:-"dockerhub"}

ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]
