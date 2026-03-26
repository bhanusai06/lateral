FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --default-timeout=1000 --no-cache-dir requests==2.31.0

COPY orchestrator/ /app/orchestrator/
COPY honeypot/ /app/honeypot/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/orchestrator/engine.py"]
