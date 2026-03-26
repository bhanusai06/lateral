FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.31.0

COPY fake_server.py /app/fake_server.py

ENV PYTHONUNBUFFERED=1
ENV HP_TYPE=admin_server
ENV HP_PORT=8445
ENV HP_NAME=Honeypot
ENV HP_ID=hp_default
ENV API_URL=http://backend:5000/api
ENV TTP_LOG=/tmp/ttp_log.json

EXPOSE 8445

CMD ["python", "/app/fake_server.py"]
