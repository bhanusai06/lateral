FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY backend/requirements.txt ./backend/
RUN tr -d '\r' < ./backend/requirements.txt > ./backend/reqs_clean.txt && \
    pip install --default-timeout=1000 --no-cache-dir -r ./backend/reqs_clean.txt

# Copy application code
COPY backend /app/backend
COPY data /app/data

# Create directories
RUN mkdir -p /app/backend/models/saved /app/data/processed /app/data/raw

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "-m", "backend.app"]
