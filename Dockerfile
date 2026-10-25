FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for asyncpg / networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pipeline.py ./pipeline.py
COPY src/ ./src/
COPY sql/ ./sql/
COPY tests/ ./tests/

ENV PYTHONUNBUFFERED=1

CMD ["python", "pipeline.py"]
