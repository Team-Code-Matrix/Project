# ==============================================================================
# Pillar 3 Worker: Application-Level Web Security & JA4S Fingerprinting
# Monorepo Build Context: ./backend
# ==============================================================================

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY workers/pillar3-websec/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared libraries and worker source
COPY shared ./shared
COPY workers/pillar3-websec ./workers/pillar3-websec

CMD ["python", "workers/pillar3-websec/src/consumer.py"]
