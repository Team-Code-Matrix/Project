# ==============================================================================
# Pillar 4 Worker: Collaborative Threat Intelligence & STIX 2.1 / TAXII 2.1
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

COPY workers/pillar4-cti/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared libraries and worker source
COPY shared ./shared
COPY workers/pillar4-cti ./workers/pillar4-cti

CMD ["python", "workers/pillar4-cti/src/consumer.py"]
