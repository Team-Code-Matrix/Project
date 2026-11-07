# ==============================================================================
# Pillar 2 Worker: Cryptographic Trust, PKI & Certificate Validation
# Monorepo Build Context: ./backend
# ==============================================================================

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY workers/pillar2-pki/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared libraries and worker source
COPY shared ./shared
COPY workers/pillar2-pki ./workers/pillar2-pki

CMD ["python", "workers/pillar2-pki/src/consumer.py"]
