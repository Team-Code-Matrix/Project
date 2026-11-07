# ==============================================================================
# Pillar 1 Worker: Intelligent Phishing Detonation & Computer Vision
# Monorepo Build Context: ./backend
# ==============================================================================

FROM mcr.microsoft.com/playwright/python:v1.43.0-jammy

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/app

COPY workers/pillar1-phishing/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browser dependencies
RUN playwright install chromium

# Copy shared libraries and worker source
COPY shared ./shared
COPY workers/pillar1-phishing ./workers/pillar1-phishing

CMD ["python", "workers/pillar1-phishing/src/consumer.py"]
