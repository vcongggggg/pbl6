FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 \
    PYTHONPATH=/app/ml-engine \
    ML_ARTIFACTS_DIR=/app/ml-engine/artifacts \
    ML_HEALTH_HOST=0.0.0.0 \
    ML_HEALTH_PORT=8001

WORKDIR /app/ml-engine

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "numpy>=1.26.0" "xgboost>=2.0.0"

COPY health_server.py ./health_server.py

RUN groupadd --system --gid 1001 appuser \
    && useradd --system --uid 1001 --gid appuser --home-dir /app --shell /sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health')"]

CMD ["python", "health_server.py"]
