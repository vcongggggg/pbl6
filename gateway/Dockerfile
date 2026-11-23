FROM python:3.12-slim

WORKDIR /app

# Install security updates and runtime requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application source code
COPY . .

# Create non-root user and ensure data directory ownership (INFRA-PBL6-001)
RUN mkdir -p /app/data \
    && groupadd --system --gid 1001 appuser \
    && useradd --system --uid 1001 --gid appuser --home-dir /app --shell /sbin/nologin appuser \
    && chown -R appuser:appuser /app /app/data

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
