# BSN Knowledge Analytics Service Dockerfile
# Task Group 6 monitoring integration patterns

FROM python:3.12-slim as builder

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.8.3

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --extra monitoring --no-dev

# Production stage
FROM python:3.12-slim as production

# Create non-root user
RUN groupadd -r analytics && useradd -r -g analytics analytics

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY src/ ./src/
COPY config/ ./config/

# Create directories
RUN mkdir -p logs data cache metrics \
    && chown -R analytics:analytics /app

# Environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:/app"
ENV PYTHONUNBUFFERED=1

# Performance monitoring settings
ENV METRICS_COLLECTION_INTERVAL=60
ENV PERFORMANCE_ALERT_THRESHOLD=0.95
ENV CACHE_ANALYTICS_TTL=3600
ENV MAX_ANALYTICS_WORKERS=2

USER analytics

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "src.bsn_knowledge.analytics.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info"]
