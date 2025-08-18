# BSN Knowledge API Gateway Dockerfile
# Task Group 5 optimization patterns with multi-stage build

# Build stage - Python 3.12 with UV 0.8.3
FROM python:3.12-slim as builder

# Install system dependencies and UV
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.8.3

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Production stage - optimized size
FROM python:3.12-slim as production

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create directories for logs and data
RUN mkdir -p logs data cache \
    && chown -R appuser:appuser /app

# Set up PATH to use virtual environment
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:/app"
ENV PYTHONUNBUFFERED=1

# Security hardening
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "src.bsn_knowledge.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--access-log", \
     "--log-level", "info"]

# Development stage - includes dev dependencies
FROM builder as development

# Install development dependencies
RUN uv sync --frozen

# Install development tools
RUN apt-get update && apt-get install -y \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Copy all source code including tests
COPY . .

# Set development environment
ENV ENVIRONMENT=development
ENV DEBUG=true
ENV LOG_LEVEL=DEBUG

# Development command with auto-reload
CMD ["uvicorn", "src.bsn_knowledge.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--log-level", "debug"]

# Testing stage - includes test dependencies
FROM development as testing

# Install testing tools
RUN uv sync --group test

# Run tests
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=html"]