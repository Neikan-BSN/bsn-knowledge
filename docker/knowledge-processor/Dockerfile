# BSN Knowledge Processor Dockerfile
# Task Group 5 optimization with medical NLP dependencies

# Build stage with medical NLP models
FROM python:3.12-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.8.3

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies including medical NLP
RUN uv sync --frozen --extra medical-nlp --no-dev

# Download medical models in build stage
RUN python -c "import spacy; spacy.cli.download('en_core_web_sm')" && \
    python -c "import spacy; spacy.cli.download('en_core_sci_sm')" || true

# Production stage
FROM python:3.12-slim as production

# Create non-root user
RUN groupadd -r processor && useradd -r -g processor processor

# Install runtime dependencies for medical processing
RUN apt-get update && apt-get install -y \
    curl \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy virtual environment and models from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /root/.local/share/spacy /home/processor/.local/share/spacy

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create directories
RUN mkdir -p logs cache models data temp \
    && chown -R processor:processor /app \
    && chown -R processor:processor /home/processor

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:/app"
ENV PYTHONUNBUFFERED=1
ENV SPACY_DATA_DIR="/home/processor/.local/share/spacy"

# Resource limits for medical processing
ENV OMP_NUM_THREADS=2
ENV MEMORY_LIMIT=2G
ENV MAX_CONCURRENT_PROCESSES=4

# Security settings
USER processor

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["uvicorn", "src.bsn_knowledge.processor.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--log-level", "info"]

# Development stage
FROM builder as development

# Install development dependencies
RUN uv sync --frozen --extra medical-nlp

# Install additional development tools
RUN apt-get update && apt-get install -y \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Copy all source
COPY . .

ENV ENVIRONMENT=development
ENV DEBUG=true
ENV LOG_LEVEL=DEBUG

# Development command with auto-reload
CMD ["uvicorn", "src.bsn_knowledge.processor.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--log-level", "debug"]

# Testing stage
FROM development as testing

RUN uv sync --group test

CMD ["pytest", "tests/", "-v", "--cov=src"]