# bsn-knowledge - Standardized Multi-Stage Dockerfile
# BSN Knowledge Base - Educational resource management system
# Security-optimized container with UV package management
# Based on Docker best practices and Context7 research

# ===== STAGE 1: Base Python with UV =====
FROM python:3.12-slim-bookworm AS base

# Build arguments
ARG PYTHON_VERSION=3.12
ARG UV_VERSION=0.8.3
ARG PROJECT_NAME="bsn-knowledge"

# Environment variables for Python optimization
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Security: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# System dependencies and security updates
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    curl \
    git \
    # library specific dependencies
     \
    # Security updates
    && apt-get upgrade -y \
    # Cleanup to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install UV package manager
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv && \
    chmod +x /usr/local/bin/uv

# Verify UV installation
RUN uv --version

# Set working directory
WORKDIR /app

# Copy UV configuration files first (for better caching)
COPY pyproject.toml uv.lock* README.md ./

# ===== STAGE 2: Dependency Installation =====
FROM base AS dependencies

# Install Python dependencies with UV
RUN uv sync --frozen --no-dev

# ===== STAGE 3: Development Dependencies =====
FROM dependencies AS development-deps

# Install development dependencies
RUN uv sync --frozen --all-extras

# Install additional development tools
RUN uv tool install ruff && \
    uv tool install mypy && \
    uv tool install pytest

# ===== STAGE 4: Application Code =====
FROM dependencies AS app-base

# Copy application source code
COPY src/ ./src/
COPY scripts/ ./
COPY config/ ./

# Security: Change ownership to non-root user
RUN chown -R appuser:appuser /app

# ===== STAGE 5: Production Image =====
FROM app-base AS production

# Install production system dependencies
RUN apt-get update && apt-get install -y \
    # Runtime dependencies only
    curl \
    # Security updates
    && apt-get upgrade -y \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Security hardening
RUN find /app -type f -name "*.py" -exec chmod 644 {} \; && \
    find /app -type d -exec chmod 755 {} \; && \
    chmod +x /app/scripts/*.sh 2>/dev/null || true

# Health check script
COPY docker-healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/healthcheck.sh && \
    chown appuser:appuser /usr/local/bin/healthcheck.sh

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Production command
CMD ["uv", "run", "python", "-m", "src.main"]

# ===== STAGE 6: Development Image =====
FROM development-deps AS development

# Install additional development tools
RUN apt-get update && apt-get install -y \
    # Development tools
    vim \
    curl \
    netcat-traditional \
    curl \
    # Debugging tools
    strace \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy application source code
COPY src/ ./src/
COPY tests/ ./tests/ 2>/dev/null || mkdir -p ./tests/
COPY scripts/ ./
COPY config/ ./
COPY .env.example ./.env 2>/dev/null || touch ./.env

# Security: Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Development command with hot reload
CMD ["uv", "run", "python", "-m", "src.main", "--dev"]

# ===== STAGE 7: Testing Image =====
FROM development-deps AS testing

# Copy all source code and tests
COPY . .

# Security: Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Test command
CMD ["uv", "run", "pytest", "-v", "--cov=src"]

# ===== BUILD METADATA =====
LABEL maintainer="Library Development Team" \
      version="0.1.0" \
      description="BSN Knowledge Base - Educational resource management system" \
      security.scan="enabled" \
      build.multi-arch="linux/amd64,linux/arm64" \
      framework="python-library" \
      package-manager="uv" \
      python.version="3.12"

# Build information
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL build.date="${BUILD_DATE}" \
      vcs.ref="${VCS_REF}" \
      version="${VERSION}"
