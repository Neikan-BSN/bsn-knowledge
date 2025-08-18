# bsn-knowledge - BSN Knowledge Base - Educational resource management system
# Standardized Makefile Template v2.0 for Phase 2 Day 2
# Follows workspace standards with UV 0.8.3 + Python 3.12 canonical patterns

.PHONY: help install clean lint format test security run dev docs deploy backup env-check ci-check

# ================================================================================
# CANONICAL ENVIRONMENT VARIABLES (PHASE 2 STANDARD)
# ================================================================================
export UV_PROJECT_ENVIRONMENT := .venv
export UV_PYTHON_VERSION := 3.12
export UV_WORKSPACE_ROOT := .
export VIRTUAL_ENV := $(PWD)/.venv

# ================================================================================
# PROJECT IDENTIFICATION
# ================================================================================
PROJECT_NAME := bsn-knowledge
PROJECT_TYPE := Python Library
PROJECT_VERSION := $(shell uv run python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])" 2>/dev/null || echo "unknown")

# ================================================================================
# DEFAULT TARGET - ENHANCED HELP SYSTEM
# ================================================================================
help: ## Show this help message with categorized targets
	@echo "$(PROJECT_NAME) - BSN Knowledge Base - Educational resource management system"
	@echo "================================================================================"
	@echo ""
	@echo "🔧 Environment: $(VIRTUAL_ENV)"
	@echo "🐍 Python: $(UV_PYTHON_VERSION)"
	@echo "📦 Version: $(PROJECT_VERSION)"
	@echo "🏗️  Type: $(PROJECT_TYPE)"
	@echo ""
	@echo "🎯 Essential Commands:"
	@echo "  make install     - Install all dependencies with UV"
	@echo "  make test        - Run comprehensive test suite"
	@echo "  make lint        - Check code quality (critical issues only)"
	@echo "  make format      - Format code with ruff"
	@echo "  make ci-check    - Run all CI checks locally"
	@echo ""
	@echo "📋 All Available Targets (by category):"
	@echo ""
	@echo "🏗️  Environment Management:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && $$2 ~ /(environment|install|setup|clean)/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "🔍 Code Quality:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && $$2 ~ /(lint|format|security|test)/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "🚀 Development:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && $$2 ~ /(run|dev|serve|start)/ {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ================================================================================
# ENVIRONMENT VALIDATION & SETUP
# ================================================================================
env-check: ## Validate canonical UV environment setup
	@echo "🔍 Checking canonical UV environment for $(PROJECT_NAME)..."
	@if [ ! -d ".venv" ]; then \
		echo "❌ Canonical .venv not found. Run 'make install' first."; \
		exit 1; \
	fi
	@if [ -d "venv" ] || [ -d ".env" ] || [ -d "env" ]; then \
		echo "❌ Multiple virtual environments detected! Only .venv is allowed."; \
		echo "🧹 Remove: venv/, .env/, env/ directories"; \
		exit 1; \
	fi
	@echo "🐍 Python version: $$(uv run python --version)"
	@echo "📦 UV version: $$(uv --version)"
	@echo "✅ Canonical environment validated"

# Environment setup
install: clean-env ## Install all dependencies with UV (canonical environment)
	@echo "📦 Setting up canonical UV environment for $(PROJECT_NAME)..."
	@echo "🐍 Python version: $(UV_PYTHON_VERSION)"
	uv python pin $(UV_PYTHON_VERSION)
	@rm -f uv.lock
	uv sync --all-groups
	@if git rev-parse --git-dir >/dev/null 2>&1; then \
		echo "🪝 Installing pre-commit hooks..."; \
		uv run pre-commit install; \
	else \
		echo "⚠️ Not a Git repository - skipping pre-commit hooks"; \
	fi
	@echo "📍 Canonical environment created at: $(VIRTUAL_ENV)"
	@echo "✅ Installation complete"

install-dev: env-check ## Install development dependencies only
	@echo "📦 Installing development dependencies..."
	uv sync --group dev --group test --group lint
	@if git rev-parse --git-dir >/dev/null 2>&1; then \
		uv run pre-commit install; \
	fi

# Clean up non-canonical environments
clean-env: ## Remove all non-canonical virtual environments
	@echo "🧹 Cleaning non-canonical virtual environments..."
	@rm -rf venv/ .env/ env/ .venv-old/ || true
	@echo "✅ Environment cleanup complete"

# ================================================================================
# CODE QUALITY - PRAGMATIC CI/CD PATTERNS
# ================================================================================
lint: env-check ## Run critical linting checks only
	@echo "🔍 Running critical lint checks (blocking issues only)..."
	uv run ruff check src/ tests/ --select="E9,F,B,S" --ignore="B008,S314,S324,B017"
	@echo "✅ No critical issues found"

lint-full: env-check ## Run comprehensive linting (advisory)
	@echo "🔍 Running full lint analysis (advisory)..."
	uv run ruff check src/ tests/ || echo "⚠️ Style issues found (not blocking)"
	uv run mypy src/ tests/ || echo "⚠️ Type issues found (advisory)"

format: env-check ## Format code with ruff
	@echo "🎨 Formatting code..."
	uv run ruff format src/ tests/

format-check: env-check ## Check if code is properly formatted
	@echo "✅ Checking code formatting..."
	uv run ruff format --check src/ tests/

# ================================================================================
# TESTING (WITH ENVIRONMENT VALIDATION)
# ================================================================================
test: env-check ## Run all tests
	@echo "🧪 Running comprehensive test suite..."
	uv run pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

test-unit: env-check ## Run unit tests only
	@echo "🧪 Running unit tests..."
	uv run pytest tests/unit/ -v

test-integration: env-check ## Run integration tests
	@echo "🧪 Running integration tests..."
	uv run pytest tests/integration/ -v

# ================================================================================
# SECURITY (WITH ENVIRONMENT VALIDATION)
# ================================================================================
security: env-check ## Run security scans
	@echo "🔒 Running security scans..."
	mkdir -p reports
	uv run bandit -r src/ tests/ -f json -o reports/bandit-report.json
	uv run safety check
	@if [ -f .secrets.baseline ]; then \
		uv run detect-secrets scan --baseline .secrets.baseline; \
	else \
		echo "⚠️ No secrets baseline found - creating one..."; \
		uv run detect-secrets scan --update .secrets.baseline; \
	fi

secrets-update: env-check ## Update secrets baseline
	@echo "🔐 Updating secrets baseline..."
	uv run detect-secrets scan --update .secrets.baseline

# ================================================================================
# BSN KNOWLEDGE SPECIFIC OPERATIONS
# ================================================================================
run: env-check ## Start the knowledge base server
	@echo "🚀 Starting BSN Knowledge server..."
	uv run python src/main.py

dev: env-check ## Run in development mode
	@echo "🔧 Starting BSN Knowledge in development mode..."
	uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

rebuild-index: env-check ## Rebuild search indices
	@echo "🔄 Rebuilding search indices..."
	uv run python src/scripts/rebuild_index.py

validate-index: env-check ## Validate index integrity
	@echo "✅ Validating index integrity..."
	uv run python src/scripts/validate_index.py

test-search: env-check ## Test search functionality
	@echo "🔍 Testing search functionality..."
	uv run pytest tests/test_search.py -v

test-indexing: env-check ## Test content indexing
	@echo "📚 Testing content indexing..."
	uv run pytest tests/test_indexing.py -v

test-retrieval: env-check ## Test knowledge retrieval
	@echo "🎯 Testing knowledge retrieval..."
	uv run pytest tests/test_retrieval.py -v

# ================================================================================
# MCP INTEGRATION
# ================================================================================
mcp-install: ## Install MCP servers
	@echo "🔧 Installing MCP servers..."
	../workspace-infrastructure/tools/coordination/mcp_setup_script.sh

mcp-test: ## Test MCP server connectivity
	@echo "🧪 Testing MCP servers..."
	../workspace-infrastructure/tools/coordination/mcp-coordinator status

# ================================================================================
# CLEAN UP (INCLUDES ENVIRONMENT CLEANUP)
# ================================================================================
clean: clean-env ## Clean build artifacts and cache
	@echo "🧹 Cleaning build artifacts..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf dist/ build/ .uv-cache/
	@echo "🗑️ Cleaned all artifacts and non-canonical environments"

# ================================================================================
# CI CHECKS
# ================================================================================
ci-check: ## Run all CI checks locally (pragmatic version)
	@echo "🔍 Running pragmatic CI check suite for $(PROJECT_NAME)..."
	$(MAKE) env-check
	$(MAKE) format-check
	$(MAKE) lint
	$(MAKE) security
	$(MAKE) test
	@echo "✅ All CI checks passed!"

# ================================================================================
# VERSION MANAGEMENT
# ================================================================================
version: ## Show current version and environment info
	@echo "📦 $(PROJECT_NAME) Information:"
	@echo "Version: $(PROJECT_VERSION)"
	@echo "Python: $$(uv run python --version)"
	@echo "UV: $$(uv --version)"
	@echo "Environment: $(VIRTUAL_ENV)"

# ================================================================================
# PROJECT-SPECIFIC EXTENSIONS
# ================================================================================
# ================================================================================
# LIBRARY MANAGEMENT
# ================================================================================
build: env-check ## Build the library
	@echo "🏗️ Building bsn-knowledge library..."
	uv build

publish-test: env-check ## Publish to test PyPI
	@echo "🚀 Publishing bsn-knowledge to test PyPI..."
	uv publish --repository testpypi

publish: env-check ## Publish to PyPI
	@echo "🚀 Publishing bsn-knowledge to PyPI..."
	uv publish

# ================================================================================
# DOCUMENTATION
# ================================================================================
docs: env-check ## Generate documentation
	@echo "📚 Generating documentation..."
	uv run mkdocs build

docs-serve: env-check ## Serve documentation locally
	@echo "📖 Serving documentation at http://localhost:8000"
	uv run mkdocs serve
