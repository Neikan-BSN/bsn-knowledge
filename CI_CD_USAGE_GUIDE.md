# BSN Knowledge CI/CD Usage Guide

## Quick Start

BSN Knowledge includes a comprehensive CI/CD suite optimized for knowledge base management systems with search/retrieval validation, content indexing, and query processing performance benchmarks.

### Essential Commands

```bash
# Environment Setup
make install           # Install all dependencies with quality gates
make env-check         # Validate canonical UV environment
make clean-env         # Remove non-canonical environments

# Quality Gates (run all or individual)
make quality-gates     # Run all 4 quality gates
make quality-gate-1    # Environment validation
make quality-gate-2    # Code quality & standards
make quality-gate-3    # Security compliance
make quality-gate-4    # Testing & coverage

# CI/CD Operations
make ci-check          # Pragmatic CI validation (5-8 minutes)
make ci-check-full     # Comprehensive CI with quality gates (15-20 minutes)
```

## BSN Knowledge Specific Features

### Knowledge Base Management Testing

**Core Knowledge Operations:**
```bash
# Knowledge base testing
make test-search       # Search functionality validation
make test-indexing     # Content indexing accuracy
make test-retrieval    # Knowledge retrieval performance
make test-categorization # Content categorization testing

# Knowledge base management
make rebuild-index     # Rebuild search indices
make validate-index    # Validate index integrity
make test-processing   # Test content processing pipeline
```

**Performance Benchmarks:**
- Basic search queries: <100ms response times
- Complex semantic searches: <500ms response times
- Content indexing: 1000+ documents/hour processing
- Knowledge graph updates: <200ms completion
- Search relevance score: >85% for test queries

### Search & Retrieval Validation

**Search Performance Testing:**
```bash
# Search accuracy and performance
make test-search-accuracy        # Search relevance validation
make test-query-performance     # Query processing speed
make test-ranking-algorithms    # Result ranking validation
make test-indexing-pipeline     # Content indexing testing
```

**Content Management Testing:**
```bash
# Content processing pipeline
make test-content-ingestion     # Document ingestion validation
make test-metadata-processing   # Metadata extraction testing
make test-content-categorization # Categorization accuracy
make test-knowledge-relationships # Knowledge graph testing
```

### Knowledge-Specific Commands

**Library Development:**
```bash
# Library management
make build             # Build the knowledge library
make publish-test      # Publish to test PyPI
make publish           # Publish to PyPI

# Documentation
make docs              # Generate documentation
make docs-serve        # Serve documentation locally (http://localhost:8000)
```

## Quality Gates Deep Dive

### Gate 1: Environment Validation

**What it checks:**
- Canonical `.venv` environment setup
- Python 3.12 version compliance
- Knowledge base dependencies
- Database connectivity (SQLite/PostgreSQL)
- Search engine integration

**Troubleshooting:**
```bash
# Fix environment issues
make clean-env && make install

# Check specific components
uv --version              # Should be 0.8.3+
python --version          # Should be 3.12+
# Test database connectivity if applicable
python -c "import sqlite3; print('SQLite OK')"
```

### Gate 2: Code Quality & Standards

**Standards Applied:**
- Ruff formatting with 88-character line limit
- Critical linting (E9, F, B, S error classes only)
- Knowledge management code pattern compliance
- API endpoint standards validation
- Database query optimization analysis

**Common Issues & Fixes:**
```bash
# Fix formatting issues
make format

# Check specific code quality issues
uv run ruff check src/ tests/ --select="E9,F,B,S"
uv run ruff format --check src/ tests/

# Fix import sorting
uv run ruff check --select I src/ tests/ --fix
```

### Gate 3: Security Compliance

**Security Checks:**
- Content access control verification
- Input sanitization for search queries
- Data privacy compliance validation
- Knowledge base security scanning

**Security Issues Resolution:**
```bash
# Run security scans
make security

# Check specific security issues
uv run bandit -r src/ tests/ -f json -o reports/bandit-report.json
uv run safety check

# Update security baseline if needed
make secrets-update
```

### Gate 4: Testing & Coverage

**Testing Requirements:**
- Unit tests: >90% coverage for knowledge components
- Integration tests: Full knowledge base validation
- Performance tests: Search and indexing benchmarks
- End-to-end tests: Complete knowledge workflow validation

**Testing Commands:**
```bash
# Run all tests with coverage
make test

# Run specific test categories
make test-unit         # Unit tests only
make test-integration  # Integration tests

# Knowledge-specific testing
pytest tests/search/       # Search functionality tests
pytest tests/indexing/     # Content indexing tests
pytest tests/knowledge/    # Knowledge management tests
```

## Development Workflow

### Daily Development

**Morning Setup:**
```bash
# Start fresh development session
make env-check         # Verify environment
make validate-index    # Check knowledge base integrity
make test-search       # Validate search functionality
```

**Before Committing:**
```bash
# Quick validation (5-8 minutes)
make ci-check

# Comprehensive validation (15-20 minutes)
make ci-check-full
```

**Feature Development:**
```bash
# Start feature development
git checkout -b feature/enhanced-search-algorithms

# Regular testing during development
make test-unit         # Fast unit tests
make test-search       # Search functionality validation

# Before merge
make quality-gates     # Full quality validation
make test-integration  # Integration testing
```

### Knowledge Base Development Workflow

**Implementing New Search Features:**
1. Implement search algorithm in `src/search/`
2. Add comprehensive tests in `tests/search/`
3. Update indexing pipeline if needed
4. Test search performance: `make test-query-performance`
5. Validate accuracy: `make test-search-accuracy`

**Modifying Content Processing:**
1. Update processing pipeline in `src/processing/`
2. Test content ingestion: `make test-content-ingestion`
3. Validate metadata extraction: `make test-metadata-processing`
4. Check categorization: `make test-content-categorization`

## Troubleshooting Common Issues

### Environment Issues

**"Canonical .venv not found":**
```bash
make clean-env && make install
```

**Library Build Issues:**
```bash
# Check build configuration
uv build --verbose

# Validate pyproject.toml
python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb')))"

# Fix dependency issues
uv sync --all-groups
```

### Knowledge Base Issues

**Search Index Problems:**
```bash
# Rebuild search indices
make rebuild-index

# Validate index integrity
make validate-index

# Check indexing performance
make test-indexing-pipeline

# Debug indexing issues
make debug-ingestion
```

**Search Performance Issues:**
```bash
# Analyze search performance
make analyze-queries

# Optimize search algorithms
make optimize-search

# Test query performance
make test-query-performance

# Check search relevance
make test-search-accuracy
```

### Content Processing Issues

**Content Ingestion Failures:**
```bash
# Test content processing pipeline
make test-processing

# Debug ingestion issues
make debug-ingestion

# Check metadata extraction
make test-metadata-processing

# Validate categorization
make test-content-categorization
```

**Knowledge Graph Issues:**
```bash
# Test knowledge relationships
make test-knowledge-relationships

# Validate graph consistency
make validate-knowledge-graph

# Check relationship accuracy
make test-relationship-accuracy
```

## Performance Optimization

### Search Performance Optimization

**Query Optimization:**
```bash
# Analyze slow queries
make analyze-slow-queries

# Optimize search algorithms
# Review src/search/ for optimization opportunities

# Test performance improvements
make test-query-performance

# Benchmark search operations
make benchmark-search
```

**Index Optimization:**
```bash
# Optimize indexing pipeline
make optimize-indexing

# Test indexing performance
make test-indexing-performance

# Monitor indexing throughput
make monitor-indexing
```

### Content Processing Optimization

**Processing Pipeline Optimization:**
```bash
# Analyze processing bottlenecks
make analyze-processing-bottlenecks

# Optimize content extraction
# Review src/processing/ for improvements

# Test processing performance
make test-processing-performance
```

**Memory Optimization:**
```bash
# Monitor memory usage during processing
python -m memory_profiler src/processing/main.py

# Optimize memory usage patterns
# Review large data structure handling

# Test memory efficiency
make test-memory-usage
```

## Advanced Usage

### Custom Search Algorithms

**Implementing Custom Search:**
```python
# Add to src/search/
class CustomSearchAlgorithm:
    def search(self, query, index):
        # Custom search logic
        pass
```

**Testing Custom Search:**
```bash
# Create custom search tests
# tests/search/test_custom_search.py

pytest tests/search/test_custom_search.py -v
```

### Advanced Content Processing

**Custom Content Processors:**
```python
# src/processing/custom_processor.py
class CustomContentProcessor:
    def process(self, content):
        # Custom processing logic
        pass
```

**Custom Categorization:**
```python
# src/categorization/custom_categorizer.py
class CustomCategorizer:
    def categorize(self, content):
        # Custom categorization logic
        pass
```

### Knowledge Graph Extensions

**Custom Relationship Types:**
```python
# src/knowledge/custom_relationships.py
class CustomRelationshipExtractor:
    def extract_relationships(self, content):
        # Custom relationship extraction
        pass
```

### CI/CD Customization

**Custom CI Commands:**
```makefile
# Add to Makefile
ci-check-knowledge: env-check
	@echo "🔍 Running BSN Knowledge specific CI checks"
	$(MAKE) quality-gates
	$(MAKE) test-search
	$(MAKE) test-indexing
	$(MAKE) validate-index
```

**Performance Monitoring:**
```bash
# Continuous performance monitoring
make monitor-search-performance &

# Alert on performance degradation
make setup-performance-alerts
```

## Library Management

### Building and Publishing

**Development Build:**
```bash
# Build library for testing
make build

# Check build artifacts
ls dist/

# Install locally for testing
uv add ./dist/bsn_knowledge-*.whl
```

**Publishing Workflow:**
```bash
# Test publishing
make publish-test

# Verify test installation
pip install -i https://test.pypi.org/simple/ bsn-knowledge

# Production publishing
make publish
```

### Documentation Management

**Documentation Generation:**
```bash
# Generate documentation
make docs

# Serve documentation locally
make docs-serve
# Access at http://localhost:8000

# Deploy documentation (if configured)
make docs-deploy
```

**Documentation Testing:**
```bash
# Test documentation examples
python -m doctest docs/examples/*.py

# Validate documentation links
make validate-docs-links

# Check documentation coverage
make docs-coverage
```

## Integration Patterns

### Database Integration

**SQLite Integration:**
```python
# src/storage/sqlite_backend.py
import sqlite3

class SQLiteKnowledgeBase:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)

    def store_knowledge(self, content):
        # Store knowledge in SQLite
        pass
```

**PostgreSQL Integration:**
```python
# src/storage/postgres_backend.py
import psycopg2

class PostgreSQLKnowledgeBase:
    def __init__(self, connection_string):
        self.conn = psycopg2.connect(connection_string)

    def store_knowledge(self, content):
        # Store knowledge in PostgreSQL
        pass
```

### Search Engine Integration

**Elasticsearch Integration:**
```python
# src/search/elasticsearch_backend.py
from elasticsearch import Elasticsearch

class ElasticsearchSearchEngine:
    def __init__(self, hosts):
        self.es = Elasticsearch(hosts)

    def search(self, query):
        # Search using Elasticsearch
        pass
```

## Best Practices

### Development Best Practices

1. **Always start with environment validation**: `make env-check`
2. **Test search functionality regularly**: `make test-search`
3. **Validate content processing**: `make test-processing`
4. **Monitor index integrity**: `make validate-index`
5. **Check performance regularly**: `make test-query-performance`

### CI/CD Best Practices

1. **Use pragmatic CI for regular development**: `make ci-check`
2. **Full CI for releases and merges**: `make ci-check-full`
3. **Test knowledge base features thoroughly**: Regular validation
4. **Monitor search performance**: Continuous performance monitoring
5. **Validate content quality**: Regular accuracy testing

### Knowledge Management Best Practices

1. **Test search algorithms in isolation**: Unit tests for search components
2. **Validate content processing pipelines**: End-to-end processing tests
3. **Monitor knowledge quality**: Regular accuracy and relevance testing
4. **Optimize for performance**: <100ms search response times
5. **Document knowledge schemas**: Clear data structure documentation

### Library Development Best Practices

1. **Version management**: Semantic versioning for releases
2. **Dependency management**: Minimal external dependencies
3. **Documentation**: Comprehensive API documentation
4. **Testing**: >90% test coverage for public APIs
5. **Backwards compatibility**: Careful API evolution

---

*For additional help, see the [Cross-Project CI/CD Best Practices Guide](../workspace-infrastructure/docs/CROSS_PROJECT_CICD_BEST_PRACTICES_GUIDE.md)*
