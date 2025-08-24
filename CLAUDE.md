# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

This is the **bsn-knowledge** project, part of a multi-project Python development workspace focused on AI-assisted development tools, RAG systems, and intelligent automation.

## MCP Server Configuration (14 Servers)

### Available Servers
- **Core Development**: filesystem, git, memory, context7
- **Code Quality**: eslint, ripgrep  
- **Database Operations**: sqlite, sqlite-secondary, postgres
- **AI/ML Capabilities**: sequential-thinking, elevenlabs
- **Web Operations**: fetch, playwright
- **Local Services**: codanna-https (SSE)

### Server Descriptions
- **filesystem**: File system operations for knowledge base content and indexing
- **git**: Git operations for version control of knowledge management system
- **memory**: Memory operations for search context and knowledge retrieval state
- **sqlite**: Primary database operations for knowledge base storage and indexing
- **sqlite-secondary**: Secondary database for search analytics and performance tracking
- **context7**: Context research for knowledge management best practices and patterns
- **ripgrep**: Fast code search across knowledge base modules and content processing
- **eslint**: Code quality checking for any JavaScript/TypeScript search interfaces
- **fetch**: HTTP operations for external knowledge source integrations
- **sequential-thinking**: AI planning for complex knowledge organization workflows
- **playwright**: Web automation for testing search interfaces and knowledge workflows
- **postgres**: PostgreSQL operations for production-scale knowledge storage
- **elevenlabs**: Text-to-speech for accessibility in knowledge base interfaces
- **codanna-https**: Local code analysis server via SSE protocol
  - URL: https://127.0.0.1:8443/mcp/sse
  - Protocol: Server-Sent Events (SSE)
  - Dependency: Requires local codanna service running

### MCP Operations
```bash
# Install and test all 14 MCP servers
make mcp-install && make mcp-test

# Quick health check for all servers
../workspace-infrastructure/tools/coordination/mcp-coordinator status

# Comprehensive validation
../workspace-infrastructure/tools/coordination/mcp-coordinator validate --level=standard

# Export health report
../workspace-infrastructure/tools/coordination/mcp-coordinator export
```

### Project Type
- **Architecture**: knowledge_base
- **Primary Focus**: Knowledge base management and search optimization
- **Technology Stack**: Python 3.11+, FastAPI, asyncio

### Key Features
- Knowledge base management system
- Search and retrieval optimization
- Content indexing and categorization
- Query processing and result ranking

## Development Guidelines

### Code Quality Standards
- **Python Version**: 3.11+
- **Package Management**: UV (preferred)
- **Code Formatting**: Black + Ruff
- **Type Checking**: MyPy
- **Testing**: pytest with >90% coverage
- **Security**: Bandit scanning

### Project Structure
```
bsn-knowledge/
├── src/                    # Main source code
├── tests/                  # Test suite
├── docs/                   # Documentation
├── scripts/                # Utility scripts
├── Makefile               # Build automation
├── pyproject.toml         # Project configuration
└── README.md              # Project overview
```

### Common Tasks
```bash
# Setup environment
uv sync --all-extras

# Run tests
make test

# Code quality checks
make lint && make format

# Documentation generation
make docs

# Full CI pipeline
make ci-check
```

### Documentation Automation
This project uses automated documentation generation:
- ARCHITECTURE.md: Auto-generated from code analysis
- TECHNICAL_SPECIFICATIONS.md: Generated from API/DB schemas
- Documentation pipeline triggered by code changes

### Integration Points
- **MCP Servers**: MCP integration in progress
- **CI/CD**: GitHub Actions with standardized workflows
- **Quality Gates**: Automated testing and validation
- **Cross-Project**: Integrated with workspace coordination

## AI Assistant Guidelines

### Development Approach
- Follow established patterns from existing codebase
- Use MCP tools for workspace coordination
- Apply quality gates at multiple levels
- Leverage domain-specific expertise

### Code Generation
- Maintain consistency with project architecture
- Follow existing naming conventions
- Include comprehensive error handling
- Add appropriate type hints and documentation

### Testing Strategy
- Write tests for all new functionality
- Maintain >90% test coverage
- Include integration tests for API endpoints
- Test error conditions and edge cases

## CI/CD Implementation & Testing

### Deployed CI/CD Workflows
BSN Knowledge now includes a complete standardized CI/CD suite following Phase 2 deployment patterns:

**Core CI/CD Features:**
- Knowledge base testing with search/retrieval validation
- Content indexing and categorization pipeline testing
- Query processing performance benchmarks
- Result ranking accuracy validation
- MCP integration testing for knowledge operations

### Workflow Structure
```bash
# Environment Management
make env-check          # Validate canonical UV environment
make install           # Install all dependencies with quality gates
make clean-env         # Remove non-canonical environments

# Quality Gates (4-tier validation)
make quality-gates     # Run all 4 quality gates
make quality-gate-1    # Environment & setup validation
make quality-gate-2    # Code quality & standards
make quality-gate-3    # Security validation & compliance
make quality-gate-4    # Testing & coverage validation

# Knowledge Base Testing
make test-search       # Search functionality validation
make test-indexing     # Content indexing accuracy
make test-retrieval    # Knowledge retrieval performance
```

### Project-Specific CI/CD Customizations

**Knowledge Base Management Testing:**
- Content indexing accuracy and performance testing
- Search query processing with relevance scoring
- Knowledge categorization algorithm validation
- Result ranking system performance benchmarks
- Content freshness and update propagation testing

**Search & Retrieval Validation:**
- Query parsing and normalization testing
- Semantic search accuracy validation
- Full-text search performance benchmarks
- Filter and faceting functionality testing
- Auto-completion and suggestion system validation

**Content Processing Pipeline:**
- Document ingestion and parsing validation
- Metadata extraction accuracy testing
- Content transformation pipeline testing
- Knowledge graph relationship validation
- Version control and change tracking testing

### Quality Gates Implementation

**Gate 1: Environment Validation**
- Python 3.12 standardization compliance
- UV canonical environment verification
- Database connectivity testing (SQLite/PostgreSQL)
- Search engine integration validation

**Gate 2: Code Quality & Standards**
- Knowledge management code pattern compliance
- API endpoint standards validation
- Database query optimization analysis
- Search algorithm implementation quality

**Gate 3: Security & Compliance**
- Content access control verification
- Input sanitization for search queries
- Data privacy compliance validation
- Knowledge base security scanning

**Gate 4: Testing & Coverage**
- Knowledge base functionality testing with >90% coverage
- Integration testing for all BSN components
- Performance testing under realistic query loads
- End-to-end knowledge workflow validation

### Knowledge-Specific Testing Patterns

**Search Performance Testing:**
```bash
# Test search accuracy
make test-search-accuracy

# Test query performance
make test-query-performance

# Test result ranking
make test-ranking-algorithms

# Test content indexing
make test-indexing-pipeline
```

**Content Management Testing:**
```bash
# Test content ingestion
make test-content-ingestion

# Test metadata extraction
make test-metadata-processing

# Test categorization
make test-content-categorization

# Test knowledge graph
make test-knowledge-relationships
```

### Performance Standards Validation

**Search Performance:**
- Basic search queries must complete within 100ms
- Complex semantic searches within 500ms
- Content indexing must process 1000+ documents/hour
- Knowledge graph updates within 200ms

**Accuracy Metrics:**
- Search relevance score >85% for test queries
- Content categorization accuracy >90%
- Metadata extraction precision >95%
- Knowledge relationship accuracy >88%

### Troubleshooting CI/CD Issues

**Common Knowledge Base Issues:**
```bash
# Search index issues
make rebuild-index     # Rebuild search indices
make validate-index    # Validate index integrity

# Content processing failures
make test-processing   # Test content processing pipeline
make debug-ingestion   # Debug content ingestion issues

# Performance issues
make analyze-queries   # Analyze slow queries
make optimize-search   # Optimize search performance
```

**Knowledge Base Debugging:**
- Use search logs in `/logs/search-*.log` for query issues
- Check indexing performance metrics for bottlenecks
- Monitor content processing pipeline for failures
- Validate knowledge graph consistency and relationships

### Deployment Validation

**Pre-Deployment Checks:**
```bash
make ci-check          # Pragmatic CI validation
make ci-check-full     # Comprehensive CI with quality gates
make deployment-check  # Knowledge base deployment readiness
```

**Post-Deployment Verification:**
- Search functionality validation
- Content indexing pipeline activation
- Knowledge graph integrity verification
- Performance baseline establishment

---

*This file is part of the standardized workspace documentation system and is auto-maintained.*


---

## MCP Server Configuration

This project is configured with **Medical Documentation Systems** MCP integration.
Medical device documentation and OCR processing with safety validation

### Essential MCP Servers

These servers are required for core functionality:

- **filesystem**: Core functionality
- **git**: Git version control operations and repository management
- **sqlite**: Core functionality

### Recommended MCP Servers

These servers enhance project capabilities:

- **code-checker**: Enhanced functionality
- **github**: github server functionality

### Optional MCP Servers

These servers provide additional features:

- **docker**: docker server functionality
- **fetch**: fetch server functionality
- **memory**: Persistent memory storage and knowledge graphs

### Configuration Examples

```bash
# Install and configure MCP servers for this project
cd /home/user01/projects/workspace-tools
./configure-mcp.sh

# Select this project and choose recommended servers
# Project type: Medical Documentation Systems
```

```bash
# Required environment variables:
export DATABASE_PATH="your_project_root/data/medical_project_name.db"
export SQLITE_EXTENSIONS="json1,fts5"
export ENCRYPTION="true"
export BACKUP_PATH="your_project_root/secure_backups"
export ALLOWED_DIRECTORIES="your_project_root/documents,project_root/processed,project_root/data"
export MAX_FILE_SIZE="50MB"
export ALLOWED_EXTENSIONS=".pdf,.jpg,.png,.tiff,.dcm,.json"
export AUDIT_LOG="true"
export ENABLE_SECURITY_CHECKS="true"
export HIPAA_COMPLIANCE="true"
export PII_DETECTION="true"
```

### Usage Patterns

```bash
# Medical Documentation Operations
"Process medical documents with OCR validation"
"Ensure HIPAA compliance in document handling"
"Validate clinical terminology and accuracy"
"Secure storage of sensitive medical information"
```

### Troubleshooting

#### Common Issues

**MCP Server Connection Issues:**
```bash
# Check server status
cd /home/user01/projects/workspace-tools
./configure-mcp.sh --test-connection

# Restart problematic servers
./configure-mcp.sh --restart-servers
```

**Environment Variable Issues:**
```bash
# Verify environment setup
echo $CLAUDE_CONFIG_PATH
cat ~/.claude.json | jq '.mcpServers'

# Reload configuration
source ~/.bashrc
./configure-mcp.sh --reload-config
```

**WSL-Specific Issues:**
```bash
# Check WSL interoperability
wsl.exe --version

# Verify Node.js access
which node && node --version
which npm && npm --version
```
