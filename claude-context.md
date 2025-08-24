# Claude Context File - BSN Knowledge

## Environment
- **OS**: WSL2 Ubuntu 22.04 on Windows 11
- **Shell**: bash (default WSL shell)
- **Terminal**: Windows Terminal / VS Code integrated terminal
- **Working Directory**: `/home/user01/projects/bsn-knowledge`
- **Windows Mount Point**: `/mnt/c/Users/user01/`
- **Python Version**: Python 3.12.3
- **Package Manager**: uv 0.8.3 (preferred over pip)
- **Docker Version**: Docker 28.3.3

## Project Details
- **Project Type**: Educational resource management system for nursing students
- **Primary Language**: Python 3.12+
- **Framework/Stack**: FastAPI + uvicorn, SQLAlchemy, Redis, PostgreSQL
- **Package Manager**: uv (required - NOT pip)
- **Architecture**: Knowledge base management with search optimization
- **Domain Focus**: BSN nursing education content, competency tracking, assessment framework

## Key Technologies & Versions
- **FastAPI**: >=0.110.0 (async API framework)
- **uvicorn**: >=0.29.0 (ASGI server)
- **Pydantic**: >=2.7.0 (data validation)
- **SQLAlchemy**: >=2.0.0 (ORM with async support)
- **Alembic**: >=1.13.0 (database migrations)
- **Redis**: >=5.0.0 (caching and session management)
- **PostgreSQL**: Database for knowledge storage
- **RAGnostic**: Enhanced knowledge retrieval integration

## Project Structure
```
/home/user01/projects/bsn-knowledge/
├── src/                               # Main source code
│   ├── api/                          # FastAPI application
│   │   ├── main.py                   # Application entry point
│   │   └── routers/                  # API route modules
│   │       ├── adaptive_learning.py  # Adaptive learning endpoints
│   │       ├── quizzes.py           # Quiz management API
│   │       └── study_guides.py      # Study guide API
│   ├── models/                       # Data models
│   │   ├── educational_content.py   # Core content models
│   │   ├── student_progress.py      # Progress tracking models
│   │   └── assessment_models.py     # Assessment data models
│   ├── generators/                   # Content generators
│   │   ├── nclex_generator.py       # NCLEX question generation
│   │   ├── study_guide_generator.py # Study guide creation
│   │   └── quiz_generator.py        # Quiz content generation
│   ├── assessment/                   # Assessment framework
│   │   ├── competency_framework.py  # Competency tracking
│   │   ├── progress_tracker.py      # Student progress analysis
│   │   └── adaptive_engine.py       # Adaptive learning algorithms
│   ├── services/                     # Business services
│   │   ├── ragnostic_client.py      # RAGnostic integration
│   │   ├── content_service.py       # Content management
│   │   └── assessment_service.py    # Assessment operations
│   └── utils/                        # Utilities
│       ├── medical_validators.py    # Medical content validation
│       ├── security_utils.py        # Security and compliance
│       └── database.py              # Database configuration
├── tests/                            # Comprehensive test suite
│   ├── unit/                        # Unit tests
│   ├── integration/                 # Integration tests
│   └── conftest.py                  # Test configuration
├── docs/                            # Documentation
├── scripts/                         # Utility scripts
├── docker/                          # Docker configurations
├── .github/                         # GitHub Actions workflows
├── pyproject.toml                   # Dependencies and project config
├── Makefile                         # Common development commands
├── CLAUDE.md                        # Development team configuration
└── claude-context.md               # This file
```

## Common Commands & Paths
```bash
# ⚠️ CRITICAL: Always use uv, never pip
uv sync --all-extras                 # Install all dependencies
uv add <package>                     # Add new dependency
uv run <command>                     # Run command in uv environment

# Development workflow
make install                         # Set up canonical UV environment
make test                           # Run comprehensive test suite
make lint                           # Critical linting (blocks CI)
make format                         # Auto-format with ruff
make ci-check                       # Run all CI checks locally

# Knowledge base operations
make run                            # Start knowledge base server (http://localhost:8000)
make dev                            # Development mode with hot reload
make rebuild-index                  # Rebuild search indices
make validate-index                 # Validate index integrity

# Testing knowledge base features
make test-search                    # Test search functionality
make test-indexing                  # Test content indexing
make test-retrieval                 # Test knowledge retrieval

# MCP operations
make mcp-install                    # Install MCP servers
make mcp-test                       # Test MCP server connectivity

# Environment setup (REQUIRED first step)
doppler setup                       # Configure secrets management
```

## Environment Variables & Configuration
- **Config file location**: `.env.example` template, managed by Doppler (never commit secrets)
- **Key variables** (managed by Doppler):
  - `DATABASE_URL`: PostgreSQL connection string
  - `REDIS_URL`: Redis connection for caching
  - `RAGNOSTIC_API_URL`: RAGnostic service URL
  - `RAGNOSTIC_API_KEY`: RAGnostic authentication
  - `SECRET_KEY`: Application security key
  - `DEBUG`: Development mode flag
- **Medical compliance**: HIPAA-compatible configuration options

## Development Workflow
- **Code editor**: VS Code (with WSL extension)
- **Testing**: pytest with async support, >90% coverage requirement
- **API testing**: FastAPI auto-generated docs at `http://localhost:8000/docs`
- **Version control**: Git (GitHub with Actions CI/CD)
- **Quality tools**: ruff + mypy + security scanning
- **Database**: PostgreSQL for persistence, Redis for caching

## BSN Knowledge Features
- **Educational Content Management**: Study guides, quizzes, learning materials
- **NCLEX Question Generation**: AI-powered NCLEX-style question creation
- **Competency Framework**: 5-level proficiency assessment (Novice to Expert)
- **Adaptive Learning**: Personalized learning path recommendations
- **Content Search & Retrieval**: Enhanced search with RAGnostic integration
- **Progress Tracking**: Student performance analytics and gap analysis
- **Medical Content Validation**: Safety checks for nursing education content

## API Endpoints Structure
```python
# Main application routes
/api/v1/study-guides/              # Study guide management
/api/v1/quizzes/                   # Quiz operations
/api/v1/adaptive-learning/         # Adaptive learning engine
/api/v1/assessments/               # Competency assessments
/api/v1/content/                   # Content management
/api/v1/search/                    # Knowledge search

# Health monitoring
/health                            # Basic health check
/health/detailed                   # Detailed system status
```

## Competency Framework
```python
# 5-Level BSN Competency Scale
class CompetencyLevel(str, Enum):
    NOVICE = "novice"                    # Beginning level
    ADVANCED_BEGINNER = "advanced_beginner"  # Developing skills
    COMPETENT = "competent"              # Safe practice
    PROFICIENT = "proficient"           # Skilled practice
    EXPERT = "expert"                   # Advanced expertise

# Assessment categories
- Fundamentals of Nursing
- Anatomy and Physiology  
- Pharmacology
- Medical-Surgical Nursing
- Psychiatric Nursing
- Pediatric Nursing
- Maternal Health Nursing
- Community Health Nursing
```

## RAGnostic Integration
```python
# Enhanced knowledge retrieval client
class RAGnosticClient:
    - search_content()              # UMLS-enriched content search
    - get_concept_graph()          # Prerequisite relationships
    - get_content_by_metadata()    # Rich metadata filtering
    - validate_medical_content()   # Safety validation
    - get_study_materials()        # Educational content retrieval
```

## Service Health & Monitoring
```bash
# Check application health
curl http://localhost:8000/health           # Basic health
curl http://localhost:8000/health/detailed  # Detailed status

# Test search functionality
curl http://localhost:8000/api/v1/search?q="nursing fundamentals"

# Test content generation
curl -X POST http://localhost:8000/api/v1/quizzes/generate \
  -H "Content-Type: application/json" \
  -d '{"topic": "pharmacology", "difficulty": "intermediate"}'
```

## MCP Server Configuration (14 Servers)
- **Core Development**: filesystem, git, memory, context7
- **Code Quality**: eslint, ripgrep
- **Database Operations**: sqlite, sqlite-secondary, postgres
- **AI/ML Capabilities**: sequential-thinking, elevenlabs
- **Web Operations**: fetch, playwright
- **Local Services**: codanna-https (SSE protocol)

## Important Notes
- ⚠️ **I'm in WSL/Linux environment** - use forward slashes, bash commands
- ⚠️ **NOT Windows PowerShell** - avoid Windows-specific commands
- ⚠️ **Use uv, NEVER pip** - uv is the required package manager
- ⚠️ **Doppler required** - Always run `doppler setup` first for secrets
- 🔄 **Hot reload enabled** - FastAPI auto-reloads on changes
- 📁 **Docker support** - Containerized deployment available
- 🏥 **Nursing education focus** - Content optimized for BSN students
- 🔒 **Educational compliance** - FERPA-compatible data handling
- 📊 **Competency tracking** - Evidence-based assessment framework

## Project Status (Updated 2025-08-18)
- **Core Infrastructure**: ✅ 100% Complete - FastAPI application with full routing
- **Data Models**: ✅ 100% Complete - Educational content and assessment models
- **Content Generators**: ✅ Framework Complete - NCLEX, study guides, quizzes
- **Assessment System**: ✅ 100% Complete - Competency framework with 5-level scale
- **RAGnostic Integration**: ✅ 100% Complete - Enhanced knowledge retrieval client
- **API Endpoints**: ✅ 100% Complete - Full REST API with documentation
- **Development Infrastructure**: ✅ 100% Complete - Quality gates, CI/CD, testing
- **MCP Integration**: ✅ 100% Complete - 14-server ecosystem operational

## Current Implementation Status
### Completed Features
- ✅ Complete FastAPI application structure with educational content APIs
- ✅ Competency framework with 5-level BSN assessment scale
- ✅ NCLEX question generation framework with medical validation
- ✅ Study guide and quiz generation systems
- ✅ RAGnostic client integration for enhanced knowledge retrieval
- ✅ Medical content validation and safety checks
- ✅ Comprehensive development infrastructure with quality gates
- ✅ Docker containerization with health monitoring
- ✅ CI/CD pipelines with educational content-specific testing

### Ready for Implementation
1. **Content Generation Logic** (8-12 hours):
   - NCLEX question generation algorithms
   - Study guide content creation
   - Quiz generation with difficulty scaling

2. **Assessment Engine** (6-10 hours):
   - Competency gap analysis algorithms
   - Learning path recommendation engine
   - Progress tracking and analytics

3. **Search & Indexing** (4-8 hours):
   - Content indexing pipeline
   - Search optimization for nursing terms
   - Metadata extraction and categorization

### Development Priorities
1. Implement core content generation algorithms
2. Build competency assessment engine
3. Deploy search and indexing functionality
4. Integrate with RAGnostic for enhanced retrieval
5. Add comprehensive testing for educational workflows

## Educational Content Categories
```python
# BSN Nursing Topics
NURSING_TOPICS = [
    "Fundamentals of Nursing",
    "Anatomy and Physiology", 
    "Pharmacology",
    "Medical-Surgical Nursing",
    "Psychiatric Nursing",
    "Pediatric Nursing",
    "Maternal Health Nursing",
    "Community Health Nursing"
]

# Content Types
CONTENT_TYPES = [
    "study_guide",
    "quiz", 
    "flashcards",
    "case_study",
    "video_lecture",
    "interactive_module",
    "nclex_practice"
]
```

## Performance Standards
- **API Response Times**: <500ms simple operations, <2s complex operations
- **Search Performance**: <100ms basic queries, <500ms semantic search
- **Content Generation**: <5s NCLEX questions, <10s study guides
- **Assessment Processing**: <2s competency evaluation
- **Database Operations**: <50ms reads, <200ms writes

---
*Last updated: 2025-08-18*
*Claude: Please reference this context for all commands, paths, and suggestions. Always use uv (not pip), respect the educational content architecture, and maintain nursing education accuracy standards.*