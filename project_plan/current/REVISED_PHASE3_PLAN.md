## Executive Summary

This revised plan addresses the critical architectural misalignment in the original Phase 3 plan, which incorrectly included application-level features within RAGnostic. Per the architectural strategy defined in planning_conversation.md (lines 1086-1218), RAGnostic must remain a pure data pipeline that enriches and indexes content, while BSN Knowledge handles all educational content generation and assessment features. This revision extracts all application logic from RAGnostic and establishes BSN Knowledge as the application layer consuming RAGnostic's enriched data.

---

## Part 1: RAGnostic - Revised Phase 3 Plan (Pure Pipeline)

### Objective

Transform RAGnostic into a focused, reusable data pipeline by removing all application features and implementing core enrichment capabilities including UMLS integration, batch processing, essential processors, and graph relationships for medical content.

### Tasks

#### Task R.1: Code Extraction & Cleanup
**Description**: Audit and remove all application-level code from RAGnostic, preparing it for migration to BSN Knowledge. This includes NCLEX generation, competency assessment, clinical decision support, learning analytics, and any student-tracking features.

**Implementation Steps**:
```bash
# Create migration manifest
1. Identify all files containing: NCLEX, competency, student, quiz, assessment, learning_path
2. Document functions and classes to be extracted
3. Create MIGRATION_TO_BSN.md with complete inventory
4. Branch creation: feature/extract-bsn-features
5. Remove application code while preserving pipeline interfaces
```

**Files to Remove/Migrate**:
- `processors/nursing-content-processor/nclex_generator.py`
- `processors/nursing-content-processor/competency_assessment.py`
- `processors/nursing-content-processor/clinical_decision.py`
- `processors/nursing-content-processor/learning_analytics.py`
- Any `student_tracking.py` or quiz-related modules
- `services/competency-service/` (entire directory if exists)
- `services/analytics-service/` (entire directory if exists)

**Success Criteria**:
- ✅ Zero application logic remaining in codebase
- ✅ All educational feature code documented for migration
- ✅ Pipeline interfaces remain intact and functional
- ✅ No references to student tracking or assessment generation
- ✅ Clean separation verified through dependency analysis

#### Task R.2: UMLS Integration & Medical Enrichment
**Description**: Implement comprehensive UMLS (Unified Medical Language System) integration for medical term enrichment, focusing solely on data enhancement without any educational feature generation.

**UMLS API Configuration**:
- **API Documentation Location**: `.user/UMLS.md` (contains complete UMLS API setup instructions and endpoints)
- **Secret Management**: ALL UMLS API keys, authentication tokens, and credentials MUST be stored in Doppler exclusively
- **Environment Variables Required**:
  ```bash
  UMLS_API_KEY=<your_umls_api_key>          # Store in Doppler
  UMLS_TGT_URL=<ticket_granting_url>        # Store in Doppler
  UMLS_AUTH_URL=<authentication_url>        # Store in Doppler
  UMLS_API_VERSION=<api_version>            # Store in Doppler
  UMLS_RATE_LIMIT=20                        # 20 requests/second limit
  ```

**Implementation**:
```python
class UMLSPipelineEnricher:
    \"\"\"Pure pipeline enrichment - no application logic\"\"\"
    VERSION = \"1.0.0\"

    def __init__(self):
        # Load UMLS credentials from Doppler environment
        from shared.utils.doppler_config import DopplerConfig
        config = DopplerConfig.get_config()

        self.api_key = config["UMLS_API_KEY"]
        self.tgt_url = config["UMLS_TGT_URL"]
        self.auth_url = config["UMLS_AUTH_URL"]
        self.api_version = config["UMLS_API_VERSION"]
        self.rate_limiter = RateLimiter(requests_per_second=20)

    def enrich_chunk(self, chunk: ContentChunk) -> EnrichedChunk:
        # Extract medical terms using scispaCy
        # Query UMLS API for CUIs (Concept Unique Identifiers)
        # Add semantic types and relationships
        # Store enrichment metadata
        return EnrichedChunk(
            original=chunk,
            medical_entities=entities,
            umls_concepts=concepts,
            semantic_types=types,
            relationships=relationships
        )

    async def authenticate_umls(self) -> str:
        \"\"\"Get UMLS authentication ticket from Doppler-stored credentials\"\"\"
        # Use Doppler-stored API key for UMLS authentication
        # Refer to .user/UMLS.md for complete authentication flow
        pass
```

**Success Criteria**:
- ✅ UMLS API integration with rate limiting
- ✅ Medical term extraction accuracy >95%
- ✅ CUI mapping for all identified medical terms
- ✅ Semantic type classification operational
- ✅ Relationship extraction between medical concepts
- ✅ All UMLS credentials stored exclusively in Doppler
- ✅ Authentication flow follows .user/UMLS.md documentation

#### Task R.3: Batch Processing Architecture
**Description**: Deploy overnight batch processing system for UMLS enrichment and multi-embedding generation, managing API rate limits and ensuring checkpoint/resume capability.

**Implementation Components**:
```python
class BatchProcessingPipeline:
    \"\"\"Overnight enrichment pipeline\"\"\"

    async def process_batch(self):
        # Checkpoint management
        # UMLS API rate limit handling (20 requests/second)
        # Multiple embedding generation:
        #   - General (OpenAI/Sentence Transformers)
        #   - Medical (BioBERT/SciBERT)
        #   - Concept-level embeddings
        # Progress tracking and monitoring
        # Failure recovery mechanisms
```

**Success Criteria**:
- ✅ Celery-based batch processing operational
- ✅ Checkpoint/resume functionality tested
- ✅ Rate limit compliance verified
- ✅ Multi-embedding storage in Qdrant collections
- ✅ Nightly processing scheduled and monitored

#### Task R.4: Core Processor Implementation
**Description**: Complete implementation of three essential processors following BaseProcessor interface: Document, OCR, and Media processors for medical content processing.

**Processor Specifications**:

```python
# Document Processor (PDF, DOCX, PPTX)
class DocumentProcessor(BaseProcessor):
    \"\"\"Process medical documents\"\"\"
    VERSION = \"1.0.0\"
    SUPPORTED_FORMATS = ['.pdf', '.docx', '.pptx']

    def process(self, source_config: dict) -> ProcessingResult:
        # Extract text with structure preservation
        # Maintain medical terminology integrity
        # Preserve tables and diagrams metadata
        # Generate hierarchical chunks
        return ProcessingResult(chunks, metadata)

# OCR Processor (Scanned documents)
class OCRProcessor(BaseProcessor):
    \"\"\"Process scanned medical documents\"\"\"
    VERSION = \"1.0.0\"

    def process(self, source_config: dict) -> ProcessingResult:
        # Tesseract integration for text extraction
        # Medical handwriting recognition
        # Confidence scoring for OCR results
        # Structure reconstruction from scans
        return ProcessingResult(chunks, confidence_scores)

# Media Processor (Lecture recordings)
class MediaProcessor(BaseProcessor):
    \"\"\"Process medical lecture recordings\"\"\"
    VERSION = \"1.0.0\"

    def process(self, source_config: dict) -> ProcessingResult:
        # Whisper transcription with timestamps
        # Medical terminology accuracy
        # Speaker diarization if available
        # Chunk by topic transitions
        return ProcessingResult(transcript_chunks, timestamps)
```

**Success Criteria**:
- ✅ All three processors fully functional
- ✅ BaseProcessor interface compliance verified
- ✅ Medical content accuracy >95%
- ✅ Integration with existing pipeline tested
- ✅ Performance benchmarks met (<2s per document)

#### Task R.5: Graph Relationships & Prerequisites
**Description**: Implement concept relationship management in PostgreSQL for prerequisite chains and learning paths, providing queryable graph data without generating educational content.

**Database Schema**:
```sql
-- Concept relationships table
CREATE TABLE concept_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_concept_id UUID REFERENCES medical_concepts(id),
    to_concept_id UUID REFERENCES medical_concepts(id),
    relationship_type VARCHAR(50), -- prerequisite, related, broader, narrower
    strength NUMERIC(3,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Prerequisite chains cache
CREATE TABLE prerequisite_chains (
    concept_id UUID PRIMARY KEY,
    prerequisites UUID[],
    depth INTEGER,
    last_calculated TIMESTAMP
);
```

**Success Criteria**:
- ✅ Graph relationships stored and indexed
- ✅ Recursive CTE queries for prerequisite chains
- ✅ API endpoints for graph traversal
- ✅ Performance <100ms for graph queries
- ✅ Relationship data accessible to BSN Knowledge

#### Task R.6: Enhanced Metadata Schema
**Description**: Implement enriched metadata schema to support educational applications without implementing the applications themselves.

**Schema Enhancements**:
```sql
ALTER TABLE content_chunks ADD COLUMN IF NOT EXISTS
    learning_objective_ids TEXT[],
    prerequisite_concept_ids UUID[],
    cognitive_level VARCHAR(20), -- Bloom's taxonomy level
    question_generation_hints JSONB,
    clinical_judgment_model VARCHAR(50),
    test_blueprint_category VARCHAR(100),
    difficulty_score NUMERIC(3,2),
    medical_specialty VARCHAR(50);
```

**Success Criteria**:
- ✅ Metadata schema deployed to production
- ✅ All chunks enriched with new metadata
- ✅ Queryable via API endpoints
- ✅ No educational content generation logic
- ✅ Schema documented for BSN Knowledge use

#### Task R.7: API Enhancement for BSN Knowledge
**Description**: Create clean, well-documented API endpoints for BSN Knowledge to consume enriched data without any application logic in RAGnostic.

**API Endpoints**:
```python
@router.get(\"/api/v1/educational/content/search\")
async def search_enriched_content(
    query: str,
    nclex_categories: List[str] = None,
    complexity_level: int = None,
    include_prerequisites: bool = False
) -> EnrichedContentResponse:
    \"\"\"Returns enriched chunks with UMLS, embeddings, relationships\"\"\"
    # Pure data retrieval - no generation

@router.get(\"/api/v1/educational/concepts/{concept_id}/graph\")
async def get_concept_graph(concept_id: str) -> ConceptGraph:
    \"\"\"Returns graph data for concept relationships\"\"\"
    # Graph traversal only - no path generation

@router.get(\"/api/v1/educational/content/batch\")
async def get_content_batch(filters: dict) -> ContentBatch:
    \"\"\"Bulk retrieval for BSN Knowledge processing\"\"\"
    # Filtered data access - no processing
```

**Success Criteria**:
- ✅ All endpoints documented with OpenAPI
- ✅ Response times <100ms
- ✅ No educational content generation
- ✅ Clean interface for BSN Knowledge
- ✅ Rate limiting and authentication implemented

#### Task R.8: Post-Refactor Integration Testing
**Description**: Comprehensive testing to ensure RAGnostic functions correctly as a pure pipeline after removing application features.

**Testing Scope**:
- Unit tests for all pipeline components
- Integration tests for processor chain
- API endpoint validation
- Performance benchmarking
- Data integrity verification
- BSN Knowledge integration testing

**Success Criteria**:
- ✅ Test coverage >90% for pipeline code
- ✅ All processors pass integration tests
- ✅ API endpoints return expected data structures
- ✅ No application logic detected in tests
- ✅ Performance targets met across all components

#### Task R.9: Documentation Update
**Description**: Update all documentation to reflect RAGnostic's focused role as a pure data pipeline.

**Documentation Updates**:
- README.md - Clear statement of pipeline-only scope
- ARCHITECTURE.md - Updated diagrams showing BSN Knowledge separation
- API_DOCUMENTATION.md - Complete endpoint reference
- PROCESSOR_GUIDE.md - Implementation patterns for new processors
- MIGRATION_GUIDE.md - Instructions for BSN Knowledge integration

**Success Criteria**:
- ✅ All documentation reflects pure pipeline scope
- ✅ No references to educational content generation
- ✅ Clear integration guide for BSN Knowledge
- ✅ Architecture diagrams updated
- ✅ API documentation complete and accurate

---

## Part 2: BSN-Knowledge - Initial Project Plan (Application Layer)

### Objective

Establish BSN Knowledge as the application layer for educational content generation, consuming RAGnostic's enriched data to provide NCLEX preparation, competency assessment, and adaptive learning features.

### Tasks

#### Task B.1: Project Scaffolding & Setup
**Description**: Initialize BSN Knowledge project with proper structure, dependencies, and connection to RAGnostic pipeline.

**Project Structure**:
```
BSN-Knowledge/
├── .env.example
├── pyproject.toml          # Using uv for consistency
├── docker-compose.yml      # Separate from RAGnostic
├── README.md
├── ARCHITECTURE.md
├── src/
│   ├── api/               # FastAPI endpoints
│   │   ├── main.py
│   │   └── routers/
│   │       ├── study_guides.py
│   │       ├── quizzes.py
│   │       └── adaptive_learning.py
│   ├── generators/        # Content generation engines
│   │   ├── nclex_generator.py
│   │   ├── study_guide_generator.py
│   │   └── quiz_generator.py
│   ├── assessment/        # Competency assessment
│   │   ├── competency_framework.py
│   │   ├── knowledge_gap_analyzer.py
│   │   └── learning_path_optimizer.py
│   ├── models/           # Pydantic models
│   ├── services/         # Business logic
│   │   ├── ragnostic_client.py
│   │   └── content_retrieval.py
│   └── utils/
└── tests/
```

**Setup Commands**:
```bash
cd ~/projects/BSN-Knowledge
uv init
uv add fastapi uvicorn pydantic sqlalchemy httpx
uv add openai instructor pandas numpy
cp ../template-workspace/.pre-commit-config.yaml .
```

**Success Criteria**:
- ✅ Project structure created and initialized
- ✅ Dependencies installed and managed with uv
- ✅ Docker environment configured
- ✅ RAGnostic client interface implemented
- ✅ Development environment operational

#### Task B.2: Feature Migration & Integration
**Description**: Migrate educational features from RAGnostic, refactoring to use RAGnostic's API instead of direct database access.

**Migration Components**:
```python
# Migrated NCLEX Generator
class NCLEXGenerator:
    \"\"\"Generates NCLEX-style questions using RAGnostic data\"\"\"

    def __init__(self, ragnostic_client: RAGnosticClient):
        self.rag_client = ragnostic_client
        self.question_templates = load_templates()

    async def generate_questions(self, topic: str, count: int = 5):
        # Fetch enriched content from RAGnostic
        content = await self.rag_client.search_content(
            query=topic,
            filters={\"content_type\": \"nursing_education\"}
        )
        # Generate questions using migrated logic
        questions = self._generate_from_content(content)
        return questions

# Migrated Competency Assessment
class CompetencyAssessment:
    \"\"\"Assesses nursing competencies using AACN framework\"\"\"

    def __init__(self, ragnostic_client: RAGnosticClient):
        self.rag_client = ragnostic_client
        self.aacn_framework = load_aacn_framework()

    async def assess_competencies(self, student_responses):
        # Use RAGnostic data for assessment
        # Apply AACN framework mapping
        # Generate competency reports
        pass
```

**Success Criteria**:
- ✅ All educational features successfully migrated
- ✅ Refactored to use RAGnostic API
- ✅ Original functionality preserved
- ✅ No direct database dependencies
- ✅ Unit tests passing for migrated code

#### Task B.3: Clinical Decision Support Implementation
**Description**: Implement clinical decision support features that were incorrectly planned for RAGnostic.

**Implementation**:
```python
class ClinicalDecisionSupport:
    \"\"\"Provides evidence-based clinical recommendations\"\"\"

    async def generate_recommendations(self, case_scenario: dict):
        # Query RAGnostic for relevant clinical content
        # Apply clinical reasoning algorithms
        # Generate evidence-based recommendations
        # Include citations and confidence scores
        pass

    async def create_case_studies(self, learning_objectives: List[str]):
        # Use RAGnostic content to build scenarios
        # Align with specified learning objectives
        # Include assessment questions
        pass
```

**Success Criteria**:
- ✅ Clinical recommendation engine functional
- ✅ Case study generator operational
- ✅ Evidence citations included
- ✅ Integration with RAGnostic tested
- ✅ API endpoints implemented

#### Task B.4: Learning Analytics & Reporting
**Description**: Implement analytics and reporting features for educational outcomes and student progress.

**Components**:
```python
class LearningAnalytics:
    \"\"\"Analyzes learning patterns and outcomes\"\"\"

    async def analyze_student_progress(self, student_id: str):
        # Track competency progression
        # Identify knowledge gaps
        # Generate learning recommendations
        # Create progress reports
        pass

    async def generate_institutional_reports(self):
        # Program effectiveness metrics
        # Curriculum alignment analysis
        # Outcome measurements
        pass
```

**Success Criteria**:
- ✅ Student progress tracking implemented
- ✅ Knowledge gap analysis functional
- ✅ Learning path recommendations working
- ✅ Institutional reporting operational
- ✅ Dashboard API endpoints created

#### Task B.5: Adaptive Learning Engine
**Description**: Create adaptive learning system that personalizes content based on student performance.

**Implementation**:
```python
class AdaptiveLearningEngine:
    \"\"\"Personalizes learning based on performance\"\"\"

    async def generate_personalized_content(self, student_profile: dict):
        # Analyze student strengths/weaknesses
        # Query RAGnostic for appropriate content
        # Adjust difficulty dynamically
        # Create personalized study plans
        pass

    async def optimize_learning_path(self, target_competencies: List[str]):
        # Use RAGnostic's prerequisite graphs
        # Calculate optimal learning sequence
        # Adjust based on progress
        pass
```

**Success Criteria**:
- ✅ Personalization algorithm implemented
- ✅ Dynamic difficulty adjustment working
- ✅ Learning path optimization functional
- ✅ Integration with RAGnostic graphs tested
- ✅ Performance metrics tracked

#### Task B.6: API Development & Documentation
**Description**: Create comprehensive API for BSN Knowledge features with proper documentation.

**API Structure**:
```python
# FastAPI routers
@router.post(\"/api/v1/nclex/generate\")
async def generate_nclex_questions(request: NCLEXRequest):
    \"\"\"Generate NCLEX-style questions\"\"\"

@router.post(\"/api/v1/assessment/competency\")
async def assess_competency(request: CompetencyRequest):
    \"\"\"Assess nursing competencies\"\"\"

@router.post(\"/api/v1/study-guide/create\")
async def create_study_guide(request: StudyGuideRequest):
    \"\"\"Generate personalized study guides\"\"\"

@router.get(\"/api/v1/analytics/student/{student_id}\")
async def get_student_analytics(student_id: str):
    \"\"\"Retrieve student learning analytics\"\"\"
```

**Success Criteria**:
- ✅ All endpoints implemented and tested
- ✅ OpenAPI documentation generated
- ✅ Authentication/authorization implemented
- ✅ Rate limiting configured
- ✅ Error handling comprehensive

#### Task B.7: Testing Suite Development
**Description**: Create comprehensive testing suite for all BSN Knowledge features.

**Testing Scope**:
- Unit tests for all generators and assessments
- Integration tests with RAGnostic API
- Performance testing for content generation
- End-to-end testing for user workflows
- Load testing for concurrent users

**Success Criteria**:
- ✅ Test coverage >85%
- ✅ All critical paths tested
- ✅ Performance benchmarks established
- ✅ Integration tests passing
- ✅ CI/CD pipeline configured

#### Task B.8: Initial Documentation
**Description**: Create foundational documentation for BSN Knowledge project.

**Documentation Components**:
- README.md - Project overview and setup
- ARCHITECTURE.md - System design and RAGnostic integration
- API_REFERENCE.md - Complete endpoint documentation
- DEPLOYMENT.md - Production deployment guide
- CONTRIBUTING.md - Development guidelines

**Success Criteria**:
- ✅ All core documentation created
- ✅ Architecture diagrams included
- ✅ API examples provided
- ✅ Setup instructions tested
- ✅ Integration guide complete

---

## Timeline & Resource Allocation

### RAGnostic Phase 3 (Pure Pipeline)
**Total Duration**: 4-5 weeks
- Week 1: Code extraction & UMLS integration (Tasks R.1-R.2)
- Week 2: Batch processing & processors (Tasks R.3-R.4)
- Week 3: Graph implementation & metadata (Tasks R.5-R.6)
- Week 4: API enhancement & testing (Tasks R.7-R.8)
- Week 5: Documentation & finalization (Task R.9)

**Resource Estimate**: 100-120 hours

### BSN Knowledge Initial Setup
**Total Duration**: 3-4 weeks (can overlap with RAGnostic work)
- Week 1: Project setup & migration (Tasks B.1-B.2)
- Week 2: Feature implementation (Tasks B.3-B.5)
- Week 3: API & testing (Tasks B.6-B.7)
- Week 4: Documentation & deployment (Task B.8)

**Resource Estimate**: 80-100 hours

---

## Risk Mitigation

### Technical Risks
1. **Migration Complexity**: Code extraction may reveal tight coupling
   - Mitigation: Incremental migration with feature flags

2. **API Performance**: BSN Knowledge's dependency on RAGnostic API
   - Mitigation: Implement caching and batch operations

3. **UMLS Rate Limits**: API restrictions for medical term enrichment
   - Mitigation: Batch processing with checkpoint/resume

### Project Risks
1. **Scope Creep**: Temptation to add features during migration
   - Mitigation: Strict adherence to architectural boundaries

2. **Testing Coverage**: Ensuring functionality after separation
   - Mitigation: Comprehensive test suite before and after

---

## Success Metrics

### RAGnostic Success Metrics
- ✅ Zero application logic in codebase
- ✅ UMLS enrichment on 100% of content
- ✅ Batch processing running nightly
- ✅ 3 core processors operational
- ✅ API response times <100ms
- ✅ Graph queries functional

### BSN Knowledge Success Metrics
- ✅ All educational features migrated and functional
- ✅ NCLEX question generation operational
- ✅ Competency assessment working
- ✅ Learning analytics implemented
- ✅ Clean integration with RAGnostic API
- ✅ Test coverage >85%

---

## ENHANCED CONTEXT7 PLANNING PROTOCOL (Required for All Subagents)

### **CRITICAL IMPLEMENTATION REQUIREMENT**:
**Any agent writing or reviewing code MUST invoke Context7 MCP tools** before implementation. This 3-step enforcement protocol eliminates library resolution delays and ensures accurate documentation access.

### Step 1: Pre-Resolved Library IDs (COMPLETE)
All Context7 library IDs have been pre-resolved during planning phase. Subagents skip `resolve-library-id` and proceed directly to `get-library-docs`.

### Step 2: Exact Documentation Queries for RAGnostic Processors

#### **DOCUMENT PROCESSOR** (`processors/document-processor/processor.py` - Enhancement Required)
**Assigned Agent**: @backend-developer
**Pre-resolved Context7 IDs**:
- `/pypdf/pypdf` - PDF processing with medical content preservation
- `/python-office/python-docx` - Office document processing for medical forms
- `/openpyxl/openpyxl` - Excel processing for medical data spreadsheets

**Required MCP Commands**:
```bash
# Documentation retrieval (execute in sequence)
mcp__context7__get-library-docs --context7CompatibleLibraryID="/pypdf/pypdf" --topic="PDF medical document processing with clinical data preservation"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/python-office/python-docx" --topic="Office document processing for medical forms and reports"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/openpyxl/openpyxl" --topic="Excel processing for medical data and structured tables"
```

**Implementation Focus**: Medical document processing with structure preservation, clinical table extraction, and metadata preservation.

#### **OCR PROCESSOR** (`processors/ocr-processor/processor.py` - Complete Implementation Required)
**Assigned Agent**: @backend-developer
**Pre-resolved Context7 IDs**:
- `/tesseract-ocr/tessdoc` - Tesseract OCR engine documentation and configuration
- `/madmaze/pytesseract` - Python wrapper for Tesseract OCR
- `/opencv/opencv` - Image preprocessing for OCR accuracy improvement

**Required MCP Commands**:
```bash
# Documentation retrieval (execute in sequence)
mcp__context7__get-library-docs --context7CompatibleLibraryID="/tesseract-ocr/tessdoc" --topic="OCR configuration for medical handwriting and clinical forms"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/madmaze/pytesseract" --topic="Python Tesseract integration with medical terminology correction"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/opencv/opencv" --topic="Image preprocessing for medical document OCR accuracy"
```

**Implementation Focus**: Medical handwriting recognition, clinical form processing, and medical terminology validation with error correction.

#### **MEDIA PROCESSOR** (`processors/media-processor/processor.py` - Enhancement Required)
**Assigned Agent**: @backend-developer
**Pre-resolved Context7 IDs**:
- `/openai/whisper` - Audio/video transcription for medical lectures
- `/moviepy/moviepy` - Video processing for educational content
- `/librosa/librosa` - Audio analysis for lecture processing

**Required MCP Commands**:
```bash
# Documentation retrieval (execute in sequence)
mcp__context7__get-library-docs --context7CompatibleLibraryID="/openai/whisper" --topic="Audio transcription for medical lectures with terminology accuracy"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/moviepy/moviepy" --topic="Video processing for medical educational content extraction"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/librosa/librosa" --topic="Audio analysis for medical lecture structure preservation"
```

**Implementation Focus**: Medical lecture transcription with timestamp accuracy, educational content structure preservation, and clinical terminology validation.

### Step 3: Implementation Guidance Queries

#### **UMLS Integration** (Task R.2)
**Assigned Agent**: @rag-pipeline-architect
**Pre-resolved Context7 IDs**:
- `/spacy/scispacy` - Medical text processing and clinical entity recognition
- `/huggingface/transformers` - Clinical BERT models for medical understanding
- `/nltk/nltk` - Natural language processing for medical terminology

**UMLS API Configuration Requirements**:
- **API Documentation**: Located at `.user/UMLS.md` (complete setup instructions)
- **Secret Management**: ALL UMLS API keys, tokens, and credentials MUST be stored in Doppler exclusively
- **Doppler Environment Variables**:
  ```bash
  UMLS_API_KEY=<api_key>           # Primary UMLS API authentication
  UMLS_TGT_URL=<tgt_url>          # Ticket granting URL
  UMLS_AUTH_URL=<auth_url>        # Authentication endpoint
  UMLS_API_VERSION=<version>      # API version identifier
  ```

**Required MCP Commands**:
```bash
# Medical NLP documentation retrieval
mcp__context7__get-library-docs --context7CompatibleLibraryID="/spacy/scispacy" --topic="Medical entity recognition with UMLS concept identification"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/huggingface/transformers" --topic="Clinical BERT integration for medical content understanding"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/nltk/nltk" --topic="Medical terminology processing and semantic type classification"
# Additional: Review .user/UMLS.md for complete API authentication patterns
```

#### **Batch Processing Architecture** (Task R.3)
**Assigned Agent**: @backend-developer
**Pre-resolved Context7 IDs**:
- `/celery/celery` - Async job processing for medical content workflows
- `/redis/redis` - Caching strategies for batch processing
- `/qdrant/qdrant-client` - Vector database operations for embeddings

**Required MCP Commands**:
```bash
# Batch processing documentation retrieval
mcp__context7__get-library-docs --context7CompatibleLibraryID="/celery/celery" --topic="Async job processing with checkpoint resume for medical content"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/redis/redis" --topic="Caching and queue management for batch processing workflows"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/qdrant/qdrant-client" --topic="Vector database operations for multi-embedding storage"
```

#### **BaseProcessor Interface Compliance**
**All Processor Agents Must Execute**:
```bash
mcp__context7__get-library-docs --context7CompatibleLibraryID="/fastapi/fastapi" --topic="BaseProcessor implementation patterns with FastAPI integration"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/pydantic/pydantic" --topic="Data validation models for ProcessingResult and ProcessedContent"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/sqlalchemy/sqlalchemy" --topic="Database integration patterns for processor configuration"
```

#### **Graph Relationships & Prerequisites** (Task R.5)
**Assigned Agent**: @backend-developer
**Pre-resolved Context7 IDs**:
- `/postgresql/psycopg2` - PostgreSQL operations for graph storage
- `/sqlalchemy/sqlalchemy` - ORM operations for concept relationships
- `/fastapi/fastapi` - API endpoints for graph traversal

**Required MCP Commands**:
```bash
# Graph database documentation retrieval
mcp__context7__get-library-docs --context7CompatibleLibraryID="/postgresql/psycopg2" --topic="PostgreSQL graph operations with recursive CTE queries"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/sqlalchemy/sqlalchemy" --topic="ORM patterns for concept relationship management"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/fastapi/fastapi" --topic="API endpoint design for graph traversal operations"
```

### Context7 Protocol Enforcement Checklist

**For RAGnostic Pipeline Enhancement**:
- [ ] **Step 1**: Verify pre-resolved Context7 IDs (18 total provided above)
- [ ] **Step 2**: Execute ALL required `get-library-docs` commands before coding
- [ ] **Step 3**: Implement pure pipeline functionality (no application logic)
- [ ] **Step 4**: Validate against BaseProcessor interface compliance
- [ ] **Step 5**: Test integration with existing RAGnostic architecture

### BSN Knowledge Context7 Requirements

#### **Content Generation Features** (Tasks B.2-B.5)
**Assigned Agent**: @rag-pipeline-architect
**Pre-resolved Context7 IDs**:
- `/openai/openai-python` - LLM integration for content generation
- `/pydantic/pydantic` - Data models for educational content structure
- `/fastapi/fastapi` - API development for BSN Knowledge services

**Required MCP Commands**:
```bash
# Educational content generation documentation
mcp__context7__get-library-docs --context7CompatibleLibraryID="/openai/openai-python" --topic="LLM integration for NCLEX question generation and clinical scenarios"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/pydantic/pydantic" --topic="Data validation for educational content and assessment models"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/fastapi/fastapi" --topic="Educational API endpoint design with authentication"
```

### Quality Assurance with Context7 Integration

**RAGnostic Pipeline Requirements**:
- Medical terminology accuracy >98% with Context7 clinical documentation
- Pure pipeline functionality verified (zero application logic)
- UMLS integration with API rate limit compliance
- BaseProcessor interface compliance across all processors
- Batch processing operational with checkpoint/resume functionality

**BSN Knowledge Application Requirements**:
- Educational content generation accuracy validated against medical standards
- RAGnostic API integration performance <100ms response times
- NCLEX question generation aligned with clinical accuracy requirements
- Competency assessment framework compliance with AACN standards

### SUBAGENT EXECUTION COMMANDS

**RAGnostic Document Processor Agent**:
```bash
# Execute these commands before any code implementation:
mcp__context7__get-library-docs --context7CompatibleLibraryID="/pypdf/pypdf" --topic="PDF medical document processing with clinical data preservation"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/python-office/python-docx" --topic="Office document processing for medical forms and reports"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/openpyxl/openpyxl" --topic="Excel processing for medical data and structured tables"
# Then enhance: processors/document-processor/processor.py with medical accuracy focus
```

**RAGnostic OCR Processor Agent**:
```bash
# Execute these commands before any code implementation:
mcp__context7__get-library-docs --context7CompatibleLibraryID="/tesseract-ocr/tessdoc" --topic="OCR configuration for medical handwriting and clinical forms"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/madmaze/pytesseract" --topic="Python Tesseract integration with medical terminology correction"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/opencv/opencv" --topic="Image preprocessing for medical document OCR accuracy"
# Then implement: processors/ocr-processor/processor.py with BaseProcessor compliance
```

**RAGnostic UMLS Integration Agent**:
```bash
# CRITICAL: Review UMLS API documentation first
# Read .user/UMLS.md for complete API setup and authentication flow

# Execute these Context7 commands before any code implementation:
mcp__context7__get-library-docs --context7CompatibleLibraryID="/spacy/scispacy" --topic="Medical entity recognition with UMLS concept identification"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/huggingface/transformers" --topic="Clinical BERT integration for medical content understanding"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/nltk/nltk" --topic="Medical terminology processing and semantic type classification"

# REQUIRED: Verify Doppler environment variables configured:
# UMLS_API_KEY, UMLS_TGT_URL, UMLS_AUTH_URL, UMLS_API_VERSION

# Then implement: Task R.2 UMLS Pipeline Enricher with clinical accuracy
# - Follow .user/UMLS.md authentication patterns
# - Use only Doppler-stored credentials (NO hardcoded keys)
# - Implement 20 req/sec rate limiting
```

**BSN Knowledge Content Generator Agent**:
```bash
# Execute these commands before any code implementation:
mcp__context7__get-library-docs --context7CompatibleLibraryID="/openai/openai-python" --topic="LLM integration for NCLEX question generation and clinical scenarios"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/pydantic/pydantic" --topic="Data validation for educational content and assessment models"
mcp__context7__get-library-docs --context7CompatibleLibraryID="/fastapi/fastapi" --topic="Educational API endpoint design with authentication"
# Then implement: BSN Knowledge educational content generation features
```

### SUCCESS VALIDATION

**Context7 Protocol Compliance Verified When**:
- [x] All 18+ pre-resolved Context7 library IDs confirmed and documented
- [ ] All RAGnostic processor agents have complete `get-library-docs` execution records
- [ ] UMLS integration implemented using Context7 medical NLP documentation
- [ ] UMLS API credentials configured exclusively in Doppler (verified .user/UMLS.md compliance)
- [ ] BSN Knowledge features implemented using Context7 educational API patterns
- [ ] BaseProcessor interface compliance verified against Context7 documentation
- [ ] Medical accuracy testing completed using Context7 clinical guidelines

**Implementation Success Criteria**:
- [ ] **RAGnostic Pipeline**: Pure data pipeline with UMLS enrichment, no application logic
- [ ] **Document/OCR/Media Processors**: Enhanced with Context7-guided medical accuracy
- [ ] **Batch Processing**: Operational with Context7-optimized performance patterns
- [ ] **BSN Knowledge**: Educational features migrated with Context7-guided content generation
- [ ] **API Integration**: Clean separation with Context7-documented interface patterns

---

## Conclusion

This revised plan properly separates concerns between RAGnostic (data pipeline) and BSN Knowledge (application layer), respecting the architectural boundaries defined in the planning conversation. RAGnostic becomes a focused, reusable pipeline that enriches and indexes medical content, while BSN Knowledge handles all educational content generation and assessment features.

**Enhanced with Context7 Planning Protocol**: The plan now includes comprehensive Context7 MCP integration with 18+ pre-resolved library IDs and exact `get-library-docs` commands for immediate subagent execution. This ensures medical accuracy, eliminates library resolution delays, and provides Context7-guided implementation patterns for both RAGnostic pipeline enhancements and BSN Knowledge educational features.

This separation ensures maintainability, scalability, clear architectural boundaries, and Context7-optimized medical content accuracy for both projects.
