"""RAGnostic Mock Service for E2E Pipeline Testing.

Realistic simulation of RAGnostic API with:
- Medical content processing
- UMLS concept integration
- Configurable response delays and error rates
- Comprehensive health monitoring
"""

import asyncio
import logging
import os
import random
import time
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
MOCK_MODE = os.getenv("MOCK_MODE", "true").lower() == "true"
RESPONSE_DELAY_MS = int(os.getenv("RESPONSE_DELAY_MS", "50"))
ERROR_RATE = float(os.getenv("ERROR_RATE", "0.02"))  # 2% error rate
SERVICE_NAME = os.getenv("SERVICE_NAME", "ragnostic-mock")


# Request/Response Models
class ContentProcessingRequest(BaseModel):
    content: str = Field(..., min_length=10)
    processing_type: str = Field(default="medical_enrichment")
    umls_integration: bool = Field(default=True)
    generate_questions: bool = Field(default=False)
    target_education_level: str = Field(default="undergraduate_nursing")


class UMLSConcept(BaseModel):
    cui: str
    preferred_name: str
    semantic_type: str
    definition: str | None = None
    confidence_score: float = Field(ge=0.0, le=1.0)


class GeneratedQuestion(BaseModel):
    id: str
    question: str
    options: list[str]
    correct_answer: str
    rationale: str
    difficulty: str
    nclex_category: str
    umls_concepts: list[str]


class ContentProcessingResponse(BaseModel):
    processed_content: str
    enriched_content: str
    medical_concepts: list[UMLSConcept]
    generated_questions: list[GeneratedQuestion] | None = None
    processing_metadata: dict[str, Any]
    processing_time_ms: float


class BatchProcessingRequest(BaseModel):
    batch_size: int = Field(ge=1, le=100)
    topics: list[str]
    difficulty_levels: list[str]
    question_types: list[str]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    service: str
    version: str
    uptime_seconds: float
    processed_requests: int
    error_count: int
    avg_response_time_ms: float


# Mock data for realistic responses
MOCK_UMLS_CONCEPTS = {
    "cardiovascular": [
        UMLSConcept(
            cui="C0007226",
            preferred_name="Cardiovascular System",
            semantic_type="Body System",
            definition="The system of heart and blood vessels",
            confidence_score=0.95,
        ),
        UMLSConcept(
            cui="C0018787",
            preferred_name="Heart",
            semantic_type="Body Part",
            definition="Muscular organ that pumps blood",
            confidence_score=0.98,
        ),
        UMLSConcept(
            cui="C0232337",
            preferred_name="Cardiovascular Assessment",
            semantic_type="Health Care Activity",
            definition="Systematic evaluation of heart and circulatory function",
            confidence_score=0.92,
        ),
    ],
    "medication": [
        UMLSConcept(
            cui="C0013227",
            preferred_name="Drug Administration",
            semantic_type="Health Care Activity",
            definition="Process of giving medications to patients",
            confidence_score=0.94,
        ),
        UMLSConcept(
            cui="C0150270",
            preferred_name="Medication Safety",
            semantic_type="Idea or Concept",
            definition="Practices to prevent medication errors",
            confidence_score=0.97,
        ),
        UMLSConcept(
            cui="C0013230",
            preferred_name="Drug Therapy",
            semantic_type="Therapeutic Procedure",
            definition="Treatment using pharmaceutical agents",
            confidence_score=0.89,
        ),
    ],
    "infection": [
        UMLSConcept(
            cui="C0085557",
            preferred_name="Infection Control",
            semantic_type="Health Care Activity",
            definition="Measures to prevent spread of infectious agents",
            confidence_score=0.96,
        ),
        UMLSConcept(
            cui="C1292711",
            preferred_name="Hand Hygiene",
            semantic_type="Health Care Activity",
            definition="Practice of cleaning hands to prevent infection",
            confidence_score=0.99,
        ),
        UMLSConcept(
            cui="C0009482",
            preferred_name="Communicable Disease Control",
            semantic_type="Health Care Activity",
            definition="Prevention and control of infectious diseases",
            confidence_score=0.91,
        ),
    ],
}

MOCK_QUESTIONS = [
    GeneratedQuestion(
        id="mock_q1",
        question="A patient with heart failure is prescribed digoxin 0.25 mg daily. Which assessment finding would indicate possible digoxin toxicity?",
        options=[
            "A. Heart rate of 88 beats per minute",
            "B. Nausea and visual disturbances",
            "C. Blood pressure of 130/80 mmHg",
            "D. Respiratory rate of 20 breaths per minute",
        ],
        correct_answer="B",
        rationale="Nausea and visual disturbances are classic early signs of digoxin toxicity due to the drug's narrow therapeutic window.",
        difficulty="medium",
        nclex_category="Pharmacological and Parenteral Therapies",
        umls_concepts=["C0018787", "C0013227"],
    ),
    GeneratedQuestion(
        id="mock_q2",
        question="Which action should the nurse take first when administering medications to ensure patient safety?",
        options=[
            "A. Check the patient's identification",
            "B. Verify the physician's order",
            "C. Perform hand hygiene",
            "D. Prepare the medication",
        ],
        correct_answer="C",
        rationale="Hand hygiene is the first step in any patient care activity to prevent healthcare-associated infections.",
        difficulty="easy",
        nclex_category="Safety and Infection Control",
        umls_concepts=["C1292711", "C0013227"],
    ),
]

# Application state
app_state = {
    "start_time": time.time(),
    "processed_requests": 0,
    "error_count": 0,
    "response_times": [],
}

# FastAPI app
app = FastAPI(
    title="RAGnostic Mock Service",
    description="Mock RAGnostic API for E2E Pipeline Testing",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def track_requests(request: Request, call_next):
    """Track request metrics for health monitoring."""
    start_time = time.time()

    # Simulate random errors based on error rate
    if random.random() < ERROR_RATE:
        app_state["error_count"] += 1
        raise HTTPException(status_code=500, detail="Simulated service error")

    response = await call_next(request)

    # Track metrics
    process_time = (time.time() - start_time) * 1000  # Convert to ms
    app_state["processed_requests"] += 1
    app_state["response_times"].append(process_time)

    # Keep only last 1000 response times for memory efficiency
    if len(app_state["response_times"]) > 1000:
        app_state["response_times"] = app_state["response_times"][-1000:]

    response.headers["X-Process-Time"] = str(process_time)
    return response


def get_mock_concepts(content: str) -> list[UMLSConcept]:
    """Extract relevant UMLS concepts based on content keywords."""
    content_lower = content.lower()
    concepts = []

    for category, category_concepts in MOCK_UMLS_CONCEPTS.items():
        if category in content_lower or any(
            word in content_lower
            for word in [
                "heart",
                "cardiac",
                "blood",
                "circulation",
                "pressure" if category == "cardiovascular" else "drug",
                "medication",
                "dose",
                "administration",
                "therapy" if category == "medication" else "infection",
                "hygiene",
                "control",
                "prevention",
                "sterile",
            ]
        ):
            concepts.extend(category_concepts)

    # Return unique concepts (avoid duplicates)
    seen_cuis = set()
    unique_concepts = []
    for concept in concepts:
        if concept.cui not in seen_cuis:
            unique_concepts.append(concept)
            seen_cuis.add(concept.cui)

    return unique_concepts[:5]  # Limit to 5 most relevant concepts


def enrich_content(original_content: str, concepts: list[UMLSConcept]) -> str:
    """Enrich content with medical terminology and context."""
    enriched = original_content

    # Add concept definitions and context
    for concept in concepts:
        if (
            concept.definition
            and concept.preferred_name.lower() in original_content.lower()
        ):
            enriched += f"\n\n{concept.preferred_name}: {concept.definition}"

    # Add educational context
    enriched += "\n\nEducational Context: This content has been enhanced with standardized medical terminology from the Unified Medical Language System (UMLS) to ensure clinical accuracy and consistency with healthcare standards."

    return enriched


def generate_mock_questions(
    content: str, concepts: list[UMLSConcept], count: int = 5
) -> list[GeneratedQuestion]:
    """Generate mock questions based on content and concepts."""
    # In a real implementation, this would use AI to generate questions
    # For mock purposes, we return pre-defined questions with slight variations

    questions = []
    base_questions = MOCK_QUESTIONS.copy()

    for i in range(min(count, len(base_questions) * 2)):
        base_q = base_questions[i % len(base_questions)]

        # Create variations
        question = GeneratedQuestion(
            id=f"mock_q_{i + 1}_{int(time.time())}",
            question=base_q.question,
            options=base_q.options.copy(),
            correct_answer=base_q.correct_answer,
            rationale=base_q.rationale,
            difficulty=base_q.difficulty,
            nclex_category=base_q.nclex_category,
            umls_concepts=[c.cui for c in concepts[:2]],  # Link to relevant concepts
        )

        questions.append(question)

    return questions[:count]


@app.post("/api/v1/process", response_model=ContentProcessingResponse)
async def process_content(request: ContentProcessingRequest):
    """Process medical content with UMLS enrichment and optional question generation."""
    start_time = time.time()

    # Simulate processing delay
    await asyncio.sleep(RESPONSE_DELAY_MS / 1000.0)

    logger.info(f"Processing content: {request.content[:100]}...")

    # Extract UMLS concepts
    concepts = get_mock_concepts(request.content)

    # Enrich content
    enriched_content = enrich_content(request.content, concepts)

    # Generate questions if requested
    questions = None
    if request.generate_questions:
        questions = generate_mock_questions(request.content, concepts, 5)

    processing_time = (time.time() - start_time) * 1000

    return ContentProcessingResponse(
        processed_content=request.content,
        enriched_content=enriched_content,
        medical_concepts=concepts,
        generated_questions=questions,
        processing_metadata={
            "processing_type": request.processing_type,
            "umls_integration_enabled": request.umls_integration,
            "education_level": request.target_education_level,
            "concepts_found": len(concepts),
            "questions_generated": len(questions) if questions else 0,
        },
        processing_time_ms=processing_time,
    )


@app.post("/api/v1/questions/batch-generate")
async def batch_generate_questions(request: BatchProcessingRequest):
    """Generate questions in batch for multiple topics."""
    start_time = time.time()

    # Simulate batch processing delay
    await asyncio.sleep((RESPONSE_DELAY_MS * request.batch_size) / 1000.0)

    logger.info(
        f"Batch generating {request.batch_size} questions for topics: {request.topics}"
    )

    # Generate questions for each topic
    all_questions = []
    for topic in request.topics:
        topic_concepts = MOCK_UMLS_CONCEPTS.get(topic, [])
        if not topic_concepts:
            # Use generic concepts if topic not found
            topic_concepts = list(MOCK_UMLS_CONCEPTS.values())[0]

        questions_per_topic = request.batch_size // len(request.topics)
        topic_questions = generate_mock_questions(
            f"Educational content about {topic}", topic_concepts, questions_per_topic
        )
        all_questions.extend(topic_questions)

    processing_time = (time.time() - start_time) * 1000

    return {
        "batch_id": f"batch_{int(time.time())}",
        "questions": all_questions,
        "metadata": {
            "requested_count": request.batch_size,
            "generated_count": len(all_questions),
            "topics": request.topics,
            "processing_time_ms": processing_time,
        },
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Comprehensive health check endpoint."""
    uptime = time.time() - app_state["start_time"]
    avg_response_time = (
        sum(app_state["response_times"]) / len(app_state["response_times"])
        if app_state["response_times"]
        else 0
    )

    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        service=SERVICE_NAME,
        version="1.0.0",
        uptime_seconds=uptime,
        processed_requests=app_state["processed_requests"],
        error_count=app_state["error_count"],
        avg_response_time_ms=avg_response_time,
    )


@app.get("/api/v1/health/detailed")
async def detailed_health_check():
    """Detailed health check with system metrics."""
    uptime = time.time() - app_state["start_time"]
    response_times = app_state["response_times"]

    # Calculate response time percentiles
    if response_times:
        sorted_times = sorted(response_times)
        p50 = sorted_times[len(sorted_times) // 2]
        p95 = sorted_times[int(0.95 * len(sorted_times))]
        p99 = (
            sorted_times[int(0.99 * len(sorted_times))]
            if len(sorted_times) >= 100
            else sorted_times[-1]
        )
    else:
        p50 = p95 = p99 = 0

    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": uptime,
        "metrics": {
            "processed_requests": app_state["processed_requests"],
            "error_count": app_state["error_count"],
            "error_rate": app_state["error_count"]
            / max(app_state["processed_requests"], 1),
            "response_times_ms": {
                "avg": sum(response_times) / len(response_times)
                if response_times
                else 0,
                "p50": p50,
                "p95": p95,
                "p99": p99,
            },
        },
        "configuration": {
            "mock_mode": MOCK_MODE,
            "response_delay_ms": RESPONSE_DELAY_MS,
            "error_rate": ERROR_RATE,
        },
    }


@app.get("/api/v1/concepts/{cui}")
async def get_concept_details(cui: str):
    """Get detailed information about a UMLS concept."""
    # Search for concept across all categories
    for category_concepts in MOCK_UMLS_CONCEPTS.values():
        for concept in category_concepts:
            if concept.cui == cui:
                return {
                    "cui": concept.cui,
                    "preferred_name": concept.preferred_name,
                    "semantic_type": concept.semantic_type,
                    "definition": concept.definition,
                    "confidence_score": concept.confidence_score,
                    "related_concepts": [
                        c.cui for c in category_concepts if c.cui != cui
                    ][:3],
                }

    raise HTTPException(status_code=404, detail=f"Concept {cui} not found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info", reload=False)
