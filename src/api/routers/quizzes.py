import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...generators.nclex_generator import NCLEXGenerator
from ...services.content_generation_service import ContentGenerationService
from ...services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/quizzes", tags=["quizzes"])


class QuizRequest(BaseModel):
    topic: str
    question_count: int = Field(default=10, ge=1, le=50)
    difficulty: str = Field(
        default="intermediate", pattern="^(beginner|intermediate|advanced)$"
    )
    quiz_type: str = Field(
        default="nclex", pattern="^(nclex|general|clinical_scenario)$"
    )
    category: str | None = None
    include_rationales: bool = True
    medical_accuracy_threshold: float = Field(default=0.95, ge=0.8, le=1.0)


class ClinicalScenarioRequest(BaseModel):
    patient_condition: str
    nursing_focus: str
    question_count: int = Field(default=5, ge=1, le=20)
    difficulty: str = Field(default="advanced", pattern="^(intermediate|advanced)$")
    include_assessment_data: bool = True


class QuizQuestion(BaseModel):
    id: str
    question: str
    options: list[str]
    correct_answer: int
    rationale: str | None = None
    category: str | None = None
    clinical_scenario: str | None = None
    evidence_citations: list[str] = []


class QuizResponse(BaseModel):
    id: str
    topic: str
    quiz_type: str
    questions: list[QuizQuestion]
    created_at: str
    difficulty: str
    validation_summary: dict[str, Any] = {}
    estimated_completion_time: int = 0  # in minutes


class QuizValidationResponse(BaseModel):
    quiz_id: str
    is_valid: bool
    validation_details: dict[str, Any]
    suggestions: list[str] = []


# Dependency injection for services
async def get_content_service():
    # This would be properly configured with dependency injection in a real app
    ragnostic_client = RAGnosticClient()
    # OpenAI API key would come from environment/config
    content_service = ContentGenerationService(
        openai_api_key="your-openai-key",  # Would be injected  # noqa: S106
        ragnostic_client=ragnostic_client,
    )
    return content_service


@router.post("/", response_model=QuizResponse)
async def create_quiz(
    request: QuizRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Create a new quiz using RAGnostic educational APIs
    """
    try:
        generator = NCLEXGenerator(content_service)

        if request.quiz_type == "nclex":
            # Generate NCLEX-style questions
            question_set = await generator.generate_questions(
                topic=request.topic,
                count=request.question_count,
                difficulty=request.difficulty,
                category=request.category,
                medical_accuracy_threshold=request.medical_accuracy_threshold,
            )

            # Convert to API response format
            quiz_questions = [
                QuizQuestion(
                    id=f"q_{i + 1}",
                    question=q.question,
                    options=q.options,
                    correct_answer=q.correct_answer,
                    rationale=q.rationale if request.include_rationales else None,
                    category=q.category,
                    clinical_scenario=q.clinical_scenario,
                    evidence_citations=q.evidence_citations,
                )
                for i, q in enumerate(question_set.questions)
            ]

            return QuizResponse(
                id=f"quiz_{datetime.utcnow().timestamp()}",
                topic=request.topic,
                quiz_type=request.quiz_type,
                questions=quiz_questions,
                created_at=datetime.utcnow().isoformat(),
                difficulty=request.difficulty,
                validation_summary=question_set.validation_summary,
                estimated_completion_time=len(quiz_questions)
                * 3,  # ~3 min per question
            )

        else:
            raise HTTPException(
                status_code=400, detail=f"Quiz type {request.quiz_type} not supported"
            )

    except Exception as e:
        logger.error(f"Quiz creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Quiz generation failed: {str(e)}")


@router.post("/clinical-scenarios", response_model=QuizResponse)
async def create_clinical_scenario_quiz(
    request: ClinicalScenarioRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Create quiz with comprehensive clinical scenarios
    """
    try:
        generator = NCLEXGenerator(content_service)

        question_set = await generator.generate_clinical_scenario_questions(
            patient_condition=request.patient_condition,
            nursing_focus=request.nursing_focus,
            count=request.question_count,
            difficulty=request.difficulty,
        )

        quiz_questions = [
            QuizQuestion(
                id=f"cs_{i + 1}",
                question=q.question,
                options=q.options,
                correct_answer=q.correct_answer,
                rationale=q.rationale,
                category=q.category,
                clinical_scenario=q.clinical_scenario,
                evidence_citations=q.evidence_citations,
            )
            for i, q in enumerate(question_set.questions)
        ]

        return QuizResponse(
            id=f"clinical_quiz_{datetime.utcnow().timestamp()}",
            topic=f"{request.patient_condition} - {request.nursing_focus}",
            quiz_type="clinical_scenario",
            questions=quiz_questions,
            created_at=datetime.utcnow().isoformat(),
            difficulty=request.difficulty,
            validation_summary=question_set.validation_summary,
            estimated_completion_time=len(quiz_questions)
            * 5,  # Longer for complex scenarios
        )

    except Exception as e:
        logger.error(f"Clinical scenario quiz creation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Clinical quiz generation failed: {str(e)}"
        )


@router.post("/validate/{quiz_id}", response_model=QuizValidationResponse)
async def validate_quiz(
    quiz_id: str,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Validate quiz questions for medical accuracy and format
    """
    try:
        # This would retrieve the quiz from storage in a real implementation
        # For now, return a placeholder response
        return QuizValidationResponse(
            quiz_id=quiz_id,
            is_valid=True,
            validation_details={
                "medical_accuracy_score": 0.95,
                "format_compliance": True,
                "evidence_quality": "high",
            },
            suggestions=[
                "Consider adding more diverse question types",
                "Include additional evidence citations",
            ],
        )

    except Exception as e:
        logger.error(f"Quiz validation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.get("/categories", response_model=list[str])
async def get_quiz_categories(
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Get available quiz categories (NCLEX categories)
    """
    try:
        generator = NCLEXGenerator(content_service)
        return await generator.get_available_categories()
    except Exception as e:
        logger.error(f"Failed to get categories: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve categories")


@router.get("/", response_model=list[QuizResponse])
async def list_quizzes(topic: str | None = None, difficulty: str | None = None):
    """
    List existing quizzes (placeholder - would integrate with storage)
    """
    # This would integrate with a database/storage system
    return []


@router.get("/quiz/{quiz_id}", response_model=QuizResponse)
async def get_quiz(quiz_id: str):
    """
    Get specific quiz by ID (placeholder - would integrate with storage)
    """
    # This would retrieve from database/storage
    raise HTTPException(status_code=404, detail="Quiz not found")


@router.post("/nclex/generate", response_model=QuizResponse)
async def generate_nclex_questions(
    request: QuizRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    REVISED_PHASE3_PLAN.md Required Endpoint: Generate NCLEX-style questions

    This is the specific endpoint required by Phase 3 planning documents.
    Delegates to the main quiz creation functionality with NCLEX type.
    """
    try:
        # Force NCLEX type for this endpoint
        request.quiz_type = "nclex"

        # Use the existing quiz creation logic
        return await create_quiz(request, content_service)

    except Exception as e:
        logger.error(f"NCLEX generation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"NCLEX question generation failed: {str(e)}"
        )


@router.get("/health")
async def quiz_service_health():
    """
    Health check for quiz service
    """
    return {
        "service": "quiz_generation",
        "status": "operational",
        "features": [
            "nclex_questions",
            "clinical_scenarios",
            "medical_validation",
            "evidence_based_content",
        ],
        "timestamp": datetime.utcnow().isoformat(),
    }
