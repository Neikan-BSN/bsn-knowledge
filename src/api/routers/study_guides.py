import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...generators.study_guide_generator import (
    CompetencyFramework,
    LearningObjectiveType,
    StudyGuideGenerator,
)
from ...services.content_generation_service import ContentGenerationService
from ...services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/study-guides", tags=["study-guides"])


class StudyGuideRequest(BaseModel):
    topic: str
    difficulty_level: str = Field(
        default="intermediate", pattern="^(beginner|intermediate|advanced)$"
    )
    target_audience: str = "BSN students"
    section_count: int = Field(default=5, ge=2, le=10)
    competency_frameworks: list[str] = Field(default=["qsen", "nclex_categories"])
    include_clinical_applications: bool = True
    personalization_enabled: bool = False


class PersonalizedGuideRequest(BaseModel):
    topic: str
    student_profile: dict[str, Any]
    learning_path: list[str] | None = None


class CompetencyFocusedRequest(BaseModel):
    topic: str
    competency: str = Field(
        pattern="^(aacn_essentials|qsen|nclex_categories|nursing_process)$"
    )
    specific_standards: list[str] | None = None


class StudyGuideSection(BaseModel):
    title: str
    content: str
    learning_objectives: list[dict[str, Any]]
    key_concepts: list[str]
    clinical_applications: list[str]
    study_questions: list[str]
    estimated_study_time: int


class StudyGuideResponse(BaseModel):
    id: str
    title: str
    topic: str
    difficulty_level: str
    target_audience: str
    sections: list[StudyGuideSection]
    overall_objectives: list[dict[str, Any]]
    prerequisites: list[str]
    estimated_completion_time: int
    competency_alignment: dict[str, list[str]]
    evidence_citations: list[str]
    created_at: str
    generation_metadata: dict[str, Any]


# Dependency injection for services
async def get_content_service():
    ragnostic_client = RAGnosticClient()
    content_service = ContentGenerationService(
        openai_api_key="your-openai-key",  # Would be injected from config  # noqa: S106
        ragnostic_client=ragnostic_client,
    )
    return content_service


@router.post("/", response_model=StudyGuideResponse)
async def create_study_guide(
    request: StudyGuideRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Create a comprehensive study guide using RAGnostic UMLS-enriched content
    """
    try:
        generator = StudyGuideGenerator(content_service)

        # Parse competency frameworks
        frameworks = []
        for fw in request.competency_frameworks:
            try:
                frameworks.append(CompetencyFramework(fw))
            except ValueError:
                logger.warning(f"Unknown competency framework: {fw}")
                continue

        if not frameworks:
            frameworks = [
                CompetencyFramework.QSEN,
                CompetencyFramework.NCLEX_CATEGORIES,
            ]

        # Generate study guide
        study_guide = await generator.generate_guide(
            topic=request.topic,
            difficulty_level=request.difficulty_level,
            target_audience=request.target_audience,
            section_count=request.section_count,
            competency_frameworks=frameworks,
        )

        # Convert to API response format
        sections = [
            StudyGuideSection(
                title=section.title,
                content=section.content,
                learning_objectives=[obj.dict() for obj in section.learning_objectives],
                key_concepts=section.key_concepts,
                clinical_applications=section.clinical_applications,
                study_questions=section.study_questions,
                estimated_study_time=section.estimated_study_time,
            )
            for section in study_guide.sections
        ]

        return StudyGuideResponse(
            id=study_guide.id,
            title=study_guide.title,
            topic=study_guide.topic,
            difficulty_level=study_guide.difficulty_level,
            target_audience=study_guide.target_audience,
            sections=sections,
            overall_objectives=[obj.dict() for obj in study_guide.overall_objectives],
            prerequisites=study_guide.prerequisites,
            estimated_completion_time=study_guide.estimated_completion_time,
            competency_alignment=study_guide.competency_alignment,
            evidence_citations=study_guide.evidence_citations,
            created_at=study_guide.created_at.isoformat(),
            generation_metadata=study_guide.generation_metadata,
        )

    except Exception as e:
        logger.error(f"Study guide creation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Study guide generation failed: {str(e) from e}"
        )


@router.post("/personalized", response_model=StudyGuideResponse)
async def create_personalized_study_guide(
    request: PersonalizedGuideRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Create a personalized study guide based on student profile
    """
    try:
        generator = StudyGuideGenerator(content_service)

        # Generate personalized guide
        study_guide = await generator.generate_personalized_guide(
            topic=request.topic,
            student_profile=request.student_profile,
            learning_path=request.learning_path,
        )

        # Convert to response format (same as above)
        sections = [
            StudyGuideSection(
                title=section.title,
                content=section.content,
                learning_objectives=[obj.dict() for obj in section.learning_objectives],
                key_concepts=section.key_concepts,
                clinical_applications=section.clinical_applications,
                study_questions=section.study_questions,
                estimated_study_time=section.estimated_study_time,
            )
            for section in study_guide.sections
        ]

        return StudyGuideResponse(
            id=study_guide.id,
            title=study_guide.title,
            topic=study_guide.topic,
            difficulty_level=study_guide.difficulty_level,
            target_audience=study_guide.target_audience,
            sections=sections,
            overall_objectives=[obj.dict() for obj in study_guide.overall_objectives],
            prerequisites=study_guide.prerequisites,
            estimated_completion_time=study_guide.estimated_completion_time,
            competency_alignment=study_guide.competency_alignment,
            evidence_citations=study_guide.evidence_citations,
            created_at=study_guide.created_at.isoformat(),
            generation_metadata=study_guide.generation_metadata,
        )

    except Exception as e:
        logger.error(f"Personalized study guide creation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Personalized guide generation failed: {str(e) from e}"
        )


@router.post("/competency-focused", response_model=StudyGuideResponse)
async def create_competency_focused_guide(
    request: CompetencyFocusedRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Create study guide focused on specific nursing competency standards
    """
    try:
        generator = StudyGuideGenerator(content_service)

        # Parse competency framework
        try:
            competency = CompetencyFramework(request.competency)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown competency framework: {request.competency}",
            ) from e

        # Generate competency-focused guide
        study_guide = await generator.generate_competency_focused_guide(
            topic=request.topic,
            competency=competency,
            specific_standards=request.specific_standards,
        )

        # Convert to response format
        sections = [
            StudyGuideSection(
                title=section.title,
                content=section.content,
                learning_objectives=[obj.dict() for obj in section.learning_objectives],
                key_concepts=section.key_concepts,
                clinical_applications=section.clinical_applications,
                study_questions=section.study_questions,
                estimated_study_time=section.estimated_study_time,
            )
            for section in study_guide.sections
        ]

        return StudyGuideResponse(
            id=study_guide.id,
            title=study_guide.title,
            topic=study_guide.topic,
            difficulty_level=study_guide.difficulty_level,
            target_audience=study_guide.target_audience,
            sections=sections,
            overall_objectives=[obj.dict() for obj in study_guide.overall_objectives],
            prerequisites=study_guide.prerequisites,
            estimated_completion_time=study_guide.estimated_completion_time,
            competency_alignment=study_guide.competency_alignment,
            evidence_citations=study_guide.evidence_citations,
            created_at=study_guide.created_at.isoformat(),
            generation_metadata=study_guide.generation_metadata,
        )

    except Exception as e:
        logger.error(f"Competency-focused guide creation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Competency guide generation failed: {str(e) from e}"
        )


@router.post("/customize/{guide_id}", response_model=StudyGuideResponse)
async def customize_study_guide(
    guide_id: str,
    student_profile: dict[str, Any],
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Customize an existing study guide based on student profile
    """
    try:
        # This would retrieve the original guide from storage
        # For now, return a placeholder response indicating customization capability
        raise HTTPException(
            status_code=501, detail="Guide customization requires storage integration"
        ) from e

    except Exception as e:
        logger.error(f"Study guide customization failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Customization failed: {str(e) from e}")


@router.get("/topics", response_model=list[str])
async def get_available_topics(
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Get available study guide topics
    """
    try:
        generator = StudyGuideGenerator(content_service)
        return await generator.get_available_topics()
    except Exception as e:
        logger.error(f"Failed to get topics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve topics") from e


@router.get("/competency-frameworks", response_model=list[str])
async def get_competency_frameworks():
    """
    Get available nursing competency frameworks
    """
    return [framework.value for framework in CompetencyFramework]


@router.get("/objective-types", response_model=list[str])
async def get_learning_objective_types():
    """
    Get available learning objective types (Bloom's taxonomy)
    """
    return [obj_type.value for obj_type in LearningObjectiveType]


@router.get("/", response_model=list[StudyGuideResponse])
async def list_study_guides(topic: str | None = None, difficulty: str | None = None):
    """
    List existing study guides (placeholder - would integrate with storage)
    """
    # This would integrate with a database/storage system
    return []


@router.get("/guide/{guide_id}", response_model=StudyGuideResponse)
async def get_study_guide(guide_id: str):
    """
    Get specific study guide by ID (placeholder - would integrate with storage)
    """
    # This would retrieve from database/storage
    raise HTTPException(status_code=404, detail="Study guide not found") from e


@router.post("/create", response_model=StudyGuideResponse)
async def create_study_guide_endpoint(
    request: StudyGuideRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    REVISED_PHASE3_PLAN.md Required Endpoint: Create personalized study guide

    This is the specific endpoint required by Phase 3 planning documents.
    Delegates to the main study guide creation functionality.
    """
    try:
        # Use the existing study guide creation logic
        return await create_study_guide(request, content_service)

    except Exception as e:
        logger.error(f"Study guide creation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Study guide creation failed: {str(e) from e}"
        )


@router.get("/health")
async def study_guide_service_health():
    """
    Health check for study guide service
    """
    return {
        "service": "study_guide_generation",
        "status": "operational",
        "features": [
            "comprehensive_guides",
            "personalized_content",
            "competency_alignment",
            "umls_enriched_content",
            "evidence_based_learning",
        ],
        "timestamp": datetime.utcnow().isoformat(),
    }
