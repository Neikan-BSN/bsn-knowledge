"""
Study Guide API endpoints for BSN Knowledge (Singular form for Phase 3 compatibility)
Provides an alias router for study guide creation endpoint
"""

from fastapi import APIRouter, Depends

from .study_guides import (
    StudyGuideRequest,
    StudyGuideResponse,
    create_study_guide_endpoint,
    get_content_service,
)

router = APIRouter(prefix="/study-guide", tags=["study-guide"])


@router.post("/create", response_model=StudyGuideResponse)
async def create_study_guide_alias(
    request: StudyGuideRequest, content_service=Depends(get_content_service)
):
    """
    REVISED_PHASE3_PLAN.md Required Endpoint: /api/v1/study-guide/create

    Create personalized study guide for nursing students.
    This endpoint is specifically required by the Phase 3 planning document.
    """
    # Delegate to the study guide creation function in study_guides router
    return await create_study_guide_endpoint(request, content_service)


@router.get("/health")
async def study_guide_service_health():
    """Health check for study guide service"""
    return {
        "service": "study_guide_generation",
        "status": "operational",
        "features": [
            "personalized_guides",
            "competency_aligned_content",
            "evidence_based_learning",
            "umls_enriched_content",
        ],
    }
