"""
NCLEX API endpoints for BSN Knowledge
Provides NCLEX-specific question generation and assessment
"""

from fastapi import APIRouter, Depends
from .quizzes import (
    QuizRequest,
    QuizResponse,
    get_content_service,
    generate_nclex_questions,
)

router = APIRouter(prefix="/nclex", tags=["nclex"])


@router.post("/generate", response_model=QuizResponse)
async def generate_nclex_endpoint(
    request: QuizRequest, content_service=Depends(get_content_service)
):
    """
    REVISED_PHASE3_PLAN.md Required Endpoint: /api/v1/nclex/generate

    Generate NCLEX-style questions for nursing students.
    This endpoint is specifically required by the Phase 3 planning document.
    """
    # Delegate to the NCLEX generation function in quizzes router
    return await generate_nclex_questions(request, content_service)


@router.get("/health")
async def nclex_service_health():
    """Health check for NCLEX service"""
    return {
        "service": "nclex_generation",
        "status": "operational",
        "features": [
            "nclex_style_questions",
            "nursing_specific_content",
            "medical_accuracy_validation",
            "evidence_based_rationales",
        ],
    }
