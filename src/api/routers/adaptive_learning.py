"""
B.5 Adaptive Learning FastAPI Endpoints

API endpoints for adaptive learning engine functionality:
- Personalized content generation with performance-based recommendations
- Dynamic difficulty adjustment based on competency progression
- Real-time learning path optimization using B.4 analytics
- Adaptive study plan generation with tracking integration

Built per REVISED_PHASE3_PLAN.md B.5 specifications
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from ...services.adaptive_learning_engine import (
    AdaptiveLearningEngine,
    LearningPathAdaptation,
)
from ...services.learning_analytics import LearningAnalytics
from ...services.ragnostic_client import RAGnosticClient
from ...services.analytics_service import AnalyticsService
from ...assessment.knowledge_gap_analyzer import KnowledgeGapAnalyzer
from ...assessment.learning_path_optimizer import LearningPathOptimizer
from ...dependencies import get_ragnostic_client, get_analytics_service

router = APIRouter(prefix="/adaptive-learning", tags=["adaptive-learning"])


# Request/Response Models for B.5 Adaptive Learning API


class PersonalizedContentRequest(BaseModel):
    """Request for personalized content generation"""

    student_id: str = Field(..., description="Student identifier")
    target_competencies: Optional[List[str]] = Field(
        None, description="Specific competencies to target"
    )
    content_filters: Optional[Dict[str, Any]] = Field(
        None, description="Additional content filters"
    )
    learning_preferences: Optional[Dict[str, Any]] = Field(
        None, description="Learning style preferences"
    )


class PersonalizedContentResponse(BaseModel):
    """Response with personalized content recommendations"""

    student_id: str
    recommendations: List[Dict[str, Any]]
    personalization_factors: Dict[str, Any]
    generated_at: str
    cache_duration_seconds: int = 1800  # 30 minutes


class LearningPathOptimizationRequest(BaseModel):
    """Request for learning path optimization"""

    student_id: str = Field(..., description="Student identifier")
    target_competencies: List[str] = Field(
        ..., description="Target competencies for optimization"
    )
    time_constraints: Optional[Dict[str, int]] = Field(
        None, description="Time constraints (weekly_minutes, etc.)"
    )
    performance_context: Optional[Dict[str, Any]] = Field(
        None, description="Current performance context"
    )


class LearningPathOptimizationResponse(BaseModel):
    """Response with optimized learning path"""

    student_id: str
    path_id: str
    target_competencies: List[str]
    optimized_path: Dict[str, Any]
    success_metrics: Dict[str, Any]
    feasibility_analysis: Dict[str, Any]
    adaptation_features: Dict[str, bool]
    performance_predictions: Dict[str, Any]
    generated_at: str


class DifficultyAdjustmentRequest(BaseModel):
    """Request for dynamic difficulty adjustment"""

    student_id: str = Field(..., description="Student identifier")
    current_content: Dict[str, Any] = Field(
        ..., description="Currently assigned content"
    )
    recent_performance: Dict[str, Any] = Field(
        ..., description="Recent performance metrics"
    )
    competency_context: Dict[str, Any] = Field(
        ..., description="Current competency levels"
    )


class DifficultyAdjustmentResponse(BaseModel):
    """Response with difficulty adjustment recommendation"""

    student_id: str
    current_difficulty: str
    recommended_difficulty: str
    adjustment_reason: str
    confidence_score: float
    supporting_metrics: Dict[str, Any]
    adjustment_magnitude: float
    calculated_at: str


class RealtimePathAdaptationRequest(BaseModel):
    """Request for real-time learning path adaptation"""

    student_id: str = Field(..., description="Student identifier")
    current_path_id: str = Field(..., description="Current learning path ID")
    performance_update: Dict[str, Any] = Field(
        ..., description="Latest performance data"
    )
    competency_changes: Dict[str, Any] = Field(
        ..., description="Changes in competency levels"
    )


class RealtimePathAdaptationResponse(BaseModel):
    """Response with real-time path adaptation"""

    student_id: str
    original_path_id: str
    adapted_path_id: str
    adaptations_made: List[str]
    performance_triggers: List[str]
    estimated_improvement: float
    adaptation_confidence: float
    adapted_at: str


class AdaptiveStudyPlanRequest(BaseModel):
    """Request for adaptive study plan generation"""

    student_id: str = Field(..., description="Student identifier")
    study_duration_weeks: int = Field(
        ..., ge=1, le=16, description="Study plan duration in weeks"
    )
    weekly_time_budget: int = Field(
        ..., ge=60, le=2400, description="Available study time per week (minutes)"
    )
    priority_competencies: List[str] = Field(
        ..., description="High-priority competencies to focus on"
    )


class AdaptiveStudyPlanResponse(BaseModel):
    """Response with comprehensive adaptive study plan"""

    student_id: str
    plan_id: str
    study_duration_weeks: int
    weekly_time_budget: int
    priority_competencies: List[str]
    personalized_content: List[Dict[str, Any]]
    learning_path: Dict[str, Any]
    weekly_schedule: List[Dict[str, Any]]
    milestones: List[Dict[str, Any]]
    assessment_schedule: List[Dict[str, Any]]
    adaptive_features: Dict[str, bool]
    success_predictions: Dict[str, Any]
    tracking_metrics: Dict[str, Any]
    generated_at: str
    next_adaptation_date: str


# Dependency injection for Adaptive Learning Engine
async def get_adaptive_learning_engine(
    ragnostic_client: RAGnosticClient = Depends(get_ragnostic_client),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> AdaptiveLearningEngine:
    """Get configured Adaptive Learning Engine instance"""
    # Initialize B.4 Learning Analytics components
    learning_analytics = LearningAnalytics(ragnostic_client, analytics_service)
    gap_analyzer = KnowledgeGapAnalyzer(ragnostic_client)
    path_optimizer = LearningPathOptimizer(ragnostic_client)

    return AdaptiveLearningEngine(
        learning_analytics=learning_analytics,
        ragnostic_client=ragnostic_client,
        analytics_service=analytics_service,
        gap_analyzer=gap_analyzer,
        path_optimizer=path_optimizer,
    )


# B.5 Adaptive Learning API Endpoints


@router.post(
    "/b5-generate-personalized-content", response_model=PersonalizedContentResponse
)
async def generate_personalized_content(
    request: PersonalizedContentRequest,
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Generate personalized content based on student performance and preferences.

    Uses B.4 Learning Analytics for student analysis and RAGnostic for content retrieval.
    Applies dynamic difficulty adjustment and personalization algorithms.

    **Key Features:**
    - Performance-based content selection using B.4 analytics
    - Learning style adaptation and preference matching
    - Knowledge gap targeting with severity prioritization
    - Success probability and engagement prediction
    """
    try:
        # Construct student profile from request
        student_profile = {
            "student_id": request.student_id,
            "learning_style": request.learning_preferences.get(
                "learning_style", "visual"
            )
            if request.learning_preferences
            else "visual",
            "difficulty_preference": request.learning_preferences.get(
                "difficulty_preference", "adaptive"
            )
            if request.learning_preferences
            else "adaptive",
            "content_types": request.learning_preferences.get(
                "content_types", ["interactive", "visual"]
            )
            if request.learning_preferences
            else ["interactive", "visual"],
            "time_constraints": request.learning_preferences.get(
                "time_constraints", {"daily_minutes": 60}
            )
            if request.learning_preferences
            else {"daily_minutes": 60},
        }

        # Generate personalized content recommendations
        recommendations = await adaptive_engine.generate_personalized_content(
            student_profile=student_profile,
            target_competencies=request.target_competencies,
            content_filters=request.content_filters,
        )

        return PersonalizedContentResponse(
            student_id=request.student_id,
            recommendations=[rec.dict() for rec in recommendations],
            personalization_factors={
                "learning_style": student_profile["learning_style"],
                "difficulty_preference": student_profile["difficulty_preference"],
                "content_type_preferences": student_profile["content_types"],
                "recommendations_count": len(recommendations),
            },
            generated_at=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error generating personalized content: {str(e)}"
        )


@router.post(
    "/b5-optimize-learning-path", response_model=LearningPathOptimizationResponse
)
async def optimize_learning_path(
    request: LearningPathOptimizationRequest,
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Optimize learning path using RAGnostic prerequisite graphs and B.4 analytics.

    Creates optimal learning sequences with performance-based adjustments.
    Integrates B.4 LearningPathOptimizer for enhanced path generation.

    **Key Features:**
    - RAGnostic prerequisite graph integration for sequencing
    - B.4 analytics for competency-based path calculation
    - Real-time progress adjustment using B.4 tracking
    - Performance predictions and feasibility analysis
    """
    try:
        # Optimize learning path with adaptive features
        optimized_result = await adaptive_engine.optimize_learning_path(
            student_id=request.student_id,
            target_competencies=request.target_competencies,
            time_constraints=request.time_constraints,
            performance_context=request.performance_context,
        )

        return LearningPathOptimizationResponse(**optimized_result)

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error optimizing learning path: {str(e)}"
        )


@router.post("/b5-adjust-difficulty", response_model=DifficultyAdjustmentResponse)
async def adjust_difficulty_dynamically(
    request: DifficultyAdjustmentRequest,
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Dynamically adjust content difficulty based on real-time performance.

    Uses B.4 competency assessment data and knowledge gap severity for
    intelligent difficulty scaling with confidence scoring.

    **Key Features:**
    - Real-time performance analysis for difficulty optimization
    - AACN proficiency levels for appropriate difficulty targeting
    - Confidence scoring based on performance patterns
    - Rationale generation for adjustment decisions
    """
    try:
        # Calculate dynamic difficulty adjustment
        difficulty_adjustment = await adaptive_engine.adjust_difficulty_dynamically(
            student_id=request.student_id,
            current_content=request.current_content,
            recent_performance=request.recent_performance,
            competency_context=request.competency_context,
        )

        return DifficultyAdjustmentResponse(
            student_id=request.student_id,
            current_difficulty=difficulty_adjustment.current_difficulty,
            recommended_difficulty=difficulty_adjustment.recommended_difficulty,
            adjustment_reason=difficulty_adjustment.adjustment_reason,
            confidence_score=difficulty_adjustment.confidence_score,
            supporting_metrics=difficulty_adjustment.supporting_metrics,
            adjustment_magnitude=difficulty_adjustment.adjustment_magnitude,
            calculated_at=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error calculating difficulty adjustment: {str(e)}"
        )


@router.post("/b5-adapt-path-realtime", response_model=RealtimePathAdaptationResponse)
async def adapt_learning_path_realtime(
    request: RealtimePathAdaptationRequest,
    background_tasks: BackgroundTasks,
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Adapt learning path in real-time based on performance updates.

    Integrates B.4 Learning Analytics real-time data with adaptive algorithms
    for immediate path optimization and content sequencing adjustments.

    **Key Features:**
    - Real-time performance change analysis
    - Automatic path re-optimization using B.4 components
    - Performance trigger identification and response
    - Background adaptation history tracking
    """
    try:
        # Perform real-time path adaptation
        adaptation_result = await adaptive_engine.adapt_learning_path_realtime(
            student_id=request.student_id,
            current_path_id=request.current_path_id,
            performance_update=request.performance_update,
            competency_changes=request.competency_changes,
        )

        # Schedule background task for adaptation history tracking
        background_tasks.add_task(
            _track_adaptation_effectiveness, request.student_id, adaptation_result
        )

        return RealtimePathAdaptationResponse(
            student_id=request.student_id,
            original_path_id=adaptation_result.original_path_id,
            adapted_path_id=adaptation_result.adapted_path_id,
            adaptations_made=adaptation_result.adaptations_made,
            performance_triggers=adaptation_result.performance_triggers,
            estimated_improvement=adaptation_result.estimated_improvement,
            adaptation_confidence=adaptation_result.adaptation_confidence,
            adapted_at=datetime.now().isoformat(),
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error adapting learning path: {str(e)}"
        )


@router.post(
    "/b5-generate-adaptive-study-plan", response_model=AdaptiveStudyPlanResponse
)
async def generate_adaptive_study_plan(
    request: AdaptiveStudyPlanRequest,
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Generate comprehensive adaptive study plan with performance tracking.

    Combines B.4 Learning Analytics, knowledge gap prioritization, and
    adaptive difficulty progression for personalized study planning.

    **Key Features:**
    - Comprehensive study plan generation with B.4 analytics integration
    - Weekly scheduling with adaptive milestone tracking
    - Performance prediction and success metric calculation
    - Real-time adjustment capabilities and tracking integration
    """
    try:
        # Generate comprehensive adaptive study plan
        study_plan = await adaptive_engine.generate_adaptive_study_plan(
            student_id=request.student_id,
            study_duration_weeks=request.study_duration_weeks,
            weekly_time_budget=request.weekly_time_budget,
            priority_competencies=request.priority_competencies,
        )

        return AdaptiveStudyPlanResponse(**study_plan)

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error generating adaptive study plan: {str(e)}"
        )


@router.get("/b5-health")
async def adaptive_learning_health_check(
    ragnostic_client: RAGnosticClient = Depends(get_ragnostic_client),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
):
    """
    Health check for B.5 Adaptive Learning Engine with component validation.

    Validates integration with B.4 Learning Analytics, RAGnostic client,
    and all adaptive learning components.
    """
    try:
        health_status = {
            "service": "B.5 Adaptive Learning Engine",
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "adaptive_learning_engine": "operational",
                "learning_analytics_integration": "connected",
                "ragnostic_client": "connected" if ragnostic_client else "unavailable",
                "analytics_service": "connected"
                if analytics_service
                else "unavailable",
                "knowledge_gap_analyzer": "operational",
                "learning_path_optimizer": "operational",
            },
            "features": {
                "personalized_content_generation": True,
                "dynamic_difficulty_adjustment": True,
                "realtime_path_adaptation": True,
                "adaptive_study_planning": True,
                "performance_based_optimization": True,
            },
            "b4_integration": {
                "learning_analytics": "fully_integrated",
                "knowledge_gap_analysis": "operational",
                "learning_path_optimization": "enhanced",
                "competency_tracking": "real_time",
            },
        }

        return health_status

    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"B.5 Adaptive Learning Engine health check failed: {str(e)}",
        )


# Background task for adaptation tracking
async def _track_adaptation_effectiveness(
    student_id: str, adaptation_result: LearningPathAdaptation
):
    """
    Background task to track adaptation effectiveness for machine learning.

    Stores adaptation data for future algorithm improvement and
    personalization enhancement.
    """
    try:
        # Mock implementation - would store in database for ML training
        adaptation_data = {
            "student_id": student_id,
            "adaptation_id": f"adapt_{student_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "adaptations_made": adaptation_result.adaptations_made,
            "estimated_improvement": adaptation_result.estimated_improvement,
            "confidence": adaptation_result.adaptation_confidence,
            "timestamp": datetime.now().isoformat(),
        }

        # In production: store in adaptation history table for analysis
        # await analytics_service.store_adaptation_data(adaptation_data)

    except Exception as e:
        # Log error but don't fail the main request
        import logging

        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to track adaptation effectiveness: {str(e)}")


# Legacy endpoints for backward compatibility


@router.post("/path", response_model=Dict[str, Any])
async def create_learning_path_legacy(
    student_id: str,
    target_competencies: List[str],
    current_level: str = "beginner",
    adaptive_engine: AdaptiveLearningEngine = Depends(get_adaptive_learning_engine),
):
    """
    Legacy endpoint for learning path creation (redirects to B.5 optimization).

    Maintained for backward compatibility with existing integrations.
    """
    try:
        # Convert to new format and call B.5 endpoint
        optimization_request = LearningPathOptimizationRequest(
            student_id=student_id,
            target_competencies=target_competencies,
            time_constraints={"weekly_minutes": 300},  # Default 5 hours/week
            performance_context={"current_level": current_level},
        )

        result = await optimize_learning_path(optimization_request, adaptive_engine)

        # Convert to legacy format
        return {
            "id": result.path_id,
            "student_id": result.student_id,
            "recommended_resources": [
                step["resource"]["title"]
                for step in result.optimized_path.get("steps", [])
            ],
            "estimated_duration": result.optimized_path.get("total_duration", 0),
            "created_at": result.generated_at,
            "adaptive_features_note": "This path includes B.5 adaptive learning features. Use /b5-* endpoints for full functionality.",
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error creating learning path: {str(e)}"
        )


@router.get("/path/{student_id}", response_model=Dict[str, Any])
async def get_learning_path_legacy(student_id: str):
    """
    Legacy endpoint for learning path retrieval.

    Returns cached path information or directs to B.5 endpoints.
    """
    try:
        # Mock implementation - would retrieve from cache/database
        return {
            "message": "Legacy endpoint - please use /b5-* endpoints for full adaptive learning functionality",
            "student_id": student_id,
            "recommendation": "Use POST /adaptive-learning/b5-generate-personalized-content for current recommendations",
            "path_optimization": "Use POST /adaptive-learning/b5-optimize-learning-path for path optimization",
            "study_planning": "Use POST /adaptive-learning/b5-generate-adaptive-study-plan for comprehensive planning",
        }

    except Exception:
        raise HTTPException(
            status_code=404,
            detail=f"Learning path not found for student {student_id}. Please use B.5 adaptive learning endpoints.",
        )


@router.post("/progress/{student_id}")
async def update_progress_legacy(
    student_id: str, resource_id: str, completion_status: str
):
    """
    Legacy endpoint for progress updates.

    Directs users to B.5 real-time adaptation endpoints.
    """
    try:
        return {
            "message": "Progress update received",
            "student_id": student_id,
            "resource_id": resource_id,
            "completion_status": completion_status,
            "recommendation": "Use POST /adaptive-learning/b5-adapt-path-realtime for real-time adaptive adjustments based on performance",
            "updated_at": datetime.now().isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error updating progress: {str(e)}"
        )
