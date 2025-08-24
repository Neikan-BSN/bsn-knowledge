"""
Assessment API endpoints for BSN Knowledge
Provides AACN competency assessment and management functionality
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
import logging

from ...models.assessment_models import (
    CompetencyAssessmentResult,
    StudentCompetencyProfile,
    KnowledgeGap,
    LearningPathRecommendation,
    AACNDomain,
    CompetencyProficiencyLevel
)
from ...assessment.competency_framework import AACNCompetencyFramework
from ...services.ragnostic_client import RAGnosticClient
from ...dependencies import get_ragnostic_client, get_competency_framework_dep

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/assessment", tags=["assessment"])


class CompetencyAssessmentRequest(BaseModel):
    """Request model for competency assessment"""
    student_id: str
    competency_id: str
    performance_data: Dict[str, Any] = Field(
        description="Assessment results, quiz scores, clinical evaluations"
    )
    assessment_type: str = "comprehensive"
    assessor_id: str = "system"


class CompetencyGapAnalysisRequest(BaseModel):
    """Request model for competency gap analysis"""
    student_id: str
    target_competencies: List[str]
    include_prerequisites: bool = True
    severity_filter: Optional[str] = None  # "low", "medium", "high", "critical"


class LearningPathRequest(BaseModel):
    """Request model for learning path generation"""
    student_id: str
    target_competencies: List[str]
    current_proficiency: Optional[Dict[str, float]] = None
    learning_preferences: Optional[Dict[str, Any]] = None
    timeline_weeks: Optional[int] = 16


class BulkCompetencyAssessmentRequest(BaseModel):
    """Request model for bulk competency assessment"""
    assessments: List[CompetencyAssessmentRequest]
    batch_id: Optional[str] = None


@router.post("/competency/assess", response_model=CompetencyAssessmentResult)
async def assess_competency(
    request: CompetencyAssessmentRequest,
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Assess student competency using AACN framework
    
    Evaluates student performance against specific competency criteria
    and provides detailed feedback with recommendations.
    """
    try:
        logger.info(f"Assessing competency {request.competency_id} for student {request.student_id}")
        
        # Framework injected via dependency
        
        # Perform competency assessment
        assessment_result = await framework.assess_competency(
            student_id=request.student_id,
            competency_id=request.competency_id,
            performance_data=request.performance_data,
            assessment_id=f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            assessor_id=request.assessor_id
        )
        
        logger.info(f"Competency assessment completed: {assessment_result.current_level} level")
        return assessment_result
        
    except ValueError as e:
        logger.warning(f"Invalid competency assessment request: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error assessing competency: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to assess competency")


@router.post("/competency/assess/bulk")
async def assess_competencies_bulk(
    request: BulkCompetencyAssessmentRequest,
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Assess multiple competencies in batch for efficient processing
    
    Useful for semester-end evaluations or comprehensive assessments.
    """
    try:
        logger.info(f"Processing bulk assessment with {len(request.assessments)} assessments")
        
        # Framework injected via dependency
        results = []
        errors = []
        
        for i, assessment_req in enumerate(request.assessments):
            try:
                result = await framework.assess_competency(
                    student_id=assessment_req.student_id,
                    competency_id=assessment_req.competency_id,
                    performance_data=assessment_req.performance_data,
                    assessment_id=f"bulk_{request.batch_id or 'default'}_{i}",
                    assessor_id=assessment_req.assessor_id
                )
                results.append(result)
                
            except Exception as e:
                error_detail = {
                    "index": i,
                    "student_id": assessment_req.student_id,
                    "competency_id": assessment_req.competency_id,
                    "error": str(e)
                }
                errors.append(error_detail)
                logger.warning(f"Failed assessment {i}: {str(e)}")
        
        response = {
            "batch_id": request.batch_id,
            "total_assessments": len(request.assessments),
            "successful_assessments": len(results),
            "failed_assessments": len(errors),
            "results": results,
            "errors": errors,
            "processed_at": datetime.now().isoformat()
        }
        
        logger.info(f"Bulk assessment completed: {len(results)}/{len(request.assessments)} successful")
        return response
        
    except Exception as e:
        logger.error(f"Error in bulk competency assessment: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to process bulk assessment")


@router.get("/competency/profile/{student_id}", response_model=StudentCompetencyProfile)
async def get_student_competency_profile(
    student_id: str,
    include_historical: bool = Query(False, description="Include historical assessment data"),
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Get comprehensive competency profile for a student
    
    Returns current competency levels, strengths, areas for improvement,
    and graduation readiness assessment.
    """
    try:
        logger.info(f"Retrieving competency profile for student {student_id}")
        
        # This would typically query the database for stored assessments
        # For now, using mock data structure
        profile = StudentCompetencyProfile(
            student_id=student_id,
            program="BSN",
            semester=3,
            competency_gpa=3.2,
            graduation_readiness_score=75.0,
            strengths_summary=[
                "Strong clinical reasoning in acute care settings",
                "Excellent interprofessional communication skills",
                "Proficient in health assessment techniques"
            ],
            development_plan=[
                "Enhance pharmacology knowledge for complex medications",
                "Develop advanced critical care competencies",
                "Strengthen population health assessment skills"
            ],
            last_updated=datetime.now()
        )
        
        logger.info(f"Retrieved competency profile: {profile.competency_gpa} GPA")
        return profile
        
    except Exception as e:
        logger.error(f"Error retrieving competency profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve competency profile")


@router.post("/gaps/analyze", response_model=Dict[str, List[KnowledgeGap]])
async def analyze_competency_gaps(
    request: CompetencyGapAnalysisRequest,
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Analyze competency gaps and generate remediation plans
    
    Identifies knowledge and skill gaps across competency domains
    and provides targeted recommendations for improvement.
    """
    try:
        logger.info(f"Analyzing gaps for student {request.student_id}")
        
        # Framework injected via dependency
        
        # Get current assessments (would query database in production)
        current_assessments = []  # Mock - would fetch from database
        
        # Analyze gaps
        gaps_by_domain = await framework.get_competency_gaps(
            student_id=request.student_id,
            target_competencies=request.target_competencies,
            current_assessments=current_assessments
        )
        
        # Filter by severity if specified
        if request.severity_filter:
            filtered_gaps = {}
            for domain, gaps in gaps_by_domain.items():
                filtered_gaps[domain] = [
                    gap for gap in gaps 
                    if gap.severity == request.severity_filter
                ]
            gaps_by_domain = filtered_gaps
        
        total_gaps = sum(len(gaps) for gaps in gaps_by_domain.values())
        logger.info(f"Gap analysis completed: {total_gaps} gaps across {len(gaps_by_domain)} domains")
        
        return gaps_by_domain
        
    except Exception as e:
        logger.error(f"Error analyzing competency gaps: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to analyze competency gaps")


@router.post("/learning-path/generate", response_model=LearningPathRecommendation)
async def generate_learning_path(
    request: LearningPathRequest,
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Generate personalized learning path recommendations
    
    Creates optimized sequence of learning activities based on current
    proficiency, target competencies, and learning preferences.
    """
    try:
        logger.info(f"Generating learning path for student {request.student_id}")
        
        # Framework injected via dependency
        
        # Generate learning path
        learning_path = await framework.recommend_learning_path(
            student_id=request.student_id,
            target_competencies=request.target_competencies,
            current_proficiency=request.current_proficiency,
            learning_preferences=request.learning_preferences
        )
        
        logger.info(f"Learning path generated: {learning_path.estimated_duration_hours} hours, {len(learning_path.recommended_sequence)} activities")
        return learning_path
        
    except Exception as e:
        logger.error(f"Error generating learning path: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate learning path")


@router.get("/competencies/available")
async def get_available_competencies(
    domain: Optional[AACNDomain] = Query(None, description="Filter by AACN domain"),
    framework: AACNCompetencyFramework = Depends(get_competency_framework_dep)
):
    """
    Get list of available AACN competencies
    
    Returns all competencies in the framework, optionally filtered by domain.
    """
    try:
        # Framework injected via dependency
        
        if domain:
            competencies = framework.get_competencies_by_domain(domain)
            logger.info(f"Retrieved {len(competencies)} competencies for domain {domain}")
        else:
            competencies = framework.get_all_competencies()
            logger.info(f"Retrieved all {len(competencies)} competencies")
        
        # Convert to serializable format
        competency_list = []
        for comp in competencies:
            competency_data = {
                "id": comp.id,
                "domain": comp.domain.value,
                "name": comp.name,
                "description": comp.description,
                "sub_competencies": comp.sub_competencies,
                "learning_outcomes": comp.learning_outcomes,
                "assessment_methods": comp.assessment_methods,
                "prerequisites": comp.prerequisites,
                "minimum_level": comp.minimum_level.value,
                "weight": comp.weight
            }
            competency_list.append(competency_data)
        
        return {
            "competencies": competency_list,
            "total_count": len(competency_list),
            "domain_filter": domain.value if domain else None
        }
        
    except Exception as e:
        logger.error(f"Error retrieving competencies: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve competencies")


@router.get("/domains")
async def get_aacn_domains():
    """
    Get list of AACN competency domains
    
    Returns all eight AACN essential domains with descriptions.
    """
    try:
        domains = [
            {
                "id": domain.value,
                "name": domain.value.replace("_", " ").title(),
                "description": _get_domain_description(domain)
            }
            for domain in AACNDomain
        ]
        
        logger.info(f"Retrieved {len(domains)} AACN domains")
        return {"domains": domains}
        
    except Exception as e:
        logger.error(f"Error retrieving AACN domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve domains")


@router.get("/proficiency-levels")
async def get_proficiency_levels():
    """
    Get available proficiency levels
    
    Returns all proficiency levels from novice to expert.
    """
    levels = [
        {
            "id": level.value,
            "name": level.value.replace("_", " ").title(),
            "description": _get_level_description(level),
            "order": list(CompetencyProficiencyLevel).index(level)
        }
        for level in CompetencyProficiencyLevel
    ]
    
    return {"proficiency_levels": levels}


def _get_domain_description(domain: AACNDomain) -> str:
    """Get description for AACN domain"""
    descriptions = {
        AACNDomain.KNOWLEDGE_FOR_NURSING_PRACTICE: "Foundational knowledge from nursing and other sciences for professional nursing practice",
        AACNDomain.PERSON_CENTERED_CARE: "Holistic nursing care that recognizes the individual within family, community, and cultural contexts",
        AACNDomain.POPULATION_HEALTH: "Health promotion and disease prevention across diverse populations and communities",
        AACNDomain.SCHOLARSHIP_FOR_NURSING_DISCIPLINE: "Integration of evidence-based practice, quality improvement, and research principles",
        AACNDomain.INFORMATION_TECHNOLOGY: "Use of healthcare technologies and informatics to deliver safe, quality patient care",
        AACNDomain.HEALTHCARE_SYSTEMS: "Understanding and navigation of complex healthcare delivery systems",
        AACNDomain.INTERPROFESSIONAL_PARTNERSHIPS: "Effective communication and collaboration within interprofessional healthcare teams",
        AACNDomain.PERSONAL_PROFESSIONAL_DEVELOPMENT: "Professional identity formation and commitment to lifelong learning"
    }
    return descriptions.get(domain, "AACN Essential Domain")


def _get_level_description(level: CompetencyProficiencyLevel) -> str:
    """Get description for proficiency level"""
    descriptions = {
        CompetencyProficiencyLevel.NOVICE: "Beginning level with limited experience",
        CompetencyProficiencyLevel.ADVANCED_BEGINNER: "Demonstrates marginally acceptable performance",
        CompetencyProficiencyLevel.COMPETENT: "Demonstrates efficient and organized performance",
        CompetencyProficiencyLevel.PROFICIENT: "Demonstrates holistic understanding and fluid performance",
        CompetencyProficiencyLevel.EXPERT: "Demonstrates intuitive grasp and highly skilled performance"
    }
    return descriptions.get(level, "Competency proficiency level")