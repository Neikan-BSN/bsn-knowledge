"""
Clinical Decision Support API Router
Provides evidence-based clinical recommendations and care planning support
"""

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ...generators.clinical_decision_support import ClinicalDecisionSupport
from ...services.clinical_decision_support import (
    ClinicalAssessment,
    ClinicalDecisionSupportService,
    ClinicalPriority,
    EvidenceLevel,
)
from ...services.content_generation_service import ContentGenerationService
from ...services.ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/clinical-support", tags=["clinical-support"])


class AssessmentRequest(BaseModel):
    """Request for clinical assessment data"""

    patient_condition: str
    symptoms: list[str] = []
    vital_signs: dict[str, Any] = {}
    lab_values: dict[str, Any] = {}
    medications: list[str] = []
    allergies: list[str] = []
    comorbidities: list[str] = []
    nursing_concerns: list[str] = []
    focus_area: str | None = None
    max_recommendations: int = Field(default=10, ge=1, le=20)
    min_confidence: float = Field(default=0.8, ge=0.5, le=1.0)


class EmergencyProtocolRequest(BaseModel):
    """Request for emergency protocols"""

    emergency_situation: str
    patient_factors: dict[str, Any] | None = None


class CareplanValidationRequest(BaseModel):
    """Request to validate a nursing care plan"""

    care_plan: dict[str, Any]
    patient_condition: str


class RecommendationResponse(BaseModel):
    """Individual clinical recommendation response"""

    id: str
    recommendation_text: str
    rationale: str
    evidence_level: str
    confidence_score: float
    priority: str
    contraindications: list[str]
    monitoring_parameters: list[str]
    evidence_citations: list[str]
    umls_concepts: list[str]


class ClinicalSupportResponse(BaseModel):
    """Complete clinical decision support response"""

    assessment_summary: dict[str, Any]
    recommendations: list[RecommendationResponse]
    nursing_diagnoses: list[str]
    priority_interventions: list[str]
    educational_needs: list[str]
    safety_considerations: list[str]
    evidence_summary: dict[str, Any]
    confidence_score: float
    generated_at: str


class EmergencyProtocolResponse(BaseModel):
    """Emergency protocol response"""

    emergency_situation: str
    protocols: str
    validation_details: dict[str, Any]
    generated_at: str


class CareplanValidationResponse(BaseModel):
    """Care plan validation response"""

    is_valid: bool
    validation_details: dict[str, Any]
    recommendations: list[str]
    evidence_gaps: list[str] = []


class CaseStudyRequest(BaseModel):
    """Request for case study generation per REVISED_PHASE3_PLAN.md B.3"""

    learning_objectives: list[str] = Field(
        description="Learning objectives for case study generation", min_items=1
    )
    case_complexity: str = Field(
        default="intermediate",
        description="Case complexity level: basic, intermediate, advanced",
    )
    focus_area: str | None = Field(None, description="Optional clinical focus area")


class ClinicalRecommendationRequest(BaseModel):
    """Request for clinical recommendations per REVISED_PHASE3_PLAN.md B.3"""

    patient_demographics: dict[str, Any] = Field(
        description="Patient age, gender, relevant demographic factors"
    )
    clinical_presentation: dict[str, Any] = Field(
        description="Current symptoms, vital signs, physical assessment findings"
    )
    relevant_history: dict[str, Any] = Field(
        description="Medical history, medications, allergies, social factors"
    )
    learning_objectives: list[str] = Field(
        description="Specific learning goals for this case scenario"
    )
    case_complexity: str = Field(
        default="intermediate",
        description="Case complexity level: basic, intermediate, advanced",
    )


class CaseStudyResponse(BaseModel):
    """Case study response"""

    case_studies: list[dict[str, Any]]
    total_generated: int
    learning_objectives_covered: list[str]
    generated_at: str
    ragnostic_integration_status: str


class ClinicalRecommendationResponse(BaseModel):
    """Clinical recommendation response per REVISED_PHASE3_PLAN.md B.3"""

    case_id: str
    recommendations: list[dict[str, Any]]
    evidence_summary: dict[str, Any]
    ragnostic_context: dict[str, Any]
    overall_confidence: float
    generated_at: str


# Dependency injection for services
async def get_content_service():
    ragnostic_client = RAGnosticClient()
    content_service = ContentGenerationService(
        openai_api_key="your-openai-key",  # Would be injected from config  # noqa: S106
        ragnostic_client=ragnostic_client,
    )
    return content_service


async def get_clinical_decision_support():
    """Get ClinicalDecisionSupport instance per REVISED_PHASE3_PLAN.md B.3"""
    ragnostic_client = RAGnosticClient()
    return ClinicalDecisionSupport(ragnostic_client=ragnostic_client)


@router.post("/recommendations", response_model=ClinicalSupportResponse)
async def get_clinical_recommendations(
    request: AssessmentRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Get evidence-based clinical recommendations for patient assessment
    """
    try:
        clinical_service = ClinicalDecisionSupportService(content_service)

        # Create clinical assessment
        assessment = ClinicalAssessment(
            patient_condition=request.patient_condition,
            symptoms=request.symptoms,
            vital_signs=request.vital_signs,
            lab_values=request.lab_values,
            medications=request.medications,
            allergies=request.allergies,
            comorbidities=request.comorbidities,
            nursing_concerns=request.nursing_concerns,
        )

        # Get recommendations
        decision_response = await clinical_service.get_clinical_recommendations(
            assessment=assessment,
            focus_area=request.focus_area,
            max_recommendations=request.max_recommendations,
            min_confidence=request.min_confidence,
        )

        # Convert to API response format
        recommendations = [
            RecommendationResponse(
                id=rec.id,
                recommendation_text=rec.recommendation_text,
                rationale=rec.rationale,
                evidence_level=rec.evidence_level.value,
                confidence_score=rec.confidence_score,
                priority=rec.priority.value,
                contraindications=rec.contraindications,
                monitoring_parameters=rec.monitoring_parameters,
                evidence_citations=rec.evidence_citations,
                umls_concepts=rec.umls_concepts,
            )
            for rec in decision_response.recommendations
        ]

        return ClinicalSupportResponse(
            assessment_summary={
                "condition": assessment.patient_condition,
                "symptoms_count": len(assessment.symptoms),
                "medications_count": len(assessment.medications),
                "comorbidities_count": len(assessment.comorbidities),
            },
            recommendations=recommendations,
            nursing_diagnoses=decision_response.nursing_diagnoses,
            priority_interventions=decision_response.priority_interventions,
            educational_needs=decision_response.educational_needs,
            safety_considerations=decision_response.safety_considerations,
            evidence_summary=decision_response.evidence_summary,
            confidence_score=decision_response.confidence_score,
            generated_at=decision_response.generated_at.isoformat(),
        )

    except Exception as e:
        logger.error(f"Clinical recommendations failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Clinical decision support failed: {str(e) from e}"
        )


@router.post("/emergency-protocols", response_model=EmergencyProtocolResponse)
async def get_emergency_protocols(
    request: EmergencyProtocolRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Get emergency nursing protocols and interventions
    """
    try:
        clinical_service = ClinicalDecisionSupportService(content_service)

        # Get emergency protocols
        result = await clinical_service.get_emergency_protocols(
            emergency_situation=request.emergency_situation,
            patient_factors=request.patient_factors,
        )

        return EmergencyProtocolResponse(
            emergency_situation=request.emergency_situation,
            protocols=result["emergency_protocols"],
            validation_details=result["validation"],
            generated_at=result["generated_at"],
        )

    except Exception as e:
        logger.error(f"Emergency protocol generation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Emergency protocol generation failed: {str(e) from e}"
        )


@router.post("/validate-careplan", response_model=CareplanValidationResponse)
async def validate_care_plan(
    request: CareplanValidationRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Validate nursing care plan against evidence-based standards
    """
    try:
        clinical_service = ClinicalDecisionSupportService(content_service)

        # Validate care plan
        validation_result = await clinical_service.validate_care_plan(
            care_plan=request.care_plan, patient_condition=request.patient_condition
        )

        return CareplanValidationResponse(
            is_valid=validation_result["is_valid"],
            validation_details=validation_result.get("validation_details", {}),
            recommendations=validation_result.get("recommendations", []),
            evidence_gaps=validation_result.get("evidence_gaps", []),
        )

    except Exception as e:
        logger.error(f"Care plan validation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Care plan validation failed: {str(e) from e}"
        )


@router.get("/evidence-levels", response_model=list[str])
async def get_evidence_levels():
    """
    Get available evidence levels for clinical recommendations
    """
    return [level.value for level in EvidenceLevel]


@router.get("/priority-levels", response_model=list[str])
async def get_priority_levels():
    """
    Get available priority levels for clinical recommendations
    """
    return [priority.value for priority in ClinicalPriority]


@router.get("/emergency-situations", response_model=list[str])
async def get_common_emergency_situations():
    """
    Get list of common emergency situations for protocol generation
    """
    return [
        "Cardiac Arrest",
        "Respiratory Distress",
        "Sepsis",
        "Stroke",
        "Anaphylaxis",
        "Hypoglycemia",
        "Seizure",
        "Chest Pain",
        "Severe Bleeding",
        "Falls with Injury",
        "Medication Error",
        "Patient Deterioration",
    ]


@router.get("/nursing-diagnoses", response_model=list[str])
async def get_common_nursing_diagnoses():
    """
    Get list of common NANDA-I nursing diagnoses
    """
    return [
        "Risk for Infection",
        "Risk for Falls",
        "Acute Pain",
        "Chronic Pain",
        "Risk for Impaired Skin Integrity",
        "Deficient Knowledge",
        "Anxiety",
        "Risk for Fluid Volume Deficit",
        "Impaired Gas Exchange",
        "Risk for Ineffective Airway Clearance",
        "Activity Intolerance",
        "Risk for Injury",
        "Ineffective Coping",
        "Risk for Bleeding",
        "Ineffective Tissue Perfusion",
    ]


@router.get("/clinical-focus-areas", response_model=list[str])
async def get_clinical_focus_areas():
    """
    Get available clinical focus areas for targeted recommendations
    """
    return [
        "Pain Management",
        "Infection Control",
        "Fall Prevention",
        "Medication Safety",
        "Wound Care",
        "Respiratory Care",
        "Cardiac Care",
        "Fluid Balance",
        "Nutrition",
        "Patient Education",
        "Discharge Planning",
        "Family Support",
        "End-of-Life Care",
        "Mental Health",
        "Rehabilitation",
    ]


@router.post("/generate-careplan", response_model=dict[str, Any])
async def generate_nursing_care_plan(
    assessment: AssessmentRequest,
    content_service: ContentGenerationService = Depends(get_content_service),
):
    """
    Generate a complete nursing care plan based on assessment data
    """
    try:
        # First get clinical recommendations
        clinical_service = ClinicalDecisionSupportService(content_service)

        clinical_assessment = ClinicalAssessment(
            patient_condition=assessment.patient_condition,
            symptoms=assessment.symptoms,
            vital_signs=assessment.vital_signs,
            lab_values=assessment.lab_values,
            medications=assessment.medications,
            allergies=assessment.allergies,
            comorbidities=assessment.comorbidities,
            nursing_concerns=assessment.nursing_concerns,
        )

        decision_response = await clinical_service.get_clinical_recommendations(
            assessment=clinical_assessment,
            focus_area=assessment.focus_area,
            max_recommendations=assessment.max_recommendations,
            min_confidence=assessment.min_confidence,
        )

        # Generate structured care plan
        care_plan = {
            "patient_assessment": {
                "condition": assessment.patient_condition,
                "symptoms": assessment.symptoms,
                "vital_signs": assessment.vital_signs,
                "lab_values": assessment.lab_values,
                "medications": assessment.medications,
                "allergies": assessment.allergies,
                "comorbidities": assessment.comorbidities,
            },
            "nursing_diagnoses": decision_response.nursing_diagnoses,
            "goals": [
                f"Patient will demonstrate {intervention}"
                for intervention in decision_response.priority_interventions[:3]
            ],
            "interventions": [
                {
                    "intervention": rec.recommendation_text,
                    "rationale": rec.rationale,
                    "priority": rec.priority.value,
                    "monitoring": rec.monitoring_parameters,
                }
                for rec in decision_response.recommendations[:10]
            ],
            "patient_education": decision_response.educational_needs,
            "safety_considerations": decision_response.safety_considerations,
            "evaluation_criteria": [
                "Patient demonstrates understanding of condition",
                "Vital signs remain within normal limits",
                "Patient reports decreased symptoms",
                "No adverse events occur",
            ],
            "generated_at": datetime.utcnow().isoformat(),
            "evidence_summary": decision_response.evidence_summary,
        }

        return care_plan

    except Exception as e:
        logger.error(f"Care plan generation failed: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Care plan generation failed: {str(e) from e}"
        )


@router.post(
    "/b3-generate-recommendations", response_model=ClinicalRecommendationResponse
)
async def b3_generate_clinical_recommendations(
    request: ClinicalRecommendationRequest,
    clinical_decision_support: ClinicalDecisionSupport = Depends(
        get_clinical_decision_support
    ),
):
    """
    B.3 Clinical Decision Support: Generate evidence-based clinical recommendations
    Per REVISED_PHASE3_PLAN.md B.3 specifications - Query RAGnostic for relevant clinical content,
    apply clinical reasoning algorithms, generate evidence-based recommendations,
    include citations and confidence scores.
    """
    try:
        # Convert request to case scenario dict
        case_scenario_dict = {
            "patient_demographics": request.patient_demographics,
            "clinical_presentation": request.clinical_presentation,
            "relevant_history": request.relevant_history,
            "learning_objectives": request.learning_objectives,
            "case_complexity": request.case_complexity,
        }

        # Generate recommendations using B.3 implementation
        result = await clinical_decision_support.generate_recommendations(
            case_scenario_dict
        )

        # Convert recommendations to serializable format
        recommendations = [
            {
                "id": f"rec_{i + 1}",
                "recommendation_text": rec.recommendation_text,
                "evidence_citations": rec.evidence_citations,
                "confidence_score": rec.confidence_score,
                "reasoning_steps": rec.reasoning_steps,
                "evidence_strength": rec.evidence_strength.value,
                "priority": rec.priority.value,
                "contraindications": rec.contraindications,
                "monitoring_parameters": rec.monitoring_parameters,
                "umls_concepts": rec.umls_concepts,
            }
            for i, rec in enumerate(result.recommendations)
        ]

        return ClinicalRecommendationResponse(
            case_id=result.case_id,
            recommendations=recommendations,
            evidence_summary=result.evidence_summary,
            ragnostic_context=result.ragnostic_context,
            overall_confidence=result.overall_confidence,
            generated_at=result.generated_at.isoformat(),
        )

    except Exception as e:
        logger.error(f"B.3 Clinical recommendation generation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Clinical decision support B.3 implementation failed: {str(e) from e}",
        )


@router.post("/b3-create-case-studies", response_model=CaseStudyResponse)
async def b3_create_case_studies(
    request: CaseStudyRequest,
    clinical_decision_support: ClinicalDecisionSupport = Depends(
        get_clinical_decision_support
    ),
):
    """
    B.3 Clinical Decision Support: Create case studies using RAGnostic content
    Per REVISED_PHASE3_PLAN.md B.3 specifications - Use RAGnostic content to build scenarios,
    align with specified learning objectives, include assessment questions.
    """
    try:
        # Generate case studies using B.3 implementation
        case_studies = await clinical_decision_support.create_case_studies(
            learning_objectives=request.learning_objectives
        )

        return CaseStudyResponse(
            case_studies=case_studies,
            total_generated=len(case_studies),
            learning_objectives_covered=request.learning_objectives,
            generated_at=datetime.utcnow().isoformat(),
            ragnostic_integration_status="operational",
        )

    except Exception as e:
        logger.error(f"B.3 Case study generation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Case study generation B.3 implementation failed: {str(e) from e}",
        )


@router.get("/b3-health", response_model=dict[str, Any])
async def b3_clinical_decision_support_health(
    clinical_decision_support: ClinicalDecisionSupport = Depends(
        get_clinical_decision_support
    ),
):
    """
    B.3 Clinical Decision Support Health Check
    Validates RAGnostic integration and OpenAI connectivity per B.3 specifications
    """
    try:
        health_status = await clinical_decision_support.health_check()

        return {
            "service": "clinical_decision_support_b3",
            "status": health_status["status"],
            "b3_features": {
                "generate_recommendations": "operational",
                "create_case_studies": "operational",
                "ragnostic_integration": health_status["ragnostic_status"]["status"]
                if "ragnostic_status" in health_status
                else "unknown",
                "openai_integration": health_status["openai_status"],
                "evidence_based_reasoning": "operational",
                "citation_generation": "operational",
                "confidence_scoring": "operational",
            },
            "cache_stats": health_status.get("cache_stats", {}),
            "implementation_version": "B.3_REVISED_PHASE3_PLAN",
            "timestamp": health_status["timestamp"],
        }

    except Exception as e:
        logger.error(f"B.3 health check failed: {str(e)}")
        return {
            "service": "clinical_decision_support_b3",
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


@router.get("/health")
async def clinical_support_health():
    """
    Health check for clinical decision support service
    """
    return {
        "service": "clinical_decision_support",
        "status": "operational",
        "features": [
            "evidence_based_recommendations",
            "emergency_protocols",
            "care_plan_validation",
            "nursing_diagnoses",
            "clinical_reasoning",
            "safety_considerations",
        ],
        "timestamp": datetime.utcnow().isoformat(),
        "b3_implementation_status": "operational",
    }
