"""
Clinical Decision Support System for BSN Knowledge
Provides evidence-based clinical recommendations using RAGnostic enriched content
"""

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from .content_generation_service import ContentGenerationService, GenerationRequest

logger = logging.getLogger(__name__)


class ClinicalPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class EvidenceLevel(str, Enum):
    LEVEL_1 = "systematic_review_meta_analysis"  # Highest quality
    LEVEL_2 = "randomized_controlled_trial"
    LEVEL_3 = "controlled_trial"
    LEVEL_4 = "case_control_study"
    LEVEL_5 = "systematic_review_descriptive"
    LEVEL_6 = "descriptive_study"
    LEVEL_7 = "expert_opinion"  # Lowest quality


class ClinicalRecommendation(BaseModel):
    """Individual clinical recommendation with evidence"""

    id: str
    recommendation_text: str
    rationale: str
    evidence_level: EvidenceLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    priority: ClinicalPriority
    contraindications: List[str] = []
    monitoring_parameters: List[str] = []
    evidence_citations: List[str] = []
    umls_concepts: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ClinicalAssessment(BaseModel):
    """Patient assessment data for decision support"""

    patient_condition: str
    symptoms: List[str] = []
    vital_signs: Dict[str, Any] = {}
    lab_values: Dict[str, Any] = {}
    medications: List[str] = []
    allergies: List[str] = []
    comorbidities: List[str] = []
    nursing_concerns: List[str] = []


class ClinicalDecisionResponse(BaseModel):
    """Complete clinical decision support response"""

    assessment: ClinicalAssessment
    recommendations: List[ClinicalRecommendation]
    nursing_diagnoses: List[str] = []
    priority_interventions: List[str] = []
    educational_needs: List[str] = []
    safety_considerations: List[str] = []
    evidence_summary: Dict[str, Any]
    confidence_score: float = Field(ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class ClinicalDecisionSupportService:
    """
    Clinical Decision Support System using RAGnostic and OpenAI
    Provides evidence-based nursing recommendations and care plans
    """

    def __init__(self, content_service: ContentGenerationService):
        self.content_service = content_service

        self.system_prompt = """
You are an expert clinical nurse specialist providing evidence-based decision support.
You must:

1. Analyze patient assessment data thoroughly
2. Generate prioritized nursing recommendations based on evidence
3. Consider safety, contraindications, and monitoring needs
4. Provide appropriate evidence levels and confidence scores
5. Focus on nursing interventions and patient outcomes
6. Consider cultural, ethical, and psychosocial factors
7. Ensure recommendations align with current nursing standards
8. Include patient education and family involvement when appropriate

Response format: Valid JSON with structured clinical recommendations.
"""

        self.decision_template = """
Patient Clinical Assessment:
Condition: {patient_condition}
Symptoms: {symptoms}
Vital Signs: {vital_signs}
Lab Values: {lab_values}
Current Medications: {medications}
Allergies: {allergies}
Comorbidities: {comorbidities}
Nursing Concerns: {nursing_concerns}

Medical Context from RAGnostic:
{medical_context}

Provide comprehensive clinical decision support including:

1. Priority nursing interventions (ranked by clinical priority)
2. Evidence-based recommendations with rationales
3. Safety considerations and contraindications
4. Monitoring parameters for each intervention
5. Patient/family education needs
6. Potential nursing diagnoses (NANDA-I)

Return as JSON with this structure:
{{
    "recommendations": [
        {{
            "id": "unique_id",
            "recommendation_text": "specific nursing intervention",
            "rationale": "evidence-based explanation",
            "evidence_level": "systematic_review_meta_analysis|randomized_controlled_trial|...",
            "confidence_score": 0.95,
            "priority": "critical|high|moderate|low",
            "contraindications": ["contraindication 1", "contraindication 2"],
            "monitoring_parameters": ["parameter 1", "parameter 2"],
            "evidence_citations": ["citation 1", "citation 2"],
            "umls_concepts": ["concept 1", "concept 2"]
        }}
    ],
    "nursing_diagnoses": ["NANDA diagnosis 1", "NANDA diagnosis 2"],
    "priority_interventions": ["intervention 1", "intervention 2"],
    "educational_needs": ["education need 1", "education need 2"],
    "safety_considerations": ["safety concern 1", "safety concern 2"],
    "evidence_summary": {{
        "total_recommendations": 0,
        "high_evidence_count": 0,
        "average_confidence": 0.0
    }},
    "confidence_score": 0.95
}}
"""

    async def get_clinical_recommendations(
        self,
        assessment: ClinicalAssessment,
        focus_area: Optional[str] = None,
        max_recommendations: int = 10,
        min_confidence: float = 0.8,
    ) -> ClinicalDecisionResponse:
        """
        Generate evidence-based clinical recommendations for patient assessment

        Args:
            assessment: Patient clinical assessment data
            focus_area: Specific clinical focus (e.g., "pain management", "infection control")
            max_recommendations: Maximum number of recommendations
            min_confidence: Minimum confidence threshold

        Returns:
            ClinicalDecisionResponse with prioritized recommendations
        """
        try:
            # Create topic for content generation
            topic = f"{assessment.patient_condition}"
            if focus_area:
                topic += f" - {focus_area}"

            # Create generation request with clinical context
            request = GenerationRequest(
                topic=topic,
                difficulty="advanced",
                count=max_recommendations,
                context_filters={
                    "content_type": "clinical_guidelines",
                    "condition": assessment.patient_condition,
                    "focus_area": focus_area,
                    "evidence_based": True,
                },
                medical_accuracy_threshold=min_confidence,
            )

            # Format assessment data for prompt
            user_prompt = self.decision_template.format(
                patient_condition=assessment.patient_condition,
                symptoms=", ".join(assessment.symptoms) or "None specified",
                vital_signs=str(assessment.vital_signs) or "None provided",
                lab_values=str(assessment.lab_values) or "None provided",
                medications=", ".join(assessment.medications) or "None",
                allergies=", ".join(assessment.allergies) or "NKDA",
                comorbidities=", ".join(assessment.comorbidities) or "None",
                nursing_concerns=", ".join(assessment.nursing_concerns)
                or "None specified",
                medical_context="{medical_context}",  # Will be filled by content service
            )

            # Generate recommendations with validation
            result = await self.content_service.generate_content_with_validation(
                request=request,
                system_prompt=self.system_prompt,
                user_prompt_template=user_prompt,
                response_format="json_object",
            )

            # Parse and validate response
            import json

            response_data = json.loads(result["content"])

            # Create recommendation objects
            recommendations = []
            for i, rec_data in enumerate(
                response_data.get("recommendations", [])[:max_recommendations]
            ):
                try:
                    # Set defaults for missing fields
                    rec_data.setdefault("id", f"rec_{i+1}")
                    rec_data.setdefault("contraindications", [])
                    rec_data.setdefault("monitoring_parameters", [])
                    rec_data.setdefault("evidence_citations", [])
                    rec_data.setdefault("umls_concepts", [])

                    # Validate evidence level
                    if rec_data.get("evidence_level") not in [
                        e.value for e in EvidenceLevel
                    ]:
                        rec_data["evidence_level"] = EvidenceLevel.LEVEL_7.value

                    # Validate priority
                    if rec_data.get("priority") not in [
                        p.value for p in ClinicalPriority
                    ]:
                        rec_data["priority"] = ClinicalPriority.MODERATE.value

                    # Ensure confidence score is valid
                    confidence = rec_data.get("confidence_score", 0.5)
                    if not isinstance(confidence, (int, float)) or not (
                        0 <= confidence <= 1
                    ):
                        rec_data["confidence_score"] = 0.5

                    recommendation = ClinicalRecommendation(**rec_data)
                    recommendations.append(recommendation)

                except Exception as e:
                    logger.warning(f"Failed to parse recommendation {i}: {str(e)}")
                    continue

            # Calculate evidence summary
            evidence_summary = {
                "total_recommendations": len(recommendations),
                "high_evidence_count": sum(
                    1
                    for r in recommendations
                    if r.evidence_level
                    in [EvidenceLevel.LEVEL_1, EvidenceLevel.LEVEL_2]
                ),
                "average_confidence": sum(r.confidence_score for r in recommendations)
                / max(len(recommendations), 1),
                "priority_distribution": {
                    priority.value: sum(
                        1 for r in recommendations if r.priority == priority
                    )
                    for priority in ClinicalPriority
                },
            }

            # Create decision response
            decision_response = ClinicalDecisionResponse(
                assessment=assessment,
                recommendations=recommendations,
                nursing_diagnoses=response_data.get("nursing_diagnoses", []),
                priority_interventions=response_data.get("priority_interventions", []),
                educational_needs=response_data.get("educational_needs", []),
                safety_considerations=response_data.get("safety_considerations", []),
                evidence_summary=evidence_summary,
                confidence_score=response_data.get(
                    "confidence_score", evidence_summary["average_confidence"]
                ),
            )

            logger.info(
                f"Generated {len(recommendations)} clinical recommendations "
                f"for {assessment.patient_condition} with {decision_response.confidence_score:.2f} confidence"
            )

            return decision_response

        except Exception as e:
            logger.error(
                f"Clinical decision support failed for {assessment.patient_condition}: {str(e)}"
            )
            raise

    async def get_emergency_protocols(
        self, emergency_situation: str, patient_factors: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Get emergency nursing protocols and interventions
        """
        try:
            request = GenerationRequest(
                topic=f"emergency protocol {emergency_situation}",
                difficulty="advanced",
                count=5,
                context_filters={
                    "content_type": "emergency_protocol",
                    "situation": emergency_situation,
                    "priority": "critical",
                },
                medical_accuracy_threshold=0.95,
            )

            emergency_prompt = f"""
            Emergency Situation: {emergency_situation}
            Patient Factors: {patient_factors or 'None specified'}

            Provide immediate emergency nursing protocols including:
            1. Initial assessment priorities (ABCDE approach)
            2. Immediate interventions (time-critical)
            3. Medication administration protocols
            4. Monitoring parameters
            5. Communication/notification requirements
            6. Documentation priorities

            Medical Context: {{medical_context}}

            Focus on time-critical, evidence-based nursing actions.
            """

            result = await self.content_service.generate_content_with_validation(
                request=request,
                system_prompt=self.system_prompt
                + "\\n\\nFOCUS: Emergency protocols require immediate, evidence-based actions.",
                user_prompt_template=emergency_prompt,
            )

            return {
                "emergency_protocols": result["content"],
                "validation": result["validation"],
                "generated_at": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(
                f"Emergency protocol generation failed for {emergency_situation}: {str(e)}"
            )
            raise

    async def validate_care_plan(
        self, care_plan: Dict[str, Any], patient_condition: str
    ) -> Dict[str, Any]:
        """
        Validate a nursing care plan against evidence-based standards
        """
        try:
            # Convert care plan to text for validation
            care_plan_text = f"""
            Nursing Care Plan for {patient_condition}:
            {json.dumps(care_plan, indent=2)}
            """

            validation = await self.content_service._validate_medical_accuracy(
                content=care_plan_text, topic=patient_condition, threshold=0.9
            )

            return {
                "is_valid": validation.is_accurate,
                "validation_details": validation.dict(),
                "recommendations": [
                    "Consider evidence-based interventions",
                    "Ensure SMART goals for patient outcomes",
                    "Include patient/family education components",
                    "Validate against current nursing standards",
                ],
            }

        except Exception as e:
            logger.error(f"Care plan validation failed: {str(e)}")
            return {"is_valid": False, "error": str(e)}
