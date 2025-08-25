from typing import Any, Dict, List, Optional
import json
import logging
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from ..services.content_generation_service import (
    ContentGenerationService,
    GenerationRequest,
)

logger = logging.getLogger(__name__)


class LearningObjectiveType(str, Enum):
    KNOWLEDGE = "knowledge"
    COMPREHENSION = "comprehension"
    APPLICATION = "application"
    ANALYSIS = "analysis"
    SYNTHESIS = "synthesis"
    EVALUATION = "evaluation"


class CompetencyFramework(str, Enum):
    AACN_ESSENTIALS = "aacn_essentials"
    QSEN = "qsen"
    NCLEX_CATEGORIES = "nclex_categories"
    NURSING_PROCESS = "nursing_process"


class LearningObjective(BaseModel):
    """Learning objective aligned with nursing competency frameworks"""

    objective: str
    objective_type: LearningObjectiveType
    competency_framework: CompetencyFramework
    assessment_criteria: List[str] = []
    prerequisite_concepts: List[str] = []


class StudySection(BaseModel):
    """Individual section of study guide"""

    title: str
    content: str
    learning_objectives: List[LearningObjective]
    key_concepts: List[str] = []
    clinical_applications: List[str] = []
    study_questions: List[str] = []
    additional_resources: List[str] = []
    umls_concepts: List[str] = []
    estimated_study_time: int  # in minutes


class StudyGuide(BaseModel):
    """Complete personalized study guide"""

    id: str
    title: str
    topic: str
    difficulty_level: str
    target_audience: str = "BSN students"
    sections: List[StudySection]
    overall_objectives: List[LearningObjective]
    prerequisites: List[str] = []
    estimated_completion_time: int  # in minutes
    competency_alignment: Dict[str, List[str]] = {}
    evidence_citations: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    generation_metadata: Dict[str, Any] = {}


class StudyGuideGenerator:
    """
    Enhanced study guide generator using RAGnostic UMLS-enriched content
    and personalized learning pathways
    """

    def __init__(self, content_service: ContentGenerationService):
        self.content_service = content_service

        self.system_prompt = """
You are an expert nursing educator creating comprehensive study guides. You must:

1. Align content with nursing competency frameworks (AACN, QSEN, NCLEX)
2. Use evidence-based content with proper citations
3. Create clear learning objectives at multiple cognitive levels
4. Include clinical applications and real-world scenarios
5. Provide study questions that promote critical thinking
6. Consider diverse learning styles and cultural perspectives
7. Ensure content accuracy using current nursing literature
8. Include prerequisite knowledge and concept relationships

Response format: Valid JSON with structured study guide sections.
"""

        self.guide_template = """
Create a comprehensive study guide for: {topic}

Requirements:
- Target audience: {target_audience}
- Difficulty level: {difficulty_level}
- Number of sections: {section_count}
- Competency alignment: {competency_frameworks}
- Include clinical applications and evidence-based content

Medical Context from RAGnostic:
{medical_context}

Structure the study guide with these components:

1. Overall learning objectives (aligned with competency frameworks)
2. Detailed sections with:
   - Clear section titles and content
   - Specific learning objectives for each section
   - Key concepts and terminology
   - Clinical applications and examples
   - Study questions for self-assessment
   - Additional resources for deeper learning
3. Prerequisites and concept relationships
4. Evidence citations from current literature

Return as JSON with this structure:
{{
    "title": "Study Guide: {topic}",
    "sections": [
        {{
            "title": "section title",
            "content": "detailed educational content",
            "learning_objectives": [
                {{
                    "objective": "specific learning objective",
                    "objective_type": "knowledge|comprehension|application|analysis|synthesis|evaluation",
                    "competency_framework": "aacn_essentials|qsen|nclex_categories|nursing_process",
                    "assessment_criteria": ["criterion 1", "criterion 2"],
                    "prerequisite_concepts": ["concept 1", "concept 2"]
                }}
            ],
            "key_concepts": ["concept 1", "concept 2"],
            "clinical_applications": ["application 1", "application 2"],
            "study_questions": ["question 1", "question 2"],
            "additional_resources": ["resource 1", "resource 2"],
            "umls_concepts": ["UMLS concept 1", "UMLS concept 2"],
            "estimated_study_time": 60
        }}
    ],
    "overall_objectives": [
        {{
            "objective": "overall objective",
            "objective_type": "application",
            "competency_framework": "qsen",
            "assessment_criteria": ["criterion"],
            "prerequisite_concepts": ["prerequisite"]
        }}
    ],
    "prerequisites": ["prerequisite 1", "prerequisite 2"],
    "competency_alignment": {{
        "aacn_essentials": ["Essential 1", "Essential 2"],
        "qsen": ["Safety", "Quality Improvement"],
        "nclex_categories": ["Physiological Integrity"]
    }},
    "evidence_citations": ["citation 1", "citation 2"]
}}
"""

    async def generate_guide(
        self,
        topic: str,
        difficulty_level: str = "intermediate",
        target_audience: str = "BSN students",
        section_count: int = 5,
        competency_frameworks: List[CompetencyFramework] = None,
        personalization_data: Optional[Dict[str, Any]] = None,
    ) -> StudyGuide:
        """
        Generate a comprehensive, personalized study guide

        Args:
            topic: Study topic
            difficulty_level: Content difficulty
            target_audience: Target learner group
            section_count: Number of sections to include
            competency_frameworks: Nursing competency frameworks to align with
            personalization_data: Student profile data for personalization

        Returns:
            StudyGuide object with comprehensive content
        """
        try:
            # Default competency frameworks
            if not competency_frameworks:
                competency_frameworks = [
                    CompetencyFramework.QSEN,
                    CompetencyFramework.NCLEX_CATEGORIES,
                ]

            # Create generation request with personalization
            context_filters = {
                "content_type": "educational",
                "target_audience": target_audience,
                "competency_alignment": True,
                "evidence_based": True,
            }

            # Add personalization filters if provided
            if personalization_data:
                context_filters.update(
                    {
                        "learning_preferences": personalization_data.get(
                            "learning_style"
                        ),
                        "knowledge_gaps": personalization_data.get("weak_areas", []),
                        "strengths": personalization_data.get("strong_areas", []),
                    }
                )

            request = GenerationRequest(
                topic=topic,
                difficulty=difficulty_level,
                count=section_count,
                context_filters=context_filters,
                medical_accuracy_threshold=0.92,
            )

            # Generate study guide content
            result = await self.content_service.generate_content_with_validation(
                request=request,
                system_prompt=self.system_prompt,
                user_prompt_template=self.guide_template.format(
                    topic=topic,
                    target_audience=target_audience,
                    difficulty_level=difficulty_level,
                    section_count=section_count,
                    competency_frameworks=", ".join(
                        [f.value for f in competency_frameworks]
                    ),
                    medical_context="{medical_context}",  # Will be filled by service
                ),
                response_format="json_object",
            )

            # Parse generated content
            guide_data = json.loads(result["content"])

            # Process sections
            sections = []
            for section_data in guide_data.get("sections", []):
                # Process learning objectives
                objectives = []
                for obj_data in section_data.get("learning_objectives", []):
                    obj_data.setdefault("assessment_criteria", [])
                    obj_data.setdefault("prerequisite_concepts", [])

                    # Validate enum values
                    if obj_data.get("objective_type") not in [
                        t.value for t in LearningObjectiveType
                    ]:
                        obj_data["objective_type"] = (
                            LearningObjectiveType.KNOWLEDGE.value
                        )
                    if obj_data.get("competency_framework") not in [
                        f.value for f in CompetencyFramework
                    ]:
                        obj_data["competency_framework"] = (
                            CompetencyFramework.QSEN.value
                        )

                    objectives.append(LearningObjective(**obj_data))

                # Set defaults for section
                section_data.setdefault("key_concepts", [])
                section_data.setdefault("clinical_applications", [])
                section_data.setdefault("study_questions", [])
                section_data.setdefault("additional_resources", [])
                section_data.setdefault("umls_concepts", [])
                section_data.setdefault("estimated_study_time", 60)

                section = StudySection(
                    **{**section_data, "learning_objectives": objectives}
                )
                sections.append(section)

            # Process overall objectives
            overall_objectives = []
            for obj_data in guide_data.get("overall_objectives", []):
                obj_data.setdefault("assessment_criteria", [])
                obj_data.setdefault("prerequisite_concepts", [])

                # Validate enum values
                if obj_data.get("objective_type") not in [
                    t.value for t in LearningObjectiveType
                ]:
                    obj_data["objective_type"] = LearningObjectiveType.APPLICATION.value
                if obj_data.get("competency_framework") not in [
                    f.value for f in CompetencyFramework
                ]:
                    obj_data["competency_framework"] = CompetencyFramework.QSEN.value

                overall_objectives.append(LearningObjective(**obj_data))

            # Calculate total study time
            total_time = sum(section.estimated_study_time for section in sections)

            # Create study guide
            study_guide = StudyGuide(
                id=f"sg_{datetime.utcnow().timestamp()}",
                title=guide_data.get("title", f"Study Guide: {topic}"),
                topic=topic,
                difficulty_level=difficulty_level,
                target_audience=target_audience,
                sections=sections,
                overall_objectives=overall_objectives,
                prerequisites=guide_data.get("prerequisites", []),
                estimated_completion_time=total_time,
                competency_alignment=guide_data.get("competency_alignment", {}),
                evidence_citations=guide_data.get("evidence_citations", []),
                generation_metadata=result["generation_metadata"],
            )

            logger.info(
                f"Generated study guide for '{topic}' with {len(sections)} sections "
                f"and {total_time} minutes estimated completion time"
            )

            return study_guide

        except Exception as e:
            logger.error(f"Study guide generation failed for topic '{topic}': {str(e)}")
            raise

    async def customize_guide(
        self, base_guide: StudyGuide, student_profile: Dict[str, Any]
    ) -> StudyGuide:
        """
        Customize existing study guide based on student profile
        """
        try:
            # Extract customization parameters
            learning_style = student_profile.get("learning_style", "mixed")
            weak_areas = student_profile.get("knowledge_gaps", [])
            strong_areas = student_profile.get("strengths", [])
            time_available = student_profile.get(
                "study_time", base_guide.estimated_completion_time
            )

            # Filter and prioritize sections based on weak areas
            customized_sections = []

            for section in base_guide.sections:
                # Check if section covers weak areas
                covers_weak_area = any(
                    weak_area.lower() in section.title.lower()
                    or weak_area.lower() in section.content.lower()
                    for weak_area in weak_areas
                )

                if covers_weak_area:
                    # Expand content for weak areas
                    section.estimated_study_time = int(
                        section.estimated_study_time * 1.5
                    )
                    section.study_questions.extend(
                        [
                            f"Additional practice: {section.title}",
                            f"Review key concepts in {section.title}",
                        ]
                    )

                # Adjust for learning style
                if learning_style == "visual":
                    section.additional_resources.append("Visual diagrams and charts")
                elif learning_style == "auditory":
                    section.additional_resources.append(
                        "Audio lectures and discussions"
                    )
                elif learning_style == "kinesthetic":
                    section.additional_resources.append(
                        "Hands-on practice and simulations"
                    )

                customized_sections.append(section)

            # Create customized guide
            customized_guide = StudyGuide(
                id=f"custom_{base_guide.id}",
                title=f"Personalized {base_guide.title}",
                topic=base_guide.topic,
                difficulty_level=base_guide.difficulty_level,
                target_audience=f"{base_guide.target_audience} (Personalized)",
                sections=customized_sections,
                overall_objectives=base_guide.overall_objectives,
                prerequisites=base_guide.prerequisites,
                estimated_completion_time=sum(
                    s.estimated_study_time for s in customized_sections
                ),
                competency_alignment=base_guide.competency_alignment,
                evidence_citations=base_guide.evidence_citations,
                generation_metadata={
                    **base_guide.generation_metadata,
                    "customization": {
                        "learning_style": learning_style,
                        "weak_areas": weak_areas,
                        "strong_areas": strong_areas,
                        "customized_at": datetime.utcnow().isoformat(),
                    },
                },
            )

            return customized_guide

        except Exception as e:
            logger.error(f"Study guide customization failed: {str(e)}")
            raise

    async def get_available_topics(self) -> List[str]:
        """
        Get available study guide topics
        """
        return [
            "Fundamentals of Nursing",
            "Anatomy and Physiology",
            "Pharmacology",
            "Medical-Surgical Nursing",
            "Psychiatric Nursing",
            "Pediatric Nursing",
            "Maternal Health Nursing",
            "Community Health Nursing",
            "Critical Care Nursing",
            "Pathophysiology",
            "Nursing Leadership",
            "Evidence-Based Practice",
        ]
