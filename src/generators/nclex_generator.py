from typing import Any, Dict, List, Optional
import json
import logging
from datetime import datetime

from pydantic import BaseModel, Field

from ..services.content_generation_service import (
    ContentGenerationService,
    GenerationRequest,
)

logger = logging.getLogger(__name__)


class NCLEXQuestion(BaseModel):
    question: str
    options: list[str] = Field(min_items=4, max_items=4)
    correct_answer: int = Field(ge=0, le=3)
    rationale: str
    category: str
    difficulty: str
    nclex_standard: str
    clinical_scenario: Optional[str] = None
    evidence_citations: List[str] = []
    umls_concepts: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)


class NCLEXQuestionSet(BaseModel):
    topic: str
    questions: List[NCLEXQuestion]
    generation_metadata: Dict[str, Any]
    validation_summary: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)


class NCLEXGenerator:
    """
    Enhanced NCLEX question generator using RAGnostic educational APIs
    and OpenAI for medically accurate question generation
    """

    def __init__(self, content_service: ContentGenerationService):
        self.content_service = content_service
        self.nclex_categories = [
            "Safe and Effective Care Environment",
            "Health Promotion and Maintenance",
            "Psychosocial Integrity",
            "Physiological Integrity",
        ]

        # NCLEX-specific prompts
        self.system_prompt = """
You are an expert nursing educator creating NCLEX-RN style questions. You must:

1. Generate questions that align with NCLEX-RN test plan categories
2. Ensure medical accuracy using evidence-based content
3. Create realistic clinical scenarios when appropriate
4. Include comprehensive rationales with evidence citations
5. Follow NCLEX format: stem + 4 options with 1 correct answer
6. Ensure cultural sensitivity and inclusive language
7. Focus on critical thinking and clinical judgment
8. Include application of nursing process when relevant

Response format: Valid JSON array of question objects.
"""

        self.question_template = """
Generate {count} NCLEX-RN style questions on the topic: {topic}

Requirements:
- Difficulty level: {difficulty}
- Category focus: Mix across NCLEX categories as appropriate
- Include clinical scenarios for complex questions
- Provide evidence-based rationales
- Use medical context provided below for accuracy

Medical Context from RAGnostic:
{medical_context}

Return as JSON array with this structure for each question:
{{
    "question": "question text with clinical scenario if needed",
    "options": ["option A", "option B", "option C", "option D"],
    "correct_answer": 0,
    "rationale": "comprehensive explanation with evidence",
    "category": "NCLEX category",
    "difficulty": "{difficulty}",
    "nclex_standard": "specific standard or competency",
    "clinical_scenario": "scenario text if applicable or null",
    "evidence_citations": ["citation 1", "citation 2"],
    "umls_concepts": ["concept 1", "concept 2"]
}}
"""

    async def generate_questions(
        self,
        topic: str,
        count: int = 10,
        difficulty: str = "intermediate",
        category: Optional[str] = None,
        include_scenarios: bool = True,
        medical_accuracy_threshold: float = 0.95,
    ) -> NCLEXQuestionSet:
        """
        Generate NCLEX questions using RAGnostic educational APIs

        Args:
            topic: Medical/nursing topic
            count: Number of questions to generate
            difficulty: Question difficulty level
            category: Specific NCLEX category to focus on
            include_scenarios: Whether to include clinical scenarios
            medical_accuracy_threshold: Minimum accuracy threshold

        Returns:
            NCLEXQuestionSet with validated questions
        """
        try:
            # Create generation request
            request = GenerationRequest(
                topic=topic,
                difficulty=difficulty,
                count=count,
                context_filters={
                    "content_type": "educational",
                    "category": category,
                    "nclex_relevant": True,
                },
                medical_accuracy_threshold=medical_accuracy_threshold,
            )

            # Generate content with validation
            result = await self.content_service.generate_content_with_validation(
                request=request,
                system_prompt=self.system_prompt,
                user_prompt_template=self.question_template,
                response_format="json_object",
            )

            # Parse generated questions
            questions_data = json.loads(result["content"])
            if isinstance(questions_data, dict) and "questions" in questions_data:
                questions_data = questions_data["questions"]

            # Validate and create question objects
            questions = []
            for i, q_data in enumerate(questions_data[:count]):
                try:
                    # Ensure required fields are present
                    q_data.setdefault("clinical_scenario", None)
                    q_data.setdefault("evidence_citations", [])
                    q_data.setdefault("umls_concepts", [])

                    # Validate correct_answer is within range
                    if not (0 <= q_data.get("correct_answer", -1) <= 3):
                        q_data["correct_answer"] = 0

                    # Ensure 4 options
                    options = q_data.get("options", [])
                    while len(options) < 4:
                        options.append(f"Option {len(options) + 1}")
                    q_data["options"] = options[:4]

                    question = NCLEXQuestion(**q_data)
                    questions.append(question)

                except Exception as e:
                    logger.warning(f"Failed to parse question {i}: {str(e)}")
                    continue

            if not questions:
                raise ValueError("No valid questions were generated")

            # Create question set
            question_set = NCLEXQuestionSet(
                topic=topic,
                questions=questions,
                generation_metadata=result["generation_metadata"],
                validation_summary=result["validation"],
            )

            logger.info(
                f"Generated {len(questions)} NCLEX questions for topic '{topic}' "
                f"with {result['validation']['confidence_score']:.2f} accuracy confidence"
            )

            return question_set

        except Exception as e:
            logger.error(
                f"NCLEX question generation failed for topic '{topic}': {str(e)}"
            )
            raise

    async def validate_question(self, question: NCLEXQuestion) -> Dict[str, Any]:
        """
        Validate a single NCLEX question for medical accuracy and format
        """
        try:
            # Convert question to text for validation
            question_text = f"""
            Question: {question.question}
            Options: {', '.join(question.options)}
            Correct Answer: {question.options[question.correct_answer]}
            Rationale: {question.rationale}
            """

            # Validate using content service
            validation = await self.content_service._validate_medical_accuracy(
                content=question_text, topic=question.category
            )

            # Additional NCLEX-specific validation
            format_issues = []

            if len(question.options) != 4:
                format_issues.append("Must have exactly 4 options")

            if not (0 <= question.correct_answer <= 3):
                format_issues.append("Correct answer must be 0-3")

            if question.category not in self.nclex_categories:
                format_issues.append(
                    f"Category must be one of: {self.nclex_categories}"
                )

            if len(question.question) < 50:
                format_issues.append("Question stem should be more detailed")

            if len(question.rationale) < 100:
                format_issues.append("Rationale should be more comprehensive")

            return {
                "is_valid": validation.is_accurate and not format_issues,
                "medical_accuracy": validation.dict(),
                "format_issues": format_issues,
                "overall_score": validation.confidence_score
                if not format_issues
                else 0.0,
            }

        except Exception as e:
            logger.error(f"Question validation failed: {str(e)}")
            return {"is_valid": False, "error": str(e), "overall_score": 0.0}

    async def get_available_categories(self) -> List[str]:
        """
        Get available NCLEX-RN test plan categories
        """
        return self.nclex_categories.copy()

    async def generate_clinical_scenario_questions(
        self,
        patient_condition: str,
        nursing_focus: str,
        count: int = 5,
        difficulty: str = "advanced",
    ) -> NCLEXQuestionSet:
        """
        Generate NCLEX questions with comprehensive clinical scenarios
        """
        scenario_template = (
            self.question_template
            + """

Additional Requirements for Clinical Scenarios:
- Create realistic patient scenarios with {patient_condition}
- Focus on {nursing_focus}
- Include relevant lab values, vital signs, or assessment data
- Questions should test clinical judgment and prioritization
- Consider cultural, ethical, and psychosocial factors
        """
        )

        request = GenerationRequest(
            topic=f"{patient_condition} - {nursing_focus}",
            difficulty=difficulty,
            count=count,
            context_filters={
                "content_type": "clinical_scenario",
                "condition": patient_condition,
                "nursing_focus": nursing_focus,
            },
        )

        result = await self.content_service.generate_content_with_validation(
            request=request,
            system_prompt=self.system_prompt,
            user_prompt_template=scenario_template,
        )

        # Parse and return as NCLEXQuestionSet
        questions_data = json.loads(result["content"])
        if isinstance(questions_data, dict) and "questions" in questions_data:
            questions_data = questions_data["questions"]

        questions = [NCLEXQuestion(**q) for q in questions_data[:count]]

        return NCLEXQuestionSet(
            topic=f"{patient_condition} - {nursing_focus}",
            questions=questions,
            generation_metadata=result["generation_metadata"],
            validation_summary=result["validation"],
        )
