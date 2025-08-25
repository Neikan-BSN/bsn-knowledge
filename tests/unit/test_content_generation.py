"""
Unit tests for content generation systems
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.generators.nclex_generator import NCLEXGenerator, NCLEXQuestion
from src.services.clinical_decision_support import (
    ClinicalAssessment,
    ClinicalDecisionSupportService,
    ClinicalRecommendation,
)
from src.services.content_generation_service import (
    ContentGenerationError,
    ContentGenerationService,
    GenerationRequest,
    MedicalValidationResult,
)


@pytest.fixture
def mock_ragnostic_client():
    """Mock RAGnostic client"""
    client = Mock()
    client.search_content = AsyncMock(
        return_value={
            "items": [
                {
                    "content": "Sample medical content",
                    "umls_concepts": ["C0001234", "C0005678"],
                    "citations": ["PubMed:12345678"],
                    "evidence_citations": ["Smith et al. 2024"],
                }
            ],
            "metadata": {"total": 1},
        }
    )
    client.validate_medical_content = AsyncMock(
        return_value={
            "is_valid": True,
            "confidence_score": 0.95,
            "validation_notes": [],
        }
    )
    return client


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client"""
    client = Mock()
    mock_response = Mock()
    mock_choice = Mock()
    mock_message = Mock()
    mock_message.content = """
    [{
        "question": "Which nursing intervention is priority for a patient with chest pain?",
        "options": ["Administer oxygen", "Take vital signs", "Call physician", "Position patient"],
        "correct_answer": 0,
        "rationale": "Oxygen is priority to improve tissue perfusion",
        "category": "Physiological Integrity",
        "difficulty": "intermediate",
        "nclex_standard": "NCLEX-RN Test Plan",
        "clinical_scenario": "Patient presents with chest pain and dyspnea",
        "evidence_citations": ["AHA Guidelines 2024"],
        "umls_concepts": ["C0008031", "C0013404"]
    }]
    """
    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]

    client.chat.completions.create = AsyncMock(return_value=mock_response)
    return client


@pytest.fixture
def content_service(mock_ragnostic_client, mock_openai_client):
    """Content generation service with mocked dependencies"""
    with patch("openai.AsyncOpenAI", return_value=mock_openai_client):
        service = ContentGenerationService(
            openai_api_key="test-key", ragnostic_client=mock_ragnostic_client
        )
        service.openai_client = mock_openai_client
        return service


class TestContentGenerationService:
    """Test ContentGenerationService"""

    @pytest.mark.asyncio
    async def test_get_enriched_context(self, content_service, mock_ragnostic_client):
        """Test enriched context retrieval"""
        context = await content_service._get_enriched_context("diabetes")

        assert "relevant_content" in context
        assert "medical_concepts" in context
        assert "evidence_base" in context
        mock_ragnostic_client.search_content.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_medical_accuracy(
        self, content_service, mock_ragnostic_client
    ):
        """Test medical accuracy validation"""
        validation = await content_service._validate_medical_accuracy(
            content="Test medical content", topic="diabetes", threshold=0.9
        )

        assert isinstance(validation, MedicalValidationResult)
        assert validation.is_accurate is True
        assert validation.confidence_score == 0.95
        mock_ragnostic_client.validate_medical_content.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_with_openai(self, content_service, mock_openai_client):
        """Test OpenAI content generation"""
        result = await content_service._generate_with_openai(
            system_prompt="Test system prompt", user_prompt="Test user prompt"
        )

        assert isinstance(result, str)
        assert len(result) > 0
        mock_openai_client.chat.completions.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_content_with_validation_success(self, content_service):
        """Test successful content generation with validation"""
        request = GenerationRequest(
            topic="diabetes management",
            difficulty="intermediate",
            count=1,
            medical_accuracy_threshold=0.9,
        )

        result = await content_service.generate_content_with_validation(
            request=request,
            system_prompt="Test system prompt",
            user_prompt_template="Generate content for {topic} at {difficulty} level: {medical_context}",
            response_format="json",
        )

        assert "content" in result
        assert "validation" in result
        assert "context" in result
        assert "generation_metadata" in result

    @pytest.mark.asyncio
    async def test_generate_content_validation_failure(
        self, content_service, mock_ragnostic_client
    ):
        """Test content generation with validation failure"""
        # Mock validation failure
        mock_ragnostic_client.validate_medical_content.return_value = {
            "is_valid": False,
            "confidence_score": 0.5,
            "validation_notes": ["Low confidence score"],
        }

        request = GenerationRequest(
            topic="test topic",
            difficulty="intermediate",
            count=1,
            medical_accuracy_threshold=0.9,
        )

        with pytest.raises(ContentGenerationError):
            await content_service.generate_content_with_validation(
                request=request,
                system_prompt="Test",
                user_prompt_template="Test: {medical_context}",
                max_validation_attempts=1,
            )


class TestNCLEXGenerator:
    """Test NCLEXGenerator"""

    @pytest.fixture
    def nclex_generator(self, content_service):
        """NCLEX generator with mocked content service"""
        return NCLEXGenerator(content_service)

    @pytest.mark.asyncio
    async def test_generate_questions(self, nclex_generator):
        """Test NCLEX question generation"""
        question_set = await nclex_generator.generate_questions(
            topic="cardiac care", count=1, difficulty="intermediate"
        )

        assert question_set.topic == "cardiac care"
        assert len(question_set.questions) >= 1
        assert isinstance(question_set.questions[0], NCLEXQuestion)

        # Validate question structure
        question = question_set.questions[0]
        assert len(question.options) == 4
        assert 0 <= question.correct_answer <= 3
        assert len(question.rationale) > 0

    @pytest.mark.asyncio
    async def test_validate_question(self, nclex_generator):
        """Test NCLEX question validation"""
        question = NCLEXQuestion(
            question="Test question?",
            options=["A", "B", "C", "D"],
            correct_answer=0,
            rationale="Test rationale with sufficient detail for comprehensive understanding",
            category="Physiological Integrity",
            difficulty="intermediate",
            nclex_standard="NCLEX-RN",
        )

        validation = await nclex_generator.validate_question(question)

        assert "is_valid" in validation
        assert "medical_accuracy" in validation
        assert "overall_score" in validation

    @pytest.mark.asyncio
    async def test_get_available_categories(self, nclex_generator):
        """Test getting available NCLEX categories"""
        categories = await nclex_generator.get_available_categories()

        assert isinstance(categories, list)
        assert "Physiological Integrity" in categories
        assert "Safe and Effective Care Environment" in categories

    @pytest.mark.asyncio
    async def test_generate_clinical_scenario_questions(self, nclex_generator):
        """Test clinical scenario question generation"""
        question_set = await nclex_generator.generate_clinical_scenario_questions(
            patient_condition="diabetes",
            nursing_focus="medication management",
            count=1,
            difficulty="advanced",
        )

        assert len(question_set.questions) >= 1
        question = question_set.questions[0]
        assert question.clinical_scenario is not None
        assert len(question.clinical_scenario) > 0


class TestClinicalDecisionSupport:
    """Test ClinicalDecisionSupportService"""

    @pytest.fixture
    def clinical_service(self, content_service):
        """Clinical decision support service"""
        return ClinicalDecisionSupportService(content_service)

    @pytest.fixture
    def sample_assessment(self):
        """Sample clinical assessment"""
        return ClinicalAssessment(
            patient_condition="diabetes type 2",
            symptoms=["polyuria", "polydipsia", "fatigue"],
            vital_signs={"bp": "140/90", "hr": 88, "temp": 98.6},
            lab_values={"glucose": 280, "hba1c": 9.2},
            medications=["metformin"],
            allergies=["penicillin"],
            comorbidities=["hypertension"],
            nursing_concerns=["medication adherence", "blood sugar monitoring"],
        )

    @pytest.mark.asyncio
    async def test_get_clinical_recommendations(
        self, clinical_service, sample_assessment, content_service
    ):
        """Test clinical recommendation generation"""
        # Mock the content service response for clinical recommendations
        mock_clinical_response = """
        {
            "recommendations": [
                {
                    "id": "rec_1",
                    "recommendation_text": "Monitor blood glucose levels every 4 hours",
                    "rationale": "Hyperglycemia requires frequent monitoring",
                    "evidence_level": "systematic_review_meta_analysis",
                    "confidence_score": 0.95,
                    "priority": "high",
                    "contraindications": [],
                    "monitoring_parameters": ["blood glucose", "symptoms"],
                    "evidence_citations": ["ADA Guidelines 2024"],
                    "umls_concepts": ["C0005802"]
                }
            ],
            "nursing_diagnoses": ["Risk for unstable blood glucose"],
            "priority_interventions": ["Blood glucose monitoring"],
            "educational_needs": ["Diabetes management"],
            "safety_considerations": ["Hypoglycemia risk"],
            "evidence_summary": {
                "total_recommendations": 1,
                "high_evidence_count": 1,
                "average_confidence": 0.95
            },
            "confidence_score": 0.95
        }
        """

        # Update the mock to return clinical content
        content_service.openai_client.chat.completions.create.return_value.choices[
            0
        ].message.content = mock_clinical_response

        response = await clinical_service.get_clinical_recommendations(
            assessment=sample_assessment, focus_area="glucose management"
        )

        assert len(response.recommendations) >= 1
        assert isinstance(response.recommendations[0], ClinicalRecommendation)
        assert response.confidence_score > 0
        assert len(response.nursing_diagnoses) >= 1

    @pytest.mark.asyncio
    async def test_get_emergency_protocols(self, clinical_service):
        """Test emergency protocol generation"""
        result = await clinical_service.get_emergency_protocols(
            emergency_situation="cardiac arrest",
            patient_factors={"age": 65, "weight": 70},
        )

        assert "emergency_protocols" in result
        assert "validation" in result
        assert "generated_at" in result

    @pytest.mark.asyncio
    async def test_validate_care_plan(self, clinical_service):
        """Test care plan validation"""
        care_plan = {
            "nursing_diagnoses": ["Risk for infection"],
            "goals": ["Patient will remain infection-free"],
            "interventions": [
                {"action": "Hand hygiene", "frequency": "before/after contact"}
            ],
        }

        validation = await clinical_service.validate_care_plan(
            care_plan=care_plan, patient_condition="post-surgical"
        )

        assert "is_valid" in validation
        assert "validation_details" in validation


class TestIntegration:
    """Integration tests for content generation systems"""

    @pytest.mark.asyncio
    async def test_end_to_end_nclex_generation(self, content_service):
        """Test complete NCLEX generation workflow"""
        generator = NCLEXGenerator(content_service)

        # Generate questions
        question_set = await generator.generate_questions(
            topic="nursing fundamentals", count=2, difficulty="beginner"
        )

        # Validate questions
        for question in question_set.questions:
            validation = await generator.validate_question(question)
            assert validation["overall_score"] >= 0

    @pytest.mark.asyncio
    async def test_content_accuracy_workflow(
        self, content_service, mock_ragnostic_client
    ):
        """Test medical accuracy validation workflow"""
        # Test high accuracy content
        mock_ragnostic_client.validate_medical_content.return_value = {
            "is_valid": True,
            "confidence_score": 0.96,
        }

        validation = await content_service._validate_medical_accuracy(
            content="Evidence-based nursing intervention",
            topic="evidence-based practice",
            threshold=0.95,
        )

        assert validation.is_accurate is True
        assert validation.confidence_score >= 0.95

    @pytest.mark.asyncio
    async def test_service_dependencies(self, mock_ragnostic_client):
        """Test service dependency injection and lifecycle"""
        with patch("openai.AsyncOpenAI") as mock_openai:
            service = ContentGenerationService(
                openai_api_key="test-key", ragnostic_client=mock_ragnostic_client
            )

            # Test service initialization
            assert service.ragnostic == mock_ragnostic_client
            assert service.model_name == "gpt-4"

            # Test cleanup
            await service.close()
            mock_openai.return_value.close.assert_called_once()


# Performance and reliability tests
class TestPerformance:
    """Performance and reliability tests"""

    @pytest.mark.asyncio
    async def test_response_time_requirements(self, content_service):
        """Test that content generation meets response time requirements"""
        import time

        request = GenerationRequest(
            topic="basic nursing care", difficulty="beginner", count=1
        )

        start_time = time.time()

        result = await content_service.generate_content_with_validation(
            request=request,
            system_prompt="Generate nursing content",
            user_prompt_template="Topic: {topic}, Context: {medical_context}",
        )

        elapsed_time = time.time() - start_time

        # Should complete within 5 seconds for simple content
        assert elapsed_time < 5.0
        assert "content" in result

    @pytest.mark.asyncio
    async def test_error_handling_resilience(
        self, content_service, mock_ragnostic_client
    ):
        """Test error handling and resilience"""
        # Test RAGnostic service failure
        mock_ragnostic_client.search_content.side_effect = Exception(
            "Service unavailable"
        )

        context = await content_service._get_enriched_context("test topic")

        # Should return empty context on failure, not crash
        assert context["relevant_content"] == []
        assert context["medical_concepts"] == []
        assert context["evidence_base"] == []
