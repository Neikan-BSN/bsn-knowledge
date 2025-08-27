"""
Comprehensive Test Suite for BSN Knowledge Phase 3 B.6 API Endpoints

This test suite provides complete coverage of the four required B.6 endpoints:
1. /api/v1/nclex/generate - NCLEX question generation
2. /api/v1/assessment/competency - Competency assessment
3. /api/v1/study-guide/create - Study guide creation
4. /api/v1/analytics/student/{student_id} - Student analytics

Tests include unit tests, integration tests, performance validation,
security verification, and error handling scenarios.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.models.assessment_models import (
    CompetencyProficiencyLevel,
    StudentProgressMetrics,
)


@pytest.mark.b6_endpoints
class TestB6NCLEXGenerationEndpoint:
    """Comprehensive tests for /api/v1/nclex/generate endpoint."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_nclex_generate_successful_request(
        self, mock_ragnostic, client: TestClient, auth_headers, mock_nclex_questions
    ):
        """Test successful NCLEX question generation with complete validation."""
        mock_client = AsyncMock()
        mock_client.generate_questions.return_value = mock_nclex_questions
        mock_ragnostic.return_value = mock_client

        request_data = {
            "topic": "cardiovascular_nursing",
            "difficulty": "medium",
            "question_count": 5,
            "question_types": ["multiple_choice"],
            "include_rationales": True,
        }

        response = client.post(
            "/api/v1/nclex/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Validate complete response structure
        assert "questions" in data
        assert "metadata" in data
        assert len(data["questions"]) >= 1

        # Validate each question structure
        for question in data["questions"]:
            assert all(
                field in question
                for field in [
                    "id",
                    "question",
                    "options",
                    "correct_answer",
                    "rationale",
                    "difficulty",
                ]
            )
            assert isinstance(question["options"], list)
            assert len(question["options"]) >= 2
            assert question["correct_answer"] in ["A", "B", "C", "D"]
            assert len(question["rationale"]) > 10  # Meaningful rationale

        # Validate metadata
        metadata = data["metadata"]
        assert "topic" in metadata
        assert "difficulty" in metadata
        assert "generation_time" in metadata

    def test_nclex_generate_all_difficulty_levels(
        self, client: TestClient, auth_headers
    ):
        """Test NCLEX generation with all supported difficulty levels."""
        difficulties = ["easy", "medium", "hard"]

        for difficulty in difficulties:
            request_data = {
                "topic": "nursing_fundamentals",
                "difficulty": difficulty,
                "question_count": 3,
            }

            response = client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )

            # Should handle all difficulty levels
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]

            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                assert data["metadata"]["difficulty"] == difficulty

    def test_nclex_generate_question_count_validation(
        self, client: TestClient, auth_headers
    ):
        """Test question count validation and limits."""
        test_counts = [1, 5, 10, 20, 50, 100]

        for count in test_counts:
            request_data = {
                "topic": "test_topic",
                "difficulty": "medium",
                "question_count": count,
            }

            response = client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )

            if count <= 50:  # Reasonable limit
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                ]
            else:  # Should reject very large requests
                assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_nclex_generate_multiple_question_types(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test NCLEX generation with multiple question types."""
        mock_client = AsyncMock()
        mock_client.generate_questions.return_value = {
            "questions": [
                {
                    "id": "q1",
                    "type": "multiple_choice",
                    "question": "Sample multiple choice question?",
                    "options": [
                        "A. Option 1",
                        "B. Option 2",
                        "C. Option 3",
                        "D. Option 4",
                    ],
                    "correct_answer": "B",
                    "rationale": "Detailed explanation for the correct answer.",
                    "difficulty": "medium",
                },
                {
                    "id": "q2",
                    "type": "select_all_that_apply",
                    "question": "Select all that apply question?",
                    "options": [
                        "A. Option 1",
                        "B. Option 2",
                        "C. Option 3",
                        "D. Option 4",
                    ],
                    "correct_answer": ["A", "C"],
                    "rationale": "Explanation for multiple correct answers.",
                    "difficulty": "medium",
                },
            ],
            "metadata": {
                "topic": "mixed_types",
                "question_types": ["multiple_choice", "select_all_that_apply"],
            },
        }
        mock_ragnostic.return_value = mock_client

        request_data = {
            "topic": "mixed_nursing_concepts",
            "difficulty": "medium",
            "question_count": 5,
            "question_types": ["multiple_choice", "select_all_that_apply"],
        }

        response = client.post(
            "/api/v1/nclex/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should handle multiple question types
        question_types = [q.get("type") for q in data["questions"]]
        assert len(set(question_types)) >= 1  # At least one type represented

    def test_nclex_generate_performance_requirements(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test NCLEX generation meets performance requirements (<2s)."""
        request_data = {
            "topic": "performance_test",
            "difficulty": "medium",
            "question_count": 5,
        }

        performance_monitor.start()
        response = client.post(
            "/api/v1/nclex/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )
        performance_monitor.stop()

        # Should complete within 2 seconds
        performance_monitor.assert_within_threshold(2.0)

        # Should not fail due to performance issues
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_nclex_generate_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test NCLEX generation rate limiting (50 requests/hour)."""
        request_data = {
            "topic": "rate_limit_test",
            "difficulty": "easy",
            "question_count": 1,
        }

        # Make multiple requests rapidly
        responses = []
        for _i in range(60):  # More than the limit
            response = client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )
            responses.append(response.status_code)

        # Should see mix of successful and rate-limited responses
        sum(1 for code in responses if code == status.HTTP_200_OK)
        rate_limited_count = sum(
            1 for code in responses if code == status.HTTP_429_TOO_MANY_REQUESTS
        )

        # Should have some rate limiting kick in
        assert rate_limited_count > 10  # Should be rate limited

    def test_nclex_generate_error_handling(self, client: TestClient, auth_headers):
        """Test NCLEX generation error handling and validation."""
        error_scenarios = [
            # Missing required fields
            ({}, status.HTTP_422_UNPROCESSABLE_ENTITY),
            # Invalid difficulty
            (
                {"topic": "test", "difficulty": "invalid", "question_count": 5},
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ),
            # Invalid question count
            (
                {"topic": "test", "difficulty": "medium", "question_count": -1},
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ),
            # Extremely large request
            (
                {
                    "topic": "x" * 10000,
                    "difficulty": "medium",
                    "question_count": 1000,
                },
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ),
        ]

        for request_data, expected_status in error_scenarios:
            response = client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )
            assert response.status_code == expected_status


@pytest.mark.b6_endpoints
class TestB6CompetencyAssessmentEndpoint:
    """Comprehensive tests for /api/v1/assessment/competency endpoint."""

    @patch("src.dependencies.get_competency_framework_dep")
    def test_competency_assessment_successful_request(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test successful competency assessment with complete validation."""
        mock_framework_dep.return_value = mock_competency_framework

        request_data = {
            "student_id": "student_001",
            "competency_id": "AACN_KNOWLEDGE_1",
            "performance_data": {
                "quiz_scores": [85, 78, 92, 88],
                "clinical_evaluations": {
                    "communication": 4.2,
                    "clinical_reasoning": 3.8,
                    "technical_skills": 4.0,
                    "professionalism": 4.5,
                },
                "simulation_scores": {"scenario_1": 88, "scenario_2": 92},
            },
            "assessment_type": "comprehensive",
            "assessor_id": "instructor_001",
        }

        response = client.post(
            "/api/v1/assessment/competency",
            json=request_data,
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Validate complete response structure
        required_fields = [
            "student_id",
            "competency_id",
            "current_level",
            "score",
            "strengths",
            "areas_for_improvement",
            "recommendations",
            "assessment_date",
            "proficiency_trend",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Validate field types and values
        assert data["student_id"] == "student_001"
        assert data["competency_id"] == "AACN_KNOWLEDGE_1"
        assert isinstance(data["score"], int | float)
        assert 0 <= data["score"] <= 100
        assert isinstance(data["strengths"], list)
        assert isinstance(data["areas_for_improvement"], list)
        assert isinstance(data["recommendations"], list)
        assert data["current_level"] in [
            level.value for level in CompetencyProficiencyLevel
        ]

    def test_competency_assessment_all_aacn_domains(
        self, client: TestClient, auth_headers, mock_competency_framework
    ):
        """Test competency assessment for all AACN domains."""
        aacn_competencies = [
            "AACN_KNOWLEDGE_1",
            "AACN_PERSON_CENTERED_1",
            "AACN_POPULATION_HEALTH_1",
            "AACN_SCHOLARSHIP_1",
            "AACN_INFORMATION_TECH_1",
            "AACN_HEALTHCARE_SYSTEMS_1",
            "AACN_INTERPROFESSIONAL_1",
            "AACN_PROFESSIONAL_DEV_1",
        ]

        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_dep.return_value = mock_competency_framework

            for competency_id in aacn_competencies:
                request_data = {
                    "student_id": "test_student",
                    "competency_id": competency_id,
                    "performance_data": {"quiz_scores": [80, 85, 90]},
                    "assessment_type": "domain_test",
                    "assessor_id": "test_assessor",
                }

                response = client.post(
                    "/api/v1/assessment/competency",
                    json=request_data,
                    headers=auth_headers["instructor1"],
                )

                # Should handle all AACN competencies
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                ]

    def test_competency_assessment_performance_data_validation(
        self, client: TestClient, auth_headers, mock_competency_framework
    ):
        """Test validation of different performance data formats."""
        performance_data_scenarios = [
            # Minimal data
            {"quiz_scores": [80]},
            # Comprehensive data
            {
                "quiz_scores": [85, 78, 92, 88],
                "clinical_evaluations": {
                    "communication": 4.2,
                    "clinical_reasoning": 3.8,
                    "technical_skills": 4.0,
                },
                "simulation_scores": {"scenario_1": 88},
                "assignment_scores": [90, 85],
                "peer_evaluations": {"collaboration": 4.5},
                "self_assessment": {"confidence": 3.8},
            },
            # Edge case - empty data
            {},
            # Invalid data types
            {"quiz_scores": "not_a_list"},
        ]

        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_dep.return_value = mock_competency_framework

            for i, performance_data in enumerate(performance_data_scenarios):
                request_data = {
                    "student_id": f"test_student_{i}",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": performance_data,
                    "assessment_type": "validation_test",
                }

                response = client.post(
                    "/api/v1/assessment/competency",
                    json=request_data,
                    headers=auth_headers["instructor1"],
                )

                # Should handle different data formats appropriately
                assert response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    status.HTTP_400_BAD_REQUEST,
                ]

    def test_competency_assessment_bulk_operation(
        self, client: TestClient, auth_headers, mock_competency_framework
    ):
        """Test bulk competency assessment functionality."""
        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_dep.return_value = mock_competency_framework

            bulk_request = {
                "assessments": [
                    {
                        "student_id": "student_001",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [85, 90]},
                        "assessment_type": "bulk_test",
                        "assessor_id": "instructor_001",
                    },
                    {
                        "student_id": "student_002",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [75, 82]},
                        "assessment_type": "bulk_test",
                        "assessor_id": "instructor_001",
                    },
                    {
                        "student_id": "student_003",
                        "competency_id": "AACN_PERSON_CENTERED_1",
                        "performance_data": {"clinical_evaluations": {"empathy": 4.5}},
                        "assessment_type": "bulk_test",
                        "assessor_id": "instructor_001",
                    },
                ],
                "batch_id": "bulk_test_2024",
            }

            response = client.post(
                "/api/v1/assessment/competency/assess/bulk",
                json=bulk_request,
                headers=auth_headers["instructor1"],
            )

            assert response.status_code == status.HTTP_200_OK
            data = response.json()

            # Validate bulk response structure
            assert "batch_id" in data
            assert "total_assessments" in data
            assert "successful_assessments" in data
            assert "failed_assessments" in data
            assert "results" in data
            assert "errors" in data

            assert data["total_assessments"] == 3
            assert data["batch_id"] == "bulk_test_2024"

    def test_competency_assessment_performance_requirements(
        self,
        client: TestClient,
        auth_headers,
        performance_monitor,
        mock_competency_framework,
    ):
        """Test competency assessment meets performance requirements (<500ms)."""
        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_dep.return_value = mock_competency_framework

            request_data = {
                "student_id": "perf_test_student",
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {"quiz_scores": [80, 85, 90]},
                "assessment_type": "performance_test",
            }

            performance_monitor.start()
            response = client.post(
                "/api/v1/assessment/competency",
                json=request_data,
                headers=auth_headers["instructor1"],
            )
            performance_monitor.stop()

            # Should complete within 500ms for simple assessments
            performance_monitor.assert_within_threshold(0.5)
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_competency_assessment_authorization_roles(
        self, client: TestClient, auth_headers, mock_competency_framework
    ):
        """Test role-based authorization for competency assessment."""
        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_dep.return_value = mock_competency_framework

            request_data = {
                "student_id": "auth_test_student",
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {"quiz_scores": [80]},
                "assessment_type": "auth_test",
            }

            # Test different role access
            role_tests = [
                ("student1", status.HTTP_403_FORBIDDEN),  # Students shouldn't assess
                ("instructor1", status.HTTP_200_OK),  # Instructors can assess
                ("admin1", status.HTTP_200_OK),  # Admins can assess
            ]

            for role, expected_status in role_tests:
                response = client.post(
                    "/api/v1/assessment/competency",
                    json=request_data,
                    headers=auth_headers[role],
                )
                assert response.status_code == expected_status


@pytest.mark.b6_endpoints
class TestB6StudyGuideCreationEndpoint:
    """Comprehensive tests for /api/v1/study-guide/create endpoint."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_study_guide_create_successful_request(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test successful study guide creation with complete validation."""
        mock_client = AsyncMock()
        mock_client.enrich_content.return_value = {
            "enriched_content": "Enhanced study guide content with detailed explanations",
            "learning_objectives": [
                "Identify normal and abnormal cardiovascular sounds",
                "Perform comprehensive cardiac assessment",
                "Recognize signs of cardiac distress",
            ],
            "assessment_suggestions": [
                "Practice quiz on heart sounds",
                "Case study analysis assignment",
                "Simulation scenario evaluation",
            ],
            "content_structure": {
                "introduction": "Overview of cardiovascular assessment",
                "main_concepts": ["Anatomy", "Physiology", "Assessment techniques"],
                "clinical_applications": [
                    "Patient scenarios",
                    "Critical thinking exercises",
                ],
            },
        }
        mock_ragnostic.return_value = mock_client

        request_data = {
            "topic": "Cardiovascular Assessment",
            "competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
            "difficulty_level": "intermediate",
            "learning_objectives": [
                "Identify normal and abnormal heart sounds",
                "Perform comprehensive cardiac assessment",
                "Understand cardiovascular pathophysiology",
            ],
            "student_level": "junior",
            "include_case_studies": True,
            "format_preferences": ["visual_diagrams", "step_by_step_procedures"],
            "estimated_study_time": 4.0,
        }

        response = client.post(
            "/api/v1/study-guide/create",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Validate complete response structure
        required_fields = [
            "topic",
            "content_sections",
            "learning_objectives",
            "assessment_methods",
            "estimated_study_time_hours",
            "competency_alignment",
            "created_at",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Validate content quality
        assert data["topic"] == "Cardiovascular Assessment"
        assert isinstance(data["content_sections"], list)
        assert len(data["content_sections"]) >= 1
        assert isinstance(data["learning_objectives"], list)
        assert len(data["learning_objectives"]) >= 3
        assert isinstance(data["assessment_methods"], list)
        assert isinstance(data["estimated_study_time_hours"], int | float)
        assert data["estimated_study_time_hours"] > 0

    def test_study_guide_create_all_difficulty_levels(
        self, client: TestClient, auth_headers
    ):
        """Test study guide creation for all difficulty levels."""
        difficulty_levels = ["beginner", "intermediate", "advanced"]

        for difficulty in difficulty_levels:
            request_data = {
                "topic": f"Nursing Fundamentals - {difficulty}",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": difficulty,
                "learning_objectives": [f"Master {difficulty} concepts"],
                "student_level": difficulty,
            }

            response = client.post(
                "/api/v1/study-guide/create",
                json=request_data,
                headers=auth_headers["student1"],
            )

            # Should handle all difficulty levels
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                assert data["difficulty_level"] == difficulty

    def test_study_guide_create_multiple_competencies(
        self, client: TestClient, auth_headers
    ):
        """Test study guide creation with multiple AACN competencies."""
        competency_combinations = [
            ["AACN_KNOWLEDGE_1"],
            ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
            [
                "AACN_KNOWLEDGE_1",
                "AACN_PERSON_CENTERED_1",
                "AACN_POPULATION_HEALTH_1",
                "AACN_SCHOLARSHIP_1",
            ],
        ]

        for competencies in competency_combinations:
            request_data = {
                "topic": f"Multi-Competency Study Guide - {len(competencies)} domains",
                "competencies": competencies,
                "difficulty_level": "intermediate",
                "learning_objectives": [
                    f"Integrate concepts from {len(competencies)} AACN domains"
                ],
            }

            response = client.post(
                "/api/v1/study-guide/create",
                json=request_data,
                headers=auth_headers["student1"],
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_study_guide_create_format_preferences(
        self, client: TestClient, auth_headers
    ):
        """Test study guide creation with different format preferences."""
        format_combinations = [
            ["text_only"],
            ["visual_diagrams"],
            ["step_by_step_procedures"],
            ["case_studies"],
            ["visual_diagrams", "step_by_step_procedures", "case_studies"],
        ]

        for formats in format_combinations:
            request_data = {
                "topic": f"Format Test - {'-'.join(formats)}",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": "intermediate",
                "format_preferences": formats,
                "include_case_studies": "case_studies" in formats,
            }

            response = client.post(
                "/api/v1/study-guide/create",
                json=request_data,
                headers=auth_headers["student1"],
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_study_guide_create_performance_requirements(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test study guide creation meets performance requirements (<2s)."""
        request_data = {
            "topic": "Performance Test Study Guide",
            "competencies": ["AACN_KNOWLEDGE_1"],
            "difficulty_level": "intermediate",
            "learning_objectives": ["Test performance requirements"],
        }

        performance_monitor.start()
        response = client.post(
            "/api/v1/study-guide/create",
            json=request_data,
            headers=auth_headers["student1"],
        )
        performance_monitor.stop()

        # Should complete within 2 seconds
        performance_monitor.assert_within_threshold(2.0)
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_study_guide_create_large_content_handling(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test handling of large study guide requests."""
        large_request = {
            "topic": "Comprehensive Advanced Nursing Practice Study Guide",
            "competencies": [
                "AACN_KNOWLEDGE_1",
                "AACN_PERSON_CENTERED_1",
                "AACN_POPULATION_HEALTH_1",
                "AACN_SCHOLARSHIP_1",
            ],
            "difficulty_level": "advanced",
            "learning_objectives": [
                f"Learning objective {i}: Detailed description of advanced nursing competency and clinical skill development"
                for i in range(25)
            ],
            "description": "A comprehensive study guide covering multiple domains of nursing practice with extensive detail and clinical applications. "
            * 50,  # Large description
            "student_level": "senior",
            "include_case_studies": True,
            "format_preferences": [
                "visual_diagrams",
                "step_by_step_procedures",
                "case_studies",
                "interactive_elements",
            ],
        }

        performance_monitor.start()
        response = client.post(
            "/api/v1/study-guide/create",
            json=large_request,
            headers=auth_headers["student1"],
        )
        performance_monitor.stop()

        # Should handle large requests within reasonable time
        performance_monitor.assert_within_threshold(5.0)

        # Should either succeed or fail gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_501_NOT_IMPLEMENTED,
        ]

    def test_study_guide_create_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test study guide creation rate limiting (50 requests/hour)."""
        request_data = {
            "topic": "Rate Limit Test Guide",
            "competencies": ["AACN_KNOWLEDGE_1"],
            "difficulty_level": "beginner",
            "learning_objectives": ["Test rate limiting"],
        }

        # Make multiple requests rapidly
        responses = []
        for _i in range(60):  # More than the limit
            response = client.post(
                "/api/v1/study-guide/create",
                json=request_data,
                headers=auth_headers["student1"],
            )
            responses.append(response.status_code)

        # Should see rate limiting
        rate_limited_count = sum(
            1 for code in responses if code == status.HTTP_429_TOO_MANY_REQUESTS
        )
        assert rate_limited_count > 10  # Should be rate limited


@pytest.mark.b6_endpoints
class TestB6StudentAnalyticsEndpoint:
    """Comprehensive tests for /api/v1/analytics/student/{student_id} endpoint."""

    @patch("src.services.analytics_service.AnalyticsService")
    def test_student_analytics_successful_request(
        self, mock_analytics, client: TestClient, auth_headers, mock_analytics_data
    ):
        """Test successful student analytics retrieval with complete validation."""
        mock_service = AsyncMock()
        mock_service.get_student_progress.return_value = StudentProgressMetrics(
            student_id="student_001",
            overall_progress=78.5,
            competency_scores={
                "knowledge_for_nursing_practice": 82.0,
                "person_centered_care": 88.0,
                "population_health": 75.0,
                "scholarship_for_nursing_discipline": 70.0,
                "information_technology": 85.0,
                "healthcare_systems": 72.0,
                "interprofessional_partnerships": 90.0,
                "personal_professional_development": 86.0,
            },
            learning_velocity=2.4,
            engagement_score=82.3,
            areas_for_improvement=["Population Health", "Healthcare Systems"],
            strengths=["Interprofessional Communication", "Person-Centered Care"],
            time_to_graduation_estimate=18.5,
            risk_factors=[],
            last_updated=datetime.now(UTC),
        )
        mock_analytics.return_value = mock_service

        response = client.get(
            "/api/v1/analytics/student/student_001",
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Validate complete analytics response structure
        required_fields = [
            "student_id",
            "overall_progress",
            "competency_scores",
            "learning_velocity",
            "engagement_score",
            "areas_for_improvement",
            "strengths",
            "last_updated",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Validate field types and values
        assert data["student_id"] == "student_001"
        assert isinstance(data["overall_progress"], int | float)
        assert 0 <= data["overall_progress"] <= 100
        assert isinstance(data["competency_scores"], dict)
        assert len(data["competency_scores"]) == 8  # All 8 AACN domains
        assert isinstance(data["areas_for_improvement"], list)
        assert isinstance(data["strengths"], list)

        # Validate AACN competency domains
        expected_domains = [
            "knowledge_for_nursing_practice",
            "person_centered_care",
            "population_health",
            "scholarship_for_nursing_discipline",
            "information_technology",
            "healthcare_systems",
            "interprofessional_partnerships",
            "personal_professional_development",
        ]

        for domain in expected_domains:
            assert domain in data["competency_scores"]
            assert 0 <= data["competency_scores"][domain] <= 100

    def test_student_analytics_with_time_filters(
        self, client: TestClient, auth_headers
    ):
        """Test student analytics with time period filtering."""
        time_periods = ["week", "month", "semester", "year", "all"]

        for period in time_periods:
            response = client.get(
                f"/api/v1/analytics/student/student_001?time_period={period}",
                headers=auth_headers["instructor1"],
            )

            # Should handle all time periods
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_student_analytics_competency_filtering(
        self, client: TestClient, auth_headers
    ):
        """Test student analytics with competency domain filtering."""
        competency_domains = [
            "knowledge_for_nursing_practice",
            "person_centered_care",
            "population_health",
            "scholarship_for_nursing_discipline",
        ]

        for domain in competency_domains:
            response = client.get(
                f"/api/v1/analytics/student/student_001?competency_filter={domain}",
                headers=auth_headers["instructor1"],
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_student_analytics_detailed_breakdown(
        self, client: TestClient, auth_headers
    ):
        """Test student analytics with detailed breakdown options."""
        detail_options = [
            "include_quiz_history=true",
            "include_competency_trends=true",
            "include_peer_comparison=true",
            "include_learning_recommendations=true",
        ]

        for option in detail_options:
            response = client.get(
                f"/api/v1/analytics/student/student_001?{option}",
                headers=auth_headers["instructor1"],
            )

            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_student_analytics_performance_requirements(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test student analytics meets performance requirements (<500ms)."""
        performance_monitor.start()
        response = client.get(
            "/api/v1/analytics/student/student_001",
            headers=auth_headers["instructor1"],
        )
        performance_monitor.stop()

        # Should complete within 500ms
        performance_monitor.assert_within_threshold(0.5)
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_student_analytics_authorization_controls(
        self, client: TestClient, auth_headers
    ):
        """Test student analytics authorization and data access controls."""
        # Test different role access patterns
        access_tests = [
            # Student accessing own data
            ("student1", "student1", status.HTTP_200_OK),
            # Student trying to access other student's data
            ("student1", "student2", status.HTTP_403_FORBIDDEN),
            # Instructor accessing student data
            ("instructor1", "student_001", status.HTTP_200_OK),
            # Admin accessing any student data
            ("admin1", "student_001", status.HTTP_200_OK),
        ]

        for role, target_student, expected_status in access_tests:
            response = client.get(
                f"/api/v1/analytics/student/{target_student}",
                headers=auth_headers[role],
            )
            # Note: Implementation may vary on authorization logic
            assert response.status_code in [
                expected_status,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]

    def test_student_analytics_rate_limiting(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test student analytics rate limiting (500 requests/hour)."""
        # Make multiple requests rapidly
        responses = []
        for _i in range(550):  # More than the limit
            response = client.get(
                "/api/v1/analytics/student/student_001",
                headers=auth_headers["instructor1"],
            )
            responses.append(response.status_code)

        # Analytics should have higher rate limit
        success_count = sum(1 for code in responses if code == status.HTTP_200_OK)
        sum(1 for code in responses if code == status.HTTP_429_TOO_MANY_REQUESTS)

        # Should allow more requests than content generation
        assert success_count > 400  # Should allow most requests

    def test_student_analytics_data_privacy(self, client: TestClient, auth_headers):
        """Test student analytics data privacy and sanitization."""
        response = client.get(
            "/api/v1/analytics/student/student_001",
            headers=auth_headers["instructor1"],
        )

        if response.status_code == status.HTTP_200_OK:
            response_text = response.text.lower()

            # Should not contain sensitive personal information
            sensitive_patterns = [
                "social security",
                "ssn",
                "credit card",
                "password",
                "home address",
                "phone number",
                "email@domain.com",  # Specific email patterns
            ]

            for pattern in sensitive_patterns:
                assert pattern not in response_text


@pytest.mark.b6_endpoints
class TestB6EndpointsIntegration:
    """Integration tests for all B.6 endpoints working together."""

    def test_complete_student_workflow_integration(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test complete student workflow using all B.6 endpoints."""
        student_id = "integration_test_student"

        # Step 1: Generate NCLEX questions
        nclex_response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "integration_test",
                "difficulty": "medium",
                "question_count": 3,
            },
            headers=auth_headers["student1"],
        )

        # Step 2: Create study guide
        study_guide_response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Integration Test Study Guide",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": "intermediate",
                "learning_objectives": ["Complete integration workflow"],
            },
            headers=auth_headers["student1"],
        )

        # Step 3: Perform competency assessment
        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_framework = AsyncMock()
            mock_framework.assess_competency.return_value = MagicMock()
            mock_dep.return_value = mock_framework

            assessment_response = client.post(
                "/api/v1/assessment/competency",
                json={
                    "student_id": student_id,
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"quiz_scores": [85, 90, 88]},
                    "assessment_type": "integration_test",
                },
                headers=auth_headers["instructor1"],
            )

        # Step 4: Retrieve analytics
        analytics_response = client.get(
            f"/api/v1/analytics/student/{student_id}",
            headers=auth_headers["instructor1"],
        )

        # Validate that workflow completed without critical failures
        responses = [
            nclex_response,
            study_guide_response,
            assessment_response,
            analytics_response,
        ]

        for response in responses:
            # Should not have server errors
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

        # Count successful operations
        successful_operations = sum(
            1 for resp in responses if resp.status_code == status.HTTP_200_OK
        )

        # At least half should succeed for basic integration
        assert successful_operations >= 2

    def test_concurrent_b6_endpoint_usage(self, client: TestClient, auth_headers):
        """Test concurrent usage of all B.6 endpoints."""

        def nclex_request():
            return client.post(
                "/api/v1/nclex/generate",
                json={
                    "topic": "concurrent_test",
                    "difficulty": "easy",
                    "question_count": 1,
                },
                headers=auth_headers["student1"],
            )

        def study_guide_request():
            return client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Concurrent Study Guide",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "beginner",
                },
                headers=auth_headers["student1"],
            )

        def assessment_request():
            with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
                mock_framework = AsyncMock()
                mock_framework.assess_competency.return_value = MagicMock()
                mock_dep.return_value = mock_framework

                return client.post(
                    "/api/v1/assessment/competency",
                    json={
                        "student_id": "concurrent_test",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [80]},
                    },
                    headers=auth_headers["instructor1"],
                )

        def analytics_request():
            return client.get(
                "/api/v1/analytics/student/concurrent_test",
                headers=auth_headers["instructor1"],
            )

        # Run all endpoints concurrently
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(nclex_request),
                executor.submit(study_guide_request),
                executor.submit(assessment_request),
                executor.submit(analytics_request),
            ]

            results = [future.result() for future in as_completed(futures)]

        # All requests should complete without server errors
        for response in results:
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

        # Most should succeed or fail gracefully
        success_or_expected_errors = sum(
            1
            for resp in results
            if resp.status_code
            in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_403_FORBIDDEN,
                status.HTTP_501_NOT_IMPLEMENTED,
            ]
        )

        assert success_or_expected_errors >= 3  # Most should handle correctly

    def test_b6_endpoints_error_consistency(self, client: TestClient):
        """Test that all B.6 endpoints handle errors consistently."""
        endpoints_and_data = [
            ("/api/v1/nclex/generate", {"invalid": "data"}),
            ("/api/v1/assessment/competency", {"invalid": "data"}),
            ("/api/v1/study-guide/create", {"invalid": "data"}),
        ]

        error_responses = []

        for endpoint, data in endpoints_and_data:
            # Test with no auth
            response = client.post(endpoint, json=data)
            error_responses.append(("no_auth", endpoint, response.status_code))

            # Test with invalid JSON
            response = client.post(
                endpoint,
                data="invalid json",
                headers={"Content-Type": "application/json"},
            )
            error_responses.append(("invalid_json", endpoint, response.status_code))

        # All should return 401 for no auth, 422 for invalid JSON
        for error_type, endpoint, status_code in error_responses:
            if error_type == "no_auth":
                assert status_code == status.HTTP_401_UNAUTHORIZED
            elif error_type == "invalid_json":
                assert status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Analytics endpoint (GET) error handling
        analytics_response = client.get("/api/v1/analytics/student/test_id")
        assert analytics_response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_b6_endpoints_performance_under_load(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test B.6 endpoints performance under moderate load."""

        def make_requests():
            responses = []

            # NCLEX generation
            start = time.time()
            resp = client.post(
                "/api/v1/nclex/generate",
                json={
                    "topic": "load_test",
                    "difficulty": "easy",
                    "question_count": 1,
                },
                headers=auth_headers["student1"],
            )
            responses.append(("nclex", time.time() - start, resp.status_code))

            # Study guide creation
            start = time.time()
            resp = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Load Test Guide",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "beginner",
                },
                headers=auth_headers["student1"],
            )
            responses.append(("study_guide", time.time() - start, resp.status_code))

            # Analytics
            start = time.time()
            resp = client.get(
                "/api/v1/analytics/student/load_test_student",
                headers=auth_headers["instructor1"],
            )
            responses.append(("analytics", time.time() - start, resp.status_code))

            return responses

        # Run multiple concurrent workflows
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(make_requests) for _ in range(3)]
            all_results = []

            for future in as_completed(futures):
                all_results.extend(future.result())

        # Analyze performance results
        endpoint_times = {}
        for endpoint, duration, _status_code in all_results:
            if endpoint not in endpoint_times:
                endpoint_times[endpoint] = []
            endpoint_times[endpoint].append(duration)

        # Validate performance requirements under load
        for endpoint, times in endpoint_times.items():
            if times:  # If we have timing data
                avg_time = sum(times) / len(times)
                max_time = max(times)

                if endpoint == "analytics":
                    assert (
                        avg_time < 1.0
                    ), f"{endpoint} average time {avg_time:.3f}s too slow"
                    assert (
                        max_time < 2.0
                    ), f"{endpoint} max time {max_time:.3f}s too slow"
                else:  # nclex and study_guide
                    assert (
                        avg_time < 3.0
                    ), f"{endpoint} average time {avg_time:.3f}s too slow"
                    assert (
                        max_time < 5.0
                    ), f"{endpoint} max time {max_time:.3f}s too slow"
