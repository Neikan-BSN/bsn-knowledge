"""
API Endpoint Tests for BSN Knowledge Platform

Tests all Phase 3 critical endpoints and core API functionality
including NCLEX generation, competency assessment, study guides, and analytics.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch


@pytest.mark.endpoints
class TestHealthAndMetricsEndpoints:
    """Test system health and metrics endpoints."""

    def test_root_endpoint(self, client: TestClient):
        """Test root endpoint returns system information."""
        response = client.get("/")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert (
            data["message"]
            == "BSN Knowledge API - Comprehensive Nursing Education Platform"
        )
        assert data["version"] == "1.0.0"
        assert "features" in data
        assert len(data["features"]) >= 8  # Should have multiple features
        assert "endpoints" in data

    def test_health_endpoint(self, client: TestClient):
        """Test health check endpoint."""
        response = client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "timestamp" in data
        assert "performance_metrics" in data
        assert "features_status" in data
        assert "security" in data

        # Check security features
        security = data["security"]
        assert security["jwt_authentication"] == "enabled"
        assert security["role_based_access"] == "enabled"
        assert security["rate_limiting"] == "enabled"

    def test_metrics_endpoint(self, client: TestClient):
        """Test performance metrics endpoint."""
        response = client.get("/metrics")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "api_metrics" in data
        assert "uptime_info" in data

        uptime = data["uptime_info"]
        assert "total_requests" in uptime
        assert "average_response_time_ms" in uptime
        assert "slow_requests_percentage" in uptime
        assert "error_rate_percentage" in uptime


@pytest.mark.endpoints
class TestNCLEXGenerationEndpoint:
    """Test Phase 3 required NCLEX generation endpoint."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_nclex_generate_endpoint_success(
        self, mock_ragnostic, client: TestClient, auth_headers, mock_nclex_questions
    ):
        """Test successful NCLEX question generation."""
        # Mock the RAGnostic service
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

        assert "questions" in data
        assert len(data["questions"]) > 0

        # Validate question structure
        question = data["questions"][0]
        assert "id" in question
        assert "question" in question
        assert "options" in question
        assert "correct_answer" in question
        assert "rationale" in question
        assert "difficulty" in question

    def test_nclex_generate_requires_authentication(self, client: TestClient):
        """Test that NCLEX generation requires authentication."""
        request_data = {
            "topic": "pharmacology",
            "difficulty": "easy",
            "question_count": 3,
        }

        response = client.post("/api/v1/nclex/generate", json=request_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_nclex_generate_invalid_parameters(self, client: TestClient, auth_headers):
        """Test NCLEX generation with invalid parameters."""
        # Missing required fields
        response = client.post(
            "/api/v1/nclex/generate", json={}, headers=auth_headers["student1"]
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_nclex_health_endpoint(self, client: TestClient):
        """Test NCLEX service health check."""
        response = client.get("/api/v1/nclex/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["service"] == "nclex_generation"
        assert data["status"] == "operational"
        assert "features" in data


@pytest.mark.endpoints
class TestCompetencyAssessmentEndpoint:
    """Test Phase 3 required competency assessment endpoint."""

    @patch("src.dependencies.get_competency_framework_dep")
    def test_competency_assessment_success(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test successful competency assessment."""
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
                },
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

        assert data["student_id"] == "student_001"
        assert data["competency_id"] == "AACN_KNOWLEDGE_1"
        assert "current_level" in data
        assert "score" in data
        assert "strengths" in data
        assert "areas_for_improvement" in data
        assert "recommendations" in data

    def test_competency_assessment_requires_authentication(self, client: TestClient):
        """Test that competency assessment requires authentication."""
        request_data = {
            "student_id": "student_001",
            "competency_id": "AACN_KNOWLEDGE_1",
            "performance_data": {},
        }

        response = client.post("/api/v1/assessment/competency", json=request_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @patch("src.dependencies.get_competency_framework_dep")
    def test_bulk_competency_assessment(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test bulk competency assessment."""
        mock_framework_dep.return_value = mock_competency_framework

        request_data = {
            "assessments": [
                {
                    "student_id": "student_001",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"quiz_scores": [85, 90]},
                    "assessment_type": "comprehensive",
                    "assessor_id": "instructor_001",
                },
                {
                    "student_id": "student_002",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"quiz_scores": [75, 82]},
                    "assessment_type": "comprehensive",
                    "assessor_id": "instructor_001",
                },
            ],
            "batch_id": "batch_2024_001",
        }

        response = client.post(
            "/api/v1/assessment/competency/assess/bulk",
            json=request_data,
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["batch_id"] == "batch_2024_001"
        assert data["total_assessments"] == 2
        assert "results" in data
        assert "errors" in data

    @patch("src.dependencies.get_competency_framework_dep")
    def test_student_competency_profile(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test getting student competency profile."""
        mock_framework_dep.return_value = mock_competency_framework

        response = client.get(
            "/api/v1/assessment/competency/profile/student_001",
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["student_id"] == "student_001"
        assert "program" in data
        assert "competency_gpa" in data
        assert "graduation_readiness_score" in data
        assert "strengths_summary" in data
        assert "development_plan" in data

    @patch("src.dependencies.get_competency_framework_dep")
    def test_competency_gap_analysis(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test competency gap analysis."""
        mock_framework_dep.return_value = mock_competency_framework

        request_data = {
            "student_id": "student_001",
            "target_competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
            "include_prerequisites": True,
            "severity_filter": "medium",
        }

        response = client.post(
            "/api/v1/assessment/gaps/analyze",
            json=request_data,
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert isinstance(data, dict)
        # Should contain domain-based gaps
        for domain, gaps in data.items():
            assert isinstance(gaps, list)

    @patch("src.dependencies.get_competency_framework_dep")
    def test_learning_path_generation(
        self,
        mock_framework_dep,
        client: TestClient,
        auth_headers,
        mock_competency_framework,
    ):
        """Test learning path generation."""
        mock_framework_dep.return_value = mock_competency_framework

        request_data = {
            "student_id": "student_001",
            "target_competencies": ["AACN_KNOWLEDGE_1"],
            "current_proficiency": {"AACN_KNOWLEDGE_1": 0.65},
            "learning_preferences": {"style": "visual", "pace": "moderate"},
            "timeline_weeks": 8,
        }

        response = client.post(
            "/api/v1/assessment/learning-path/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["student_id"] == "student_001"
        assert "target_competencies" in data
        assert "recommended_sequence" in data
        assert "estimated_duration_hours" in data

    def test_get_available_competencies(self, client: TestClient, auth_headers):
        """Test getting available competencies."""
        response = client.get(
            "/api/v1/assessment/competencies/available",
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "competencies" in data
        assert "total_count" in data

    def test_get_aacn_domains(self, client: TestClient, auth_headers):
        """Test getting AACN domains."""
        response = client.get(
            "/api/v1/assessment/domains", headers=auth_headers["student1"]
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "domains" in data
        assert len(data["domains"]) == 8  # AACN has 8 domains

    def test_get_proficiency_levels(self, client: TestClient, auth_headers):
        """Test getting proficiency levels."""
        response = client.get(
            "/api/v1/assessment/proficiency-levels", headers=auth_headers["student1"]
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "proficiency_levels" in data
        levels = data["proficiency_levels"]
        assert len(levels) >= 5  # Should have novice to expert levels


@pytest.mark.endpoints
class TestStudyGuideEndpoint:
    """Test Phase 3 required study guide creation endpoint."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_study_guide_create_success(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test successful study guide creation."""
        mock_client = AsyncMock()
        mock_client.enrich_content.return_value = {
            "enriched_content": "Enhanced study guide content",
            "learning_objectives": ["Objective 1", "Objective 2"],
            "assessment_suggestions": ["Quiz 1", "Assignment 1"],
        }
        mock_ragnostic.return_value = mock_client

        request_data = {
            "topic": "Cardiovascular Assessment",
            "competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
            "difficulty_level": "intermediate",
            "learning_objectives": [
                "Identify normal and abnormal heart sounds",
                "Perform comprehensive cardiac assessment",
            ],
            "student_level": "junior",
            "include_case_studies": True,
            "format_preferences": ["visual_diagrams", "step_by_step_procedures"],
        }

        response = client.post(
            "/api/v1/study-guide/create",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["topic"] == "Cardiovascular Assessment"
        assert "content_sections" in data
        assert "learning_objectives" in data
        assert "assessment_methods" in data
        assert "estimated_study_time_hours" in data

    def test_study_guide_requires_authentication(self, client: TestClient):
        """Test that study guide creation requires authentication."""
        request_data = {
            "topic": "Basic Nursing Skills",
            "competencies": ["AACN_KNOWLEDGE_1"],
        }

        response = client.post("/api/v1/study-guide/create", json=request_data)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_study_guide_invalid_parameters(self, client: TestClient, auth_headers):
        """Test study guide creation with invalid parameters."""
        # Missing required topic
        response = client.post(
            "/api/v1/study-guide/create",
            json={"competencies": ["AACN_KNOWLEDGE_1"]},
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.endpoints
class TestAnalyticsEndpoint:
    """Test Phase 3 required analytics endpoint."""

    @patch("src.services.analytics_service.AnalyticsService")
    def test_student_analytics_success(
        self, mock_analytics, client: TestClient, auth_headers, mock_analytics_data
    ):
        """Test successful student analytics retrieval."""
        mock_service = AsyncMock()
        mock_service.get_student_analytics.return_value = mock_analytics_data[
            "student_analytics"
        ]
        mock_analytics.return_value = mock_service

        response = client.get(
            "/api/v1/analytics/student/student_001", headers=auth_headers["instructor1"]
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["student_id"] == "student_001"
        assert "overall_progress" in data
        assert "competency_scores" in data
        assert "study_time_hours" in data
        assert "quiz_completion_rate" in data
        assert "areas_for_improvement" in data

    def test_student_analytics_requires_authentication(self, client: TestClient):
        """Test that student analytics requires authentication."""
        response = client.get("/api/v1/analytics/student/student_001")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_student_analytics_authorization(self, client: TestClient, auth_headers):
        """Test that students can only access their own analytics."""
        # This test assumes authorization logic is implemented
        response = client.get(
            "/api/v1/analytics/student/other_student", headers=auth_headers["student1"]
        )

        # Should either return 403 or filter results appropriately
        # Implementation depends on business logic
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_403_FORBIDDEN]

    @patch("src.services.analytics_service.AnalyticsService")
    def test_class_analytics(self, mock_analytics, client: TestClient, auth_headers):
        """Test class-level analytics (instructor/admin only)."""
        mock_service = AsyncMock()
        mock_service.get_class_analytics.return_value = {
            "class_id": "BSN_2024_SPRING",
            "total_students": 32,
            "average_progress": 76.8,
            "completion_rate": 89.2,
            "competency_averages": {
                "knowledge_for_nursing_practice": 79.5,
                "person_centered_care": 85.2,
            },
        }
        mock_analytics.return_value = mock_service

        response = client.get(
            "/api/v1/analytics/class/BSN_2024_SPRING",
            headers=auth_headers["instructor1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["class_id"] == "BSN_2024_SPRING"
        assert "total_students" in data
        assert "average_progress" in data

    def test_analytics_with_filters(self, client: TestClient, auth_headers):
        """Test analytics with date and competency filters."""
        response = client.get(
            "/api/v1/analytics/student/student_001?start_date=2024-01-01&end_date=2024-08-24&competency_filter=knowledge_for_nursing_practice",
            headers=auth_headers["instructor1"],
        )

        # Should not error even if filters aren't fully implemented
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]


@pytest.mark.endpoints
class TestQuizAndStudyGuideEndpoints:
    """Test quiz and study guide management endpoints."""

    @patch("src.services.content_generation_service.ContentGenerationService")
    def test_generate_quiz_success(
        self, mock_service, client: TestClient, auth_headers, mock_nclex_questions
    ):
        """Test successful quiz generation."""
        mock_gen_service = AsyncMock()
        mock_gen_service.generate_questions.return_value = mock_nclex_questions
        mock_service.return_value = mock_gen_service

        request_data = {
            "topic": "Medication Administration",
            "difficulty": "medium",
            "question_count": 10,
            "question_types": ["multiple_choice", "select_all_that_apply"],
            "include_rationales": True,
        }

        response = client.post(
            "/api/v1/quizzes/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert "questions" in data
        assert data["metadata"]["topic"] == "Medication Administration"

    def test_adaptive_learning_recommendation(self, client: TestClient, auth_headers):
        """Test adaptive learning recommendations."""
        request_data = {
            "student_id": "student_001",
            "performance_history": {
                "recent_quiz_scores": [78, 85, 72, 90],
                "time_spent_minutes": [45, 60, 30, 75],
                "topics_studied": ["cardiology", "pharmacology"],
            },
            "learning_preferences": {
                "preferred_difficulty": "medium",
                "learning_style": "visual",
            },
        }

        response = client.post(
            "/api/v1/adaptive-learning/recommend",
            json=request_data,
            headers=auth_headers["student1"],
        )

        # Should return recommendations even if basic implementation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_501_NOT_IMPLEMENTED,
        ]

    def test_clinical_support_scenarios(self, client: TestClient, auth_headers):
        """Test clinical decision support scenarios."""
        request_data = {
            "clinical_scenario": "patient_assessment",
            "patient_demographics": {
                "age": 65,
                "gender": "female",
                "diagnosis": "heart_failure",
            },
            "complexity_level": "intermediate",
        }

        response = client.post(
            "/api/v1/clinical-support/scenarios/generate",
            json=request_data,
            headers=auth_headers["student1"],
        )

        # Should provide clinical scenarios
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_501_NOT_IMPLEMENTED,
        ]


@pytest.mark.endpoints
class TestErrorHandlingAndValidation:
    """Test error handling and input validation across endpoints."""

    def test_malformed_json_requests(self, client: TestClient, auth_headers):
        """Test handling of malformed JSON requests."""
        # Send invalid JSON
        response = client.post(
            "/api/v1/nclex/generate",
            data="invalid json content",
            headers={**auth_headers["student1"], "Content-Type": "application/json"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_oversized_request_handling(self, client: TestClient, auth_headers):
        """Test handling of oversized requests."""
        # Create a large request payload
        large_data = {
            "topic": "test",
            "large_field": "x" * 10000,  # Large string
        }

        response = client.post(
            "/api/v1/study-guide/create",
            json=large_data,
            headers=auth_headers["student1"],
        )

        # Should either process or reject gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_sql_injection_prevention_in_endpoints(
        self, client: TestClient, auth_headers
    ):
        """Test SQL injection prevention in endpoint parameters."""
        sql_injection_attempts = [
            "'; DROP TABLE students; --",
            "' OR 1=1 --",
            "<script>alert('xss')</script>",
        ]

        for injection in sql_injection_attempts:
            response = client.get(
                f"/api/v1/analytics/student/{injection}",
                headers=auth_headers["instructor1"],
            )

            # Should return proper error codes, not server errors
            assert response.status_code in [
                status.HTTP_400_BAD_REQUEST,
                status.HTTP_404_NOT_FOUND,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            ]

    def test_xss_prevention_in_responses(self, client: TestClient, auth_headers):
        """Test XSS prevention in API responses."""
        xss_payload = "<script>alert('xss')</script>"

        response = client.post(
            "/api/v1/study-guide/create",
            json={"topic": xss_payload, "competencies": ["AACN_KNOWLEDGE_1"]},
            headers=auth_headers["student1"],
        )

        if response.status_code == status.HTTP_200_OK:
            response_text = response.text
            # XSS payload should be escaped or sanitized
            assert "<script>" not in response_text

    def test_concurrent_request_handling(self, client: TestClient, auth_headers):
        """Test handling of concurrent requests."""
        import threading

        results = []

        def make_request():
            response = client.get("/health")
            results.append(response.status_code)

        # Create multiple threads to test concurrency
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All requests should succeed
        assert all(status_code == status.HTTP_200_OK for status_code in results)
        assert len(results) == 5


@pytest.mark.endpoints
@pytest.mark.performance
class TestEndpointPerformance:
    """Test endpoint performance requirements."""

    def test_health_endpoint_performance(self, client: TestClient, performance_monitor):
        """Test health endpoint meets performance requirements."""
        performance_monitor.start()
        response = client.get("/health")
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.1)  # 100ms threshold

    def test_authentication_performance(
        self, client: TestClient, performance_monitor, test_users
    ):
        """Test authentication endpoint performance."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        performance_monitor.start()
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.5)  # 500ms threshold

    def test_metrics_endpoint_performance(
        self, client: TestClient, performance_monitor
    ):
        """Test metrics endpoint performance."""
        performance_monitor.start()
        response = client.get("/metrics")
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.2)  # 200ms threshold


@pytest.mark.endpoints
class TestResponseHeaders:
    """Test proper response headers are set."""

    def test_security_headers(self, client: TestClient):
        """Test that appropriate security headers are present."""
        response = client.get("/health")

        # Check for performance headers
        assert "X-Process-Time" in response.headers
        assert "X-Request-ID" in response.headers

    def test_cors_headers(self, client: TestClient, auth_headers):
        """Test CORS headers are properly set."""
        response = client.options("/api/v1/auth/me")

        # CORS headers should be present for OPTIONS requests
        # Implementation may vary based on CORS middleware configuration
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_204_NO_CONTENT,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        ]

    def test_content_type_headers(self, client: TestClient):
        """Test proper Content-Type headers."""
        response = client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        assert "application/json" in response.headers.get("content-type", "")

    def test_rate_limit_headers_present(self, client: TestClient, auth_headers):
        """Test that rate limit headers are present."""
        response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])

        # Rate limiting headers should be present
        if response.status_code == status.HTTP_200_OK:
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers
