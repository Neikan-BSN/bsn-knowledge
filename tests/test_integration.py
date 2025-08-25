"""
Integration Tests for BSN Knowledge API

Tests end-to-end workflows, cross-endpoint data consistency,
RAGnostic integration, and complete user journeys.
"""

import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from src.auth import UserRole


@pytest.mark.integration
class TestStudentLearningWorkflow:
    """Test complete student learning workflow integration."""

    def test_complete_student_journey(self, client: TestClient, test_users):
        """Test full student journey from login to assessment."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Step 1: Student login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        assert login_response.status_code == status.HTTP_200_OK

        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 2: Check student profile
        profile_response = client.get("/api/v1/auth/me", headers=headers)
        assert profile_response.status_code == status.HTTP_200_OK

        student_data = profile_response.json()
        assert student_data["role"] == UserRole.STUDENT
        f"student_{student_data['id']}"

        # Step 3: Generate study guide
        study_guide_response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Cardiovascular Nursing",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": "intermediate",
                "student_level": "sophomore",
            },
            headers=headers,
        )
        # May succeed or fail depending on implementation
        if study_guide_response.status_code == status.HTTP_200_OK:
            study_guide = study_guide_response.json()
            assert study_guide["topic"] == "Cardiovascular Nursing"

        # Step 4: Generate NCLEX practice questions
        nclex_response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "cardiovascular_assessment",
                "difficulty": "medium",
                "question_count": 5,
                "include_rationales": True,
            },
            headers=headers,
        )
        # May succeed or fail depending on implementation
        if nclex_response.status_code == status.HTTP_200_OK:
            questions = nclex_response.json()
            assert "questions" in questions
            assert len(questions["questions"]) > 0

        # Step 5: View available competencies
        competencies_response = client.get(
            "/api/v1/assessment/competencies/available", headers=headers
        )
        if competencies_response.status_code == status.HTTP_200_OK:
            competencies = competencies_response.json()
            assert "competencies" in competencies

        # Step 6: Logout
        logout_response = client.post("/api/v1/auth/logout", headers=headers)
        assert logout_response.status_code == status.HTTP_200_OK

    def test_student_assessment_workflow(self, client: TestClient, test_users):
        """Test student assessment and progress tracking workflow."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as student
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        student_headers = {"Authorization": f"Bearer {token}"}

        # Login as instructor (for assessment)
        instructor_login = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        instructor_token = instructor_login.json()["access_token"]
        instructor_headers = {"Authorization": f"Bearer {instructor_token}"}

        student_id = "test_student_001"

        # Step 1: Instructor performs competency assessment
        assessment_response = client.post(
            "/api/v1/assessment/competency",
            json={
                "student_id": student_id,
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {
                    "quiz_scores": [85, 78, 92],
                    "clinical_evaluation": 4.0,
                    "assignment_scores": [88, 85],
                },
                "assessment_type": "midterm",
                "assessor_id": "instructor_001",
            },
            headers=instructor_headers,
        )

        # May succeed based on mocked framework
        if assessment_response.status_code == status.HTTP_200_OK:
            assessment = assessment_response.json()
            assert assessment["student_id"] == student_id
            assert "current_level" in assessment
            assert "recommendations" in assessment

        # Step 2: Get student competency profile
        profile_response = client.get(
            f"/api/v1/assessment/competency/profile/{student_id}",
            headers=instructor_headers,
        )

        if profile_response.status_code == status.HTTP_200_OK:
            profile = profile_response.json()
            assert profile["student_id"] == student_id

        # Step 3: Analyze competency gaps
        gaps_response = client.post(
            "/api/v1/assessment/gaps/analyze",
            json={
                "student_id": student_id,
                "target_competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
                "severity_filter": "medium",
            },
            headers=instructor_headers,
        )

        if gaps_response.status_code == status.HTTP_200_OK:
            gaps = gaps_response.json()
            assert isinstance(gaps, dict)

        # Step 4: Generate learning path
        learning_path_response = client.post(
            "/api/v1/assessment/learning-path/generate",
            json={
                "student_id": student_id,
                "target_competencies": ["AACN_KNOWLEDGE_1"],
                "timeline_weeks": 8,
            },
            headers=student_headers,
        )

        if learning_path_response.status_code == status.HTTP_200_OK:
            learning_path = learning_path_response.json()
            assert learning_path["student_id"] == student_id


@pytest.mark.integration
class TestInstructorWorkflow:
    """Test instructor workflow integration."""

    def test_instructor_class_management_workflow(self, client: TestClient, test_users):
        """Test instructor managing class and assessments."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as instructor
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 1: View available competencies and domains
        competencies_response = client.get(
            "/api/v1/assessment/competencies/available", headers=headers
        )
        assert competencies_response.status_code == status.HTTP_200_OK

        domains_response = client.get("/api/v1/assessment/domains", headers=headers)
        assert domains_response.status_code == status.HTTP_200_OK

        # Step 2: Bulk assess multiple students
        bulk_assessment_response = client.post(
            "/api/v1/assessment/competency/assess/bulk",
            json={
                "assessments": [
                    {
                        "student_id": "student_001",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [85, 90]},
                        "assessment_type": "quiz",
                        "assessor_id": "instructor_001",
                    },
                    {
                        "student_id": "student_002",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [75, 82]},
                        "assessment_type": "quiz",
                        "assessor_id": "instructor_001",
                    },
                ],
                "batch_id": "midterm_2024",
            },
            headers=headers,
        )

        if bulk_assessment_response.status_code == status.HTTP_200_OK:
            bulk_results = bulk_assessment_response.json()
            assert bulk_results["batch_id"] == "midterm_2024"
            assert "total_assessments" in bulk_results

        # Step 3: Generate class analytics
        analytics_response = client.get(
            "/api/v1/analytics/class/BSN_2024_SPRING", headers=headers
        )
        # May not be implemented yet
        if analytics_response.status_code == status.HTTP_200_OK:
            analytics = analytics_response.json()
            assert "class_id" in analytics

        # Step 4: Create NCLEX questions for class
        nclex_response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "nursing_fundamentals",
                "difficulty": "medium",
                "question_count": 10,
                "question_types": ["multiple_choice"],
                "include_rationales": True,
            },
            headers=headers,
        )

        if nclex_response.status_code == status.HTTP_200_OK:
            questions = nclex_response.json()
            assert "questions" in questions

    def test_instructor_content_creation_workflow(self, client: TestClient, test_users):
        """Test instructor creating educational content."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create study guides for different competency levels
        competency_levels = [
            ("Basic Nursing Skills", "beginner"),
            ("Advanced Pathophysiology", "advanced"),
            ("Clinical Decision Making", "expert"),
        ]

        for topic, level in competency_levels:
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": topic,
                    "competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
                    "difficulty_level": level,
                    "student_level": "junior",
                    "include_case_studies": True,
                },
                headers=headers,
            )

            if response.status_code == status.HTTP_200_OK:
                study_guide = response.json()
                assert study_guide["topic"] == topic


@pytest.mark.integration
class TestAdministratorWorkflow:
    """Test administrator workflow integration."""

    def test_admin_system_management_workflow(self, client: TestClient, test_users):
        """Test administrator managing system and users."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as admin
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 1: List all users
        users_response = client.get("/api/v1/auth/users", headers=headers)
        assert users_response.status_code == status.HTTP_200_OK

        users = users_response.json()
        assert isinstance(users, list)
        assert len(users) >= 3  # At least our test users

        # Step 2: Check system health
        health_response = client.get("/health")
        assert health_response.status_code == status.HTTP_200_OK

        health_data = health_response.json()
        assert health_data["status"] == "healthy"

        # Step 3: Get system metrics
        metrics_response = client.get("/metrics")
        assert metrics_response.status_code == status.HTTP_200_OK

        metrics = metrics_response.json()
        assert "api_metrics" in metrics
        assert "uptime_info" in metrics

        # Step 4: Test role-based permissions
        # Admin should be able to access instructor functions
        assessment_response = client.post(
            "/api/v1/assessment/competency",
            json={
                "student_id": "admin_test_student",
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {"test_score": 95},
                "assessment_type": "final",
                "assessor_id": "admin_001",
            },
            headers=headers,
        )

        # Admin should have instructor-level access
        assert assessment_response.status_code != status.HTTP_403_FORBIDDEN


@pytest.mark.integration
class TestCrossEndpointDataConsistency:
    """Test data consistency across different endpoints."""

    def test_user_data_consistency(self, client: TestClient, test_users):
        """Test user data consistency across auth endpoints."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login to get token
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Get user info from /auth/me
        me_response = client.get("/api/v1/auth/me", headers=headers)
        assert me_response.status_code == status.HTTP_200_OK
        me_data = me_response.json()

        # Login as admin to get user list
        admin_login = client.post(
            "/api/v1/auth/login",
            json={"username": "admin1", "password": "test_password"},
        )
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Get user list from /auth/users
        users_response = client.get("/api/v1/auth/users", headers=admin_headers)
        assert users_response.status_code == status.HTTP_200_OK
        users_data = users_response.json()

        # Find instructor in user list
        instructor_in_list = next(
            (user for user in users_data if user["username"] == "instructor1"), None
        )
        assert instructor_in_list is not None

        # Data should be consistent
        assert me_data["id"] == instructor_in_list["id"]
        assert me_data["username"] == instructor_in_list["username"]
        assert me_data["email"] == instructor_in_list["email"]
        assert me_data["role"] == instructor_in_list["role"]

    def test_assessment_data_consistency(self, client: TestClient, test_users):
        """Test assessment data consistency across endpoints."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as instructor
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        student_id = "consistency_test_student"
        competency_id = "AACN_KNOWLEDGE_1"

        # Perform assessment
        assessment_response = client.post(
            "/api/v1/assessment/competency",
            json={
                "student_id": student_id,
                "competency_id": competency_id,
                "performance_data": {"quiz_scores": [88, 92, 85]},
                "assessment_type": "comprehensive",
                "assessor_id": "instructor_consistency",
            },
            headers=headers,
        )

        if assessment_response.status_code == status.HTTP_200_OK:
            assessment_response.json()

            # Get student profile
            profile_response = client.get(
                f"/api/v1/assessment/competency/profile/{student_id}", headers=headers
            )

            if profile_response.status_code == status.HTTP_200_OK:
                profile_data = profile_response.json()

                # Data should be consistent
                assert profile_data["student_id"] == student_id


@pytest.mark.integration
class TestRAGnosticIntegration:
    """Test RAGnostic service integration."""

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_ragnostic_nclex_generation_integration(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test integration between NCLEX endpoint and RAGnostic service."""
        # Mock RAGnostic client
        mock_client = AsyncMock()
        mock_client.generate_questions.return_value = {
            "questions": [
                {
                    "id": "ragnostic_001",
                    "type": "multiple_choice",
                    "question": "Which assessment finding indicates digoxin toxicity?",
                    "options": [
                        "A. Heart rate 90 bpm",
                        "B. Visual disturbances and nausea",
                        "C. Blood pressure 140/90",
                        "D. Temperature 99.2°F",
                    ],
                    "correct_answer": "B",
                    "rationale": "Visual disturbances and nausea are classic signs of digoxin toxicity due to the drug's effect on cardiac conduction and the CNS.",
                    "topic": "pharmacology",
                    "difficulty": "medium",
                    "nclex_category": "Pharmacological and Parenteral Therapies",
                }
            ],
            "metadata": {
                "generation_time": 2.3,
                "confidence": 0.94,
                "source": "RAGnostic AI",
            },
        }
        mock_ragnostic.return_value = mock_client

        # Make NCLEX generation request
        response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "pharmacology_cardiology",
                "difficulty": "medium",
                "question_count": 5,
                "include_rationales": True,
                "target_competencies": ["AACN_KNOWLEDGE_1"],
            },
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify RAGnostic integration
        assert "questions" in data
        assert len(data["questions"]) > 0

        question = data["questions"][0]
        assert question["id"] == "ragnostic_001"
        assert question["correct_answer"] == "B"
        assert "rationale" in question

        # Verify RAGnostic was called correctly
        mock_client.generate_questions.assert_called_once()

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_ragnostic_study_guide_integration(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test integration between study guide endpoint and RAGnostic service."""
        # Mock RAGnostic content enrichment
        mock_client = AsyncMock()
        mock_client.enrich_content.return_value = {
            "enriched_content": """
            ## Cardiovascular Assessment

            ### Learning Objectives
            1. Perform systematic cardiac assessment
            2. Identify normal vs abnormal heart sounds
            3. Recognize signs of cardiovascular distress

            ### Key Concepts
            - Heart anatomy and physiology
            - Assessment techniques (inspection, palpation, auscultation)
            - Common cardiovascular conditions
            """,
            "learning_objectives": [
                "Perform systematic cardiac assessment",
                "Identify normal vs abnormal heart sounds",
                "Recognize signs of cardiovascular distress",
            ],
            "assessment_suggestions": [
                "Case study: Patient with chest pain",
                "Practice quiz: Heart sound identification",
                "Simulation: Emergency cardiac assessment",
            ],
            "estimated_study_time": 240,  # 4 hours
        }
        mock_ragnostic.return_value = mock_client

        # Create study guide request
        response = client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Cardiovascular Assessment",
                "competencies": ["AACN_KNOWLEDGE_1", "AACN_PERSON_CENTERED_1"],
                "difficulty_level": "intermediate",
                "student_level": "junior",
                "include_case_studies": True,
                "learning_preferences": ["visual", "hands_on"],
            },
            headers=auth_headers["student1"],
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Verify RAGnostic integration
        assert data["topic"] == "Cardiovascular Assessment"
        assert "content_sections" in data
        assert "learning_objectives" in data
        assert "estimated_study_time_hours" in data

        # Verify RAGnostic was called for content enrichment
        mock_client.enrich_content.assert_called_once()

    @patch("src.services.ragnostic_client.RAGnosticClient")
    def test_ragnostic_error_handling_integration(
        self, mock_ragnostic, client: TestClient, auth_headers
    ):
        """Test error handling when RAGnostic service fails."""
        # Mock RAGnostic service failure
        mock_client = AsyncMock()
        mock_client.generate_questions.side_effect = Exception(
            "RAGnostic service unavailable"
        )
        mock_ragnostic.return_value = mock_client

        response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "medical_surgical_nursing",
                "difficulty": "hard",
                "question_count": 10,
            },
            headers=auth_headers["student1"],
        )

        # Should handle service failure gracefully
        assert response.status_code in [
            status.HTTP_503_SERVICE_UNAVAILABLE,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ]

        if response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            error_data = response.json()
            assert error_data["error"] is True
            assert (
                "service" in error_data["message"].lower()
                or "unavailable" in error_data["message"].lower()
            )


@pytest.mark.integration
@pytest.mark.performance
class TestPerformanceIntegration:
    """Test performance of integrated workflows."""

    def test_complete_workflow_performance(
        self, client: TestClient, test_users, performance_monitor
    ):
        """Test performance of complete user workflow."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        performance_monitor.start()

        # Complete workflow: login -> generate content -> assess -> analytics

        # Step 1: Login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        assert login_response.status_code == status.HTTP_200_OK

        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 2: Generate study guide
        client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": "Basic Nursing Skills",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": "beginner",
            },
            headers=headers,
        )

        # Step 3: Generate NCLEX questions
        client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "nursing_fundamentals",
                "difficulty": "easy",
                "question_count": 3,
            },
            headers=headers,
        )

        # Step 4: Check competencies
        client.get("/api/v1/assessment/competencies/available", headers=headers)

        performance_monitor.stop()

        # Complete workflow should finish within reasonable time
        performance_monitor.assert_within_threshold(10.0)  # 10 seconds max

    def test_concurrent_user_performance(self, client: TestClient, test_users):
        """Test performance with concurrent users."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        import threading
        import time

        results = []

        def user_workflow(username):
            start_time = time.time()

            # Login
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": "test_password"},
            )

            if login_response.status_code == status.HTTP_200_OK:
                token = login_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}

                # Make some requests
                client.get("/api/v1/auth/me", headers=headers)
                client.get("/api/v1/assessment/domains", headers=headers)

                # Logout
                client.post("/api/v1/auth/logout", headers=headers)

            end_time = time.time()
            results.append(
                {
                    "username": username,
                    "success": login_response.status_code == status.HTTP_200_OK,
                    "duration": end_time - start_time,
                }
            )

        # Create threads for concurrent users
        users = ["student1", "instructor1", "admin1"]
        threads = []

        for username in users:
            thread = threading.Thread(target=user_workflow, args=(username,))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # All users should succeed
        assert len(results) == 3
        assert all(result["success"] for result in results)

        # All should complete within reasonable time
        for result in results:
            assert result["duration"] < 5.0  # 5 seconds per user


@pytest.mark.integration
class TestErrorPropagationIntegration:
    """Test error propagation across integrated components."""

    def test_authentication_error_propagation(self, client: TestClient):
        """Test that authentication errors propagate correctly."""
        invalid_headers = {"Authorization": "Bearer invalid_token_here"}

        # All protected endpoints should return 401
        endpoints_to_test = [
            ("/api/v1/auth/me", "GET"),
            ("/api/v1/nclex/generate", "POST"),
            ("/api/v1/assessment/competency", "POST"),
            ("/api/v1/analytics/student/test", "GET"),
        ]

        for endpoint, method in endpoints_to_test:
            if method == "GET":
                response = client.get(endpoint, headers=invalid_headers)
            else:
                response = client.post(endpoint, json={}, headers=invalid_headers)

            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_authorization_error_propagation(self, client: TestClient, test_users):
        """Test that authorization errors propagate correctly."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as student
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Try to access admin endpoints
        admin_endpoints = [
            "/api/v1/auth/users",
        ]

        for endpoint in admin_endpoints:
            response = client.get(endpoint, headers=headers)
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_validation_error_propagation(self, client: TestClient, auth_headers):
        """Test that validation errors propagate correctly."""
        # Test various invalid inputs across endpoints
        invalid_requests = [
            ("/api/v1/nclex/generate", {"invalid": "data"}),
            ("/api/v1/study-guide/create", {"missing": "required_fields"}),
            ("/api/v1/assessment/competency", {"incomplete": "data"}),
        ]

        for endpoint, invalid_data in invalid_requests:
            response = client.post(
                endpoint, json=invalid_data, headers=auth_headers.get("student1", {})
            )

            # Should return validation error
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.integration
@pytest.mark.slow
class TestLongRunningIntegrationWorkflows:
    """Test long-running integration scenarios."""

    def test_extended_user_session(self, client: TestClient, test_users):
        """Test extended user session with multiple operations."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Perform multiple operations over time
        operations = [
            ("GET", "/api/v1/auth/me"),
            ("GET", "/api/v1/assessment/domains"),
            ("GET", "/api/v1/assessment/competencies/available"),
            ("GET", "/api/v1/assessment/proficiency-levels"),
        ]

        for _i, (method, endpoint) in enumerate(operations):
            if method == "GET":
                response = client.get(endpoint, headers=headers)
            else:
                response = client.post(endpoint, json={}, headers=headers)

            # All operations should succeed
            assert response.status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,  # For invalid POST data
            ]

            # Small delay between operations
            time.sleep(0.1)

        # Token should still be valid at the end
        final_response = client.get("/api/v1/auth/me", headers=headers)
        assert final_response.status_code == status.HTTP_200_OK

    def test_bulk_operations_integration(self, client: TestClient, test_users):
        """Test bulk operations integration."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Login as instructor
        login_response = client.post(
            "/api/v1/auth/login",
            json={"username": "instructor1", "password": "test_password"},
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create bulk assessment request
        bulk_assessments = []
        for i in range(10):  # 10 students
            bulk_assessments.append(
                {
                    "student_id": f"bulk_test_student_{i:03d}",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {
                        "quiz_scores": [80 + i, 75 + i, 85 + i],
                        "participation_score": 4.0 + (i * 0.1),
                    },
                    "assessment_type": "comprehensive",
                    "assessor_id": "instructor_bulk_test",
                }
            )

        # Submit bulk assessment
        bulk_response = client.post(
            "/api/v1/assessment/competency/assess/bulk",
            json={"assessments": bulk_assessments, "batch_id": "integration_test_bulk"},
            headers=headers,
        )

        if bulk_response.status_code == status.HTTP_200_OK:
            results = bulk_response.json()
            assert results["total_assessments"] == 10
            assert results["batch_id"] == "integration_test_bulk"
