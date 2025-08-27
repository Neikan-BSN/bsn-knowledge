"""
Test helper utilities for BSN Knowledge API tests.

Provides common test utilities, validation helpers, and test data generators.
"""

import random
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from src.auth import UserInDB, UserRole, create_auth_tokens
from src.models.assessment_models import AACNDomain, CompetencyProficiencyLevel


class TestDataGenerator:
    """Generates realistic test data for nursing education scenarios."""

    @staticmethod
    def generate_student_id(prefix: str = "STU", year: int = None) -> str:
        """Generate a realistic student ID."""
        if year is None:
            year = datetime.now().year

        random_num = random.randint(1000, 9999)
        return f"{prefix}{year}{random_num}"

    @staticmethod
    def generate_competency_id(domain: AACNDomain | None = None) -> str:
        """Generate a realistic competency ID."""
        if domain is None:
            domain = random.choice(list(AACNDomain))

        domain_prefix = domain.value.upper().replace("_", "")[:8]
        number = random.randint(1, 99)
        return f"AACN_{domain_prefix}_{number:02d}"

    @staticmethod
    def generate_quiz_scores(
        count: int = 5, min_score: int = 60, max_score: int = 100
    ) -> list[int]:
        """Generate realistic quiz scores."""
        return [random.randint(min_score, max_score) for _ in range(count)]

    @staticmethod
    def generate_clinical_evaluation() -> dict[str, float]:
        """Generate realistic clinical evaluation scores."""
        categories = [
            "communication",
            "clinical_reasoning",
            "technical_skills",
            "professionalism",
            "critical_thinking",
            "patient_safety",
        ]

        return {
            category: round(random.uniform(3.0, 5.0), 1)
            for category in random.sample(categories, k=random.randint(3, 6))
        }

    @staticmethod
    def generate_nursing_topic() -> str:
        """Generate a realistic nursing topic."""
        topics = [
            "Cardiovascular Assessment",
            "Respiratory Care Management",
            "Medication Administration Safety",
            "Infection Prevention Control",
            "Patient Communication Skills",
            "Wound Care Techniques",
            "Vital Signs Monitoring",
            "Pain Management Strategies",
            "Mental Health Nursing",
            "Pediatric Care Principles",
            "Geriatric Assessment",
            "Emergency Response Procedures",
            "Surgical Preparation",
            "Discharge Planning",
            "Health Education Delivery",
            "Cultural Competency",
        ]
        return random.choice(topics)

    @staticmethod
    def generate_nclex_question(
        topic: str = None, difficulty: str = "medium"
    ) -> dict[str, Any]:
        """Generate a realistic NCLEX-style question."""
        if topic is None:
            topic = TestDataGenerator.generate_nursing_topic()

        question_templates = {
            "easy": [
                "What is the normal range for {vital_sign}?",
                "Which of the following is a sign of {condition}?",
                "When should a nurse {action}?",
            ],
            "medium": [
                "A patient presents with {symptoms}. What is the priority nursing intervention?",
                "Which assessment finding would indicate {condition} in a patient receiving {treatment}?",
                "A nurse is caring for a patient with {diagnosis}. Which action should be taken first?",
            ],
            "hard": [
                "A patient with {primary_diagnosis} develops {complication}. Which intervention has the highest priority?",
                "The nurse is evaluating multiple patients. Which patient should be assessed first?",
                "A patient's condition changes during {procedure}. What is the most appropriate response?",
            ],
        }

        templates = question_templates.get(difficulty, question_templates["medium"])
        template = random.choice(templates)

        # Simple template filling (in real implementation, would use more sophisticated NLP)
        question_text = template.replace("{vital_sign}", "heart rate")
        question_text = question_text.replace("{condition}", "infection")
        question_text = question_text.replace("{action}", "wash hands")
        question_text = question_text.replace(
            "{symptoms}", "chest pain and shortness of breath"
        )
        question_text = question_text.replace("{treatment}", "antibiotic therapy")
        question_text = question_text.replace("{diagnosis}", "pneumonia")
        question_text = question_text.replace(
            "{primary_diagnosis}", "diabetes mellitus"
        )
        question_text = question_text.replace("{complication}", "hypoglycemia")
        question_text = question_text.replace(
            "{procedure}", "medication administration"
        )

        options = [
            "A. Monitor vital signs every 4 hours",
            "B. Administer prescribed medication",
            "C. Notify the healthcare provider immediately",
            "D. Document findings in patient record",
        ]

        correct_answer = random.choice(["A", "B", "C", "D"])

        rationales = {
            "A": "Monitoring vital signs helps track patient condition changes.",
            "B": "Prescribed medications help treat the underlying condition.",
            "C": "Healthcare provider notification ensures appropriate medical response.",
            "D": "Documentation ensures continuity of care and legal compliance.",
        }

        return {
            "id": f"test_q_{int(time.time())}_{random.randint(1000, 9999)}",
            "type": "multiple_choice",
            "question": question_text,
            "options": options,
            "correct_answer": correct_answer,
            "rationale": rationales[correct_answer],
            "topic": topic,
            "difficulty": difficulty,
            "nclex_category": random.choice(
                [
                    "Safe and Effective Care Environment",
                    "Health Promotion and Maintenance",
                    "Psychosocial Integrity",
                    "Physiological Integrity",
                ]
            ),
        }

    @staticmethod
    def generate_performance_data(student_level: str = "junior") -> dict[str, Any]:
        """Generate realistic student performance data."""
        base_scores = {
            "freshman": (65, 80),
            "sophomore": (70, 85),
            "junior": (75, 90),
            "senior": (80, 95),
        }

        min_score, max_score = base_scores.get(student_level, (70, 85))

        return {
            "quiz_scores": TestDataGenerator.generate_quiz_scores(
                count=random.randint(3, 8), min_score=min_score, max_score=max_score
            ),
            "clinical_evaluations": TestDataGenerator.generate_clinical_evaluation(),
            "simulation_scores": {
                f"scenario_{i}": random.randint(min_score, max_score)
                for i in range(1, random.randint(2, 5))
            },
            "assignment_scores": [
                random.randint(min_score, max_score)
                for _ in range(random.randint(2, 6))
            ],
            "participation_score": round(random.uniform(3.5, 5.0), 1),
            "attendance_rate": round(random.uniform(0.85, 1.0), 2),
        }


class AuthenticationHelper:
    """Helper class for authentication-related test operations."""

    @staticmethod
    def create_test_user(
        username: str, role: UserRole = UserRole.STUDENT, is_active: bool = True
    ) -> UserInDB:
        """Create a test user with hashed password."""
        from src.auth import get_password_hash

        return UserInDB(
            id=hash(username) % 10000,  # Generate consistent ID
            username=username,
            email=f"{username}@test.nursing.edu",
            role=role,
            hashed_password=get_password_hash("test_password"),
            is_active=is_active,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def get_auth_headers(user: UserInDB) -> dict[str, str]:
        """Get authentication headers for a user."""
        token_response = create_auth_tokens(user)
        return {"Authorization": f"Bearer {token_response.access_token}"}

    @staticmethod
    def login_user(
        client: TestClient, username: str, password: str = "test_password"
    ) -> str | None:
        """Login a user and return the access token."""
        response = client.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )

        if response.status_code == 200:
            return response.json()["access_token"]
        return None


class ResponseValidator:
    """Helper class for validating API responses."""

    @staticmethod
    def validate_error_response(response_data: dict[str, Any]) -> bool:
        """Validate that error response has correct structure."""
        required_fields = ["error", "error_code", "message", "timestamp"]

        for field in required_fields:
            if field not in response_data:
                return False

        if response_data["error"] is not True:
            return False

        # Validate timestamp format
        try:
            datetime.fromisoformat(response_data["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return False

        return True

    @staticmethod
    def validate_pagination_response(response_data: dict[str, Any]) -> bool:
        """Validate paginated response structure."""
        if not isinstance(response_data, dict):
            return False

        # Common pagination fields
        expected_fields = ["total_count", "items"]

        # Check if it looks like a list response
        if isinstance(response_data, list):
            return True

        # Check for pagination metadata
        has_pagination = any(field in response_data for field in expected_fields)
        return has_pagination

    @staticmethod
    def validate_jwt_token_structure(token: str) -> bool:
        """Validate JWT token has correct structure."""
        try:
            import jwt

            payload = jwt.decode(token, options={"verify_signature": False})

            required_claims = ["sub", "exp", "iat", "type"]
            for claim in required_claims:
                if claim not in payload:
                    return False

            return True
        except Exception:
            return False

    @staticmethod
    def validate_nclex_question_structure(question: dict[str, Any]) -> bool:
        """Validate NCLEX question has correct structure."""
        required_fields = ["id", "question", "options", "correct_answer", "rationale"]

        for field in required_fields:
            if field not in question:
                return False

        # Validate options are list with multiple choices
        if not isinstance(question["options"], list) or len(question["options"]) < 2:
            return False

        # Validate correct answer is one of A, B, C, D, etc.
        if (
            not isinstance(question["correct_answer"], str)
            or len(question["correct_answer"]) != 1
        ):
            return False

        return True

    @staticmethod
    def validate_competency_assessment_structure(assessment: dict[str, Any]) -> bool:
        """Validate competency assessment has correct structure."""
        required_fields = [
            "student_id",
            "competency_id",
            "current_level",
            "score",
            "strengths",
            "areas_for_improvement",
            "recommendations",
        ]

        for field in required_fields:
            if field not in assessment:
                return False

        # Validate proficiency level
        if "current_level" in assessment:
            try:
                CompetencyProficiencyLevel(assessment["current_level"])
            except ValueError:
                return False

        # Validate score is numeric
        if not isinstance(assessment.get("score"), int | float):
            return False

        return True


class PerformanceHelper:
    """Helper class for performance testing utilities."""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.measurements = []

    def start_measurement(self):
        """Start a performance measurement."""
        self.start_time = time.time()

    def end_measurement(self) -> float:
        """End measurement and return duration."""
        self.end_time = time.time()
        if self.start_time:
            duration = self.end_time - self.start_time
            self.measurements.append(duration)
            return duration
        return 0.0

    def get_average_time(self) -> float:
        """Get average time from all measurements."""
        if not self.measurements:
            return 0.0
        return sum(self.measurements) / len(self.measurements)

    def get_max_time(self) -> float:
        """Get maximum time from all measurements."""
        return max(self.measurements) if self.measurements else 0.0

    def get_min_time(self) -> float:
        """Get minimum time from all measurements."""
        return min(self.measurements) if self.measurements else 0.0

    def assert_performance_threshold(self, max_duration: float):
        """Assert that latest measurement is within threshold."""
        if self.measurements:
            latest = self.measurements[-1]
            assert latest <= max_duration, (
                f"Performance threshold exceeded: {latest:.3f}s > {max_duration}s"
            )

    @staticmethod
    def time_function(func: Callable, *args, **kwargs) -> tuple[Any, float]:
        """Time a function execution and return result and duration."""
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        return result, duration

    @staticmethod
    def create_load_test(
        test_function: Callable, num_requests: int, concurrent_users: int = 1
    ) -> dict[str, Any]:
        """Create a basic load test scenario."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []

        def execute_test():
            start = time.time()
            try:
                result = test_function()
                success = True
                error = None
            except Exception as e:
                result = None
                success = False
                error = str(e)

            end = time.time()
            return {
                "success": success,
                "duration": end - start,
                "result": result,
                "error": error,
            }

        # Execute load test
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(execute_test) for _ in range(num_requests)]
            results = [future.result() for future in as_completed(futures)]

        # Analyze results
        successful_requests = [r for r in results if r["success"]]
        failed_requests = [r for r in results if not r["success"]]

        response_times = [r["duration"] for r in successful_requests]

        return {
            "total_requests": num_requests,
            "successful_requests": len(successful_requests),
            "failed_requests": len(failed_requests),
            "success_rate": len(successful_requests) / num_requests,
            "average_response_time": sum(response_times) / len(response_times)
            if response_times
            else 0,
            "min_response_time": min(response_times) if response_times else 0,
            "max_response_time": max(response_times) if response_times else 0,
            "errors": [r["error"] for r in failed_requests if r["error"]],
        }


class DatabaseHelper:
    """Helper class for database-related test operations."""

    @staticmethod
    def create_test_database_url(test_name: str) -> str:
        """Create a test-specific database URL."""
        timestamp = int(time.time())
        return f"sqlite+aiosqlite:///./test_{test_name}_{timestamp}.db"

    @staticmethod
    def cleanup_test_database(db_url: str):
        """Clean up test database file."""
        import os

        if "sqlite" in db_url and "test_" in db_url:
            db_file = db_url.replace("sqlite+aiosqlite:///./", "")
            if os.path.exists(db_file):
                os.remove(db_file)


class MockServiceHelper:
    """Helper for creating mock services and responses."""

    @staticmethod
    def create_mock_ragnostic_response(
        question_count: int = 5,
        topic: str = "nursing_fundamentals",
        difficulty: str = "medium",
    ) -> dict[str, Any]:
        """Create a mock RAGnostic service response."""
        questions = []

        for _i in range(question_count):
            questions.append(
                TestDataGenerator.generate_nclex_question(topic, difficulty)
            )

        return {
            "questions": questions,
            "metadata": {
                "generation_time": round(random.uniform(1.0, 3.0), 2),
                "source": "RAGnostic AI Mock",
                "confidence": round(random.uniform(0.85, 0.98), 2),
                "topic": topic,
                "difficulty": difficulty,
            },
        }

    @staticmethod
    def create_mock_competency_assessment_result(
        student_id: str, competency_id: str
    ) -> dict[str, Any]:
        """Create a mock competency assessment result."""
        proficiency_levels = list(CompetencyProficiencyLevel)
        current_level = random.choice(proficiency_levels)

        return {
            "student_id": student_id,
            "competency_id": competency_id,
            "assessment_id": f"mock_assessment_{int(time.time())}",
            "current_level": current_level.value,
            "score": round(random.uniform(65.0, 95.0), 1),
            "strengths": [
                "Demonstrates good understanding of basic concepts",
                "Shows improvement in clinical reasoning",
                "Effective communication with patients",
            ][: random.randint(1, 3)],
            "areas_for_improvement": [
                "Needs more practice with advanced procedures",
                "Should review pharmacology principles",
                "Could improve documentation skills",
            ][: random.randint(1, 3)],
            "recommendations": [
                "Complete additional practice exercises",
                "Review relevant textbook chapters",
                "Participate in simulation scenarios",
            ][: random.randint(1, 3)],
            "evidence_summary": "Based on quiz scores, clinical evaluations, and simulation performance",
            "assessor_id": "mock_assessor_001",
            "assessment_date": datetime.now(UTC).isoformat(),
            "next_assessment_due": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "proficiency_trend": random.choice(["improving", "stable", "declining"]),
        }


class SecurityTestHelper:
    """Helper for security testing scenarios."""

    @staticmethod
    def generate_sql_injection_payloads() -> list[str]:
        """Generate common SQL injection test payloads."""
        return [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "1; DELETE FROM sessions WHERE 1=1; --",
            "' UNION SELECT password FROM users WHERE username='admin' --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            "' OR 1=1 --",
            "admin'/*",
            "' OR 'a'='a",
            "1' AND SLEEP(5) --",
        ]

    @staticmethod
    def generate_xss_payloads() -> list[str]:
        """Generate common XSS test payloads."""
        return [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(1)'>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src='javascript:alert(1)'></iframe>",
            "&#60;script&#62;alert('xss')&#60;/script&#62;",
            "<body onload='alert(1)'>",
            "<input onfocus='alert(1)' autofocus>",
            "<marquee onstart='alert(1)'>",
        ]

    @staticmethod
    def generate_path_traversal_payloads() -> list[str]:
        """Generate path traversal test payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "../../../../../../etc/shadow",
            "..\\..\\..\\..\\windows\\win.ini",
        ]

    @staticmethod
    def is_response_safe(response_text: str) -> bool:
        """Check if response text appears to be safe from common vulnerabilities."""
        dangerous_patterns = [
            "<script>",
            "</script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "root:x:",
            "/bin/bash",
            "administrator",
            "password",
            "secret",
            "token",
            "database",
            "connection string",
            "stack trace",
        ]

        response_lower = response_text.lower()
        return not any(
            pattern.lower() in response_lower for pattern in dangerous_patterns
        )
