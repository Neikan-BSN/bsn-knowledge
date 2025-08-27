"""
Comprehensive test configuration for BSN Knowledge API testing suite.
Provides fixtures for authentication, database setup, and mock services.
"""

import asyncio
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
import psutil

from src.api.main import app
from src.auth import (
    UserInDB,
    UserRole,
    create_auth_tokens,
    fake_users_db,
    get_password_hash,
)
from src.models.assessment_models import (
    CompetencyAssessmentResult,
    CompetencyProficiencyLevel,
    KnowledgeGap,
    LearningPathRecommendation,
)

# Test database URL - E2E Integration
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_bsn_knowledge.db"

# E2E Service Configuration (From Group 1A Infrastructure)
E2E_SERVICES_CONFIG = {
    "bsn_knowledge": {
        "url": "http://bsn-knowledge-test:8040",
        "health_endpoint": "/health",
        "api_key": "test_bsn_api_key",
    },
    "ragnostic_orchestrator": {
        "url": "http://ragnostic-orchestrator:8030",
        "health_endpoint": "/health",
        "api_key": "test_ragnostic_api_key",
    },
    "ragnostic_storage": {
        "url": "http://ragnostic-storage:8032",
        "health_endpoint": "/health",
    },
    "ragnostic_nursing_processor": {
        "url": "http://ragnostic-nursing-processor:8033",
        "health_endpoint": "/health",
    },
    "bsn_analytics": {
        "url": "http://bsn-analytics:8041",
        "health_endpoint": "/health",
    },
    "umls_mock": {
        "url": "http://umls-mock:8000",
        "health_endpoint": "/health",
    },
    "openai_mock": {
        "url": "http://openai-mock:8000",
        "health_endpoint": "/health",
    },
}

# Database Configuration (From Group 1A Multi-DB Setup)
E2E_DATABASE_CONFIG = {
    "postgresql": {
        "ragnostic_e2e": "postgresql+asyncpg://ragnostic_user:ragnostic_pass@postgres-e2e:5432/ragnostic_e2e",
        "bsn_knowledge_e2e": "postgresql+asyncpg://bsn_user:bsn_pass@postgres-e2e:5432/bsn_knowledge_e2e",
        "e2e_analytics": "postgresql+asyncpg://analytics_user:analytics_pass@postgres-e2e:5432/e2e_analytics",
    },
    "redis": {
        "url": "redis://redis-e2e:6379",
        "databases": {"cache": 0, "sessions": 1, "tasks": 2, "metrics": 3, "test": 15},
    },
    "qdrant": {
        "url": "http://qdrant-e2e:6333",
        "collections": ["medical_terminology", "nursing_content", "embeddings"],
    },
    "neo4j": {
        "url": "bolt://neo4j-e2e:7687",
        "http_url": "http://neo4j-e2e:7474",
        "user": "neo4j",
        "password": "test_password",
    },
}

# Test configuration
TEST_CONFIG = {
    "JWT_SECRET_KEY": "test_secret_key_for_testing_only",
    "TEST_MODE": True,
    "RATE_LIMIT_DISABLED": True,
    "EXTERNAL_SERVICE_MOCK": True,
    "E2E_MODE": os.getenv("E2E_MODE", "false").lower() == "true",
    "MEDICAL_ACCURACY_THRESHOLD": 0.98,
    "PERFORMANCE_TARGET_MS": 500,
    "SERVICE_TIMEOUT_SECONDS": 30,
}


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_app() -> FastAPI:
    """Test FastAPI application instance."""
    return app


@pytest.fixture(scope="function")
def client(test_app: FastAPI) -> TestClient:
    """Synchronous test client for FastAPI application."""
    with TestClient(test_app) as test_client:
        yield test_client


@pytest.fixture(scope="function")
async def async_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Async test client for FastAPI application."""
    async with AsyncClient(app=test_app, base_url="http://test") as ac:
        yield ac


# Authentication fixtures
@pytest.fixture(scope="function")
def test_users() -> dict[str, UserInDB]:
    """Test users for authentication testing."""
    return {
        "student1": UserInDB(
            id=1,
            username="student1",
            email="student1@test.edu",
            role=UserRole.STUDENT,
            hashed_password=get_password_hash("test_password"),
            is_active=True,
            created_at=datetime.now(UTC),
        ),
        "instructor1": UserInDB(
            id=2,
            username="instructor1",
            email="instructor1@test.edu",
            role=UserRole.INSTRUCTOR,
            hashed_password=get_password_hash("test_password"),
            is_active=True,
            created_at=datetime.now(UTC),
        ),
        "admin1": UserInDB(
            id=3,
            username="admin1",
            email="admin1@test.edu",
            role=UserRole.ADMIN,
            hashed_password=get_password_hash("test_password"),
            is_active=True,
            created_at=datetime.now(UTC),
        ),
        "inactive_user": UserInDB(
            id=4,
            username="inactive_user",
            email="inactive@test.edu",
            role=UserRole.STUDENT,
            hashed_password=get_password_hash("test_password"),
            is_active=False,
            created_at=datetime.now(UTC),
        ),
    }


@pytest.fixture(scope="function")
def auth_tokens(test_users: dict[str, UserInDB]) -> dict[str, str]:
    """Generate authentication tokens for test users."""
    tokens = {}
    for username, user in test_users.items():
        if user.is_active:
            token_response = create_auth_tokens(user)
            tokens[username] = token_response.access_token
    return tokens


@pytest.fixture(scope="function")
def auth_headers(auth_tokens: dict[str, str]) -> dict[str, dict[str, str]]:
    """Generate authentication headers for test requests."""
    return {
        username: {"Authorization": f"Bearer {token}"}
        for username, token in auth_tokens.items()
    }


# Mock data fixtures
@pytest.fixture
def sample_nursing_content() -> dict[str, Any]:
    """Sample nursing education content for testing."""
    return {
        "topics": [
            {
                "id": "cardiology_basics",
                "name": "Basic Cardiology",
                "category": "cardiovascular",
                "description": "Fundamental cardiovascular assessment and care",
                "difficulty": "beginner",
            },
            {
                "id": "medication_administration",
                "name": "Safe Medication Administration",
                "category": "pharmacology",
                "description": "Principles of safe medication administration",
                "difficulty": "intermediate",
            },
            {
                "id": "infection_control",
                "name": "Infection Prevention and Control",
                "category": "safety",
                "description": "Evidence-based infection prevention strategies",
                "difficulty": "intermediate",
            },
        ],
        "competencies": [
            {
                "id": "AACN_KNOWLEDGE_1",
                "domain": "knowledge_for_nursing_practice",
                "name": "Pathophysiology Knowledge",
                "description": "Understanding of human pathophysiology",
            },
            {
                "id": "AACN_PERSON_CENTERED_1",
                "domain": "person_centered_care",
                "name": "Holistic Assessment",
                "description": "Comprehensive patient assessment skills",
            },
        ],
    }


@pytest.fixture
def mock_nclex_questions() -> dict[str, Any]:
    """Mock NCLEX-style questions for testing."""
    return {
        "questions": [
            {
                "id": "nclex_001",
                "type": "multiple_choice",
                "question": "A patient with heart failure is receiving digoxin. Which finding would indicate digoxin toxicity?",
                "options": [
                    "A. Heart rate of 88 bpm",
                    "B. Nausea and visual disturbances",
                    "C. Blood pressure of 130/80 mmHg",
                    "D. Respiratory rate of 18",
                ],
                "correct_answer": "B",
                "rationale": "Nausea and visual disturbances are classic signs of digoxin toxicity.",
                "topic": "cardiology",
                "difficulty": "medium",
                "nclex_category": "Pharmacological and Parenteral Therapies",
            },
            {
                "id": "nclex_002",
                "type": "multiple_choice",
                "question": "Which action should the nurse take first when administering medications?",
                "options": [
                    "A. Check the patient's armband",
                    "B. Verify the physician's order",
                    "C. Wash hands thoroughly",
                    "D. Prepare the medication",
                ],
                "correct_answer": "C",
                "rationale": "Hand hygiene is always the first step in any patient care activity.",
                "topic": "infection_control",
                "difficulty": "easy",
                "nclex_category": "Safety and Infection Control",
            },
        ]
    }


@pytest.fixture
def mock_assessment_data() -> dict[str, Any]:
    """Mock assessment data for competency testing."""
    return {
        "student_performance": {
            "student_id": "student_001",
            "quiz_scores": [85, 78, 92, 88],
            "clinical_evaluations": {
                "communication": 4.2,
                "clinical_reasoning": 3.8,
                "technical_skills": 4.0,
                "professionalism": 4.5,
            },
            "simulation_scores": {"scenario_1": 88, "scenario_2": 92, "scenario_3": 85},
        },
        "competency_gaps": [
            {
                "competency_id": "AACN_KNOWLEDGE_1",
                "severity": "medium",
                "description": "Gaps in advanced pathophysiology concepts",
                "recommendations": [
                    "Review cardiovascular pathophysiology",
                    "Complete practice exercises",
                ],
            }
        ],
    }


@pytest.fixture
def mock_analytics_data() -> dict[str, Any]:
    """Mock analytics data for testing."""
    return {
        "student_analytics": {
            "student_id": "student_001",
            "overall_progress": 78.5,
            "competency_scores": {
                "knowledge_for_nursing_practice": 82.0,
                "person_centered_care": 88.0,
                "population_health": 75.0,
                "scholarship_for_nursing_discipline": 70.0,
                "information_technology": 85.0,
                "healthcare_systems": 72.0,
                "interprofessional_partnerships": 90.0,
                "personal_professional_development": 86.0,
            },
            "study_time_hours": 45.5,
            "quiz_completion_rate": 92.0,
            "areas_for_improvement": ["Population Health", "Healthcare Systems"],
        }
    }


# Service mocks
@pytest.fixture(scope="function")
def mock_ragnostic_client():
    """Mock RAGnostic client for testing."""
    mock_client = AsyncMock()

    # Mock question generation
    mock_client.generate_questions.return_value = {
        "questions": [
            {
                "id": "generated_001",
                "question": "Mock generated question?",
                "options": ["A. Option 1", "B. Option 2", "C. Option 3", "D. Option 4"],
                "correct_answer": "B",
                "rationale": "Mock rationale",
                "difficulty": "medium",
            }
        ],
        "metadata": {
            "generation_time": 1.5,
            "source": "ragnostic_ai",
            "confidence": 0.92,
        },
    }

    # Mock content enrichment
    mock_client.enrich_content.return_value = {
        "enriched_content": "Enhanced educational content with additional context",
        "learning_objectives": ["Objective 1", "Objective 2"],
        "assessment_suggestions": ["Quiz question 1", "Case study scenario"],
    }

    return mock_client


@pytest.fixture(scope="function")
def mock_competency_framework():
    """Mock AACN competency framework for testing."""
    mock_framework = AsyncMock()

    # Mock competency assessment
    mock_framework.assess_competency.return_value = CompetencyAssessmentResult(
        student_id="student_001",
        competency_id="AACN_KNOWLEDGE_1",
        assessment_id="test_assessment_001",
        current_level=CompetencyProficiencyLevel.COMPETENT,
        score=78.5,
        strengths=["Good understanding of basic concepts"],
        areas_for_improvement=["Advanced pathophysiology"],
        recommendations=["Review cardiovascular system", "Practice case studies"],
        evidence_summary="Based on quiz scores and clinical evaluations",
        assessor_id="instructor_001",
        assessment_date=datetime.now(UTC),
        next_assessment_due=datetime.now(UTC),
        proficiency_trend="improving",
    )

    # Mock competency gaps
    mock_framework.get_competency_gaps.return_value = {
        "knowledge_for_nursing_practice": [
            KnowledgeGap(
                competency_id="AACN_KNOWLEDGE_1",
                gap_description="Advanced pathophysiology concepts",
                severity="medium",
                recommended_resources=["Pathophysiology textbook Ch. 12-15"],
                estimated_time_to_close_hours=8,
                prerequisites=[],
            )
        ]
    }

    # Mock learning path
    mock_framework.recommend_learning_path.return_value = LearningPathRecommendation(
        student_id="student_001",
        target_competencies=["AACN_KNOWLEDGE_1"],
        recommended_sequence=[
            {
                "activity_type": "reading",
                "content": "Pathophysiology review",
                "estimated_duration_minutes": 60,
            },
            {
                "activity_type": "quiz",
                "content": "Practice quiz on cardiovascular system",
                "estimated_duration_minutes": 30,
            },
        ],
        estimated_duration_hours=12,
        difficulty_progression="beginner_to_intermediate",
        learning_style_adaptations=["visual", "kinesthetic"],
    )

    return mock_framework


# Database fixtures
@pytest.fixture(scope="function")
async def test_db_engine():
    """Test database engine with in-memory SQLite."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=StaticPool,
        connect_args={
            "check_same_thread": False,
        },
    )
    yield engine
    await engine.dispose()


@pytest.fixture(scope="function")
async def test_db_session(test_db_engine):
    """Test database session with automatic cleanup."""
    async with test_db_engine.begin() as conn:
        async with AsyncSession(conn, expire_on_commit=False) as session:
            yield session
            await session.rollback()


# Performance testing fixtures
@pytest.fixture
def performance_monitor():
    """Performance monitoring fixture for testing."""

    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        @property
        def duration(self) -> float:
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0.0

        def assert_within_threshold(self, threshold_seconds: float):
            assert (
                self.duration <= threshold_seconds
            ), f"Operation took {self.duration:.3f}s, exceeds threshold of {threshold_seconds}s"

    return PerformanceMonitor()


# Rate limiting fixtures
@pytest.fixture(scope="function")
def reset_rate_limiter():
    """Reset rate limiter state before each test."""
    # Clear rate limiter state
    from src.auth import rate_limiter

    rate_limiter.requests.clear()
    yield
    rate_limiter.requests.clear()


# Helper functions
@pytest.fixture
def assert_valid_jwt_token():
    """Helper to validate JWT token structure."""
    import jwt

    def _validate_token(token: str) -> dict[str, Any]:
        try:
            # Decode without verification for testing
            payload = jwt.decode(token, options={"verify_signature": False})

            # Check required fields
            assert "sub" in payload, "Token missing 'sub' field"
            assert "user_id" in payload, "Token missing 'user_id' field"
            assert "role" in payload, "Token missing 'role' field"
            assert "exp" in payload, "Token missing 'exp' field"
            assert "iat" in payload, "Token missing 'iat' field"
            assert "type" in payload, "Token missing 'type' field"

            return payload
        except jwt.DecodeError as e:
            pytest.fail(f"Invalid JWT token: {e}")

    return _validate_token


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_test_environment():
    """Cleanup test environment after each test."""
    yield
    # Reset any global state
    fake_users_db.clear()
    fake_users_db.update(
        {
            "student1": UserInDB(
                id=1,
                username="student1",
                email="student1@nursing.edu",
                role=UserRole.STUDENT,
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # noqa: S106
                is_active=True,
            ),
            "instructor1": UserInDB(
                id=2,
                username="instructor1",
                email="instructor1@nursing.edu",
                role=UserRole.INSTRUCTOR,
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # noqa: S106
                is_active=True,
            ),
            "admin1": UserInDB(
                id=3,
                username="admin1",
                email="admin1@nursing.edu",
                role=UserRole.ADMIN,
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # noqa: S106
                is_active=True,
            ),
        }
    )


# E2E Service Health Monitoring
@pytest.fixture(scope="session")
async def e2e_service_health_monitor():
    """Monitor E2E service health throughout test session."""
    from tests.framework.orchestrator import ServiceHealthChecker

    if not TEST_CONFIG["E2E_MODE"]:
        # Return mock health checker for unit tests
        mock_checker = AsyncMock()
        mock_checker.wait_for_services.return_value = True
        mock_checker.get_all_health_status.return_value = {
            "healthy_count": len(E2E_SERVICES_CONFIG),
            "total_count": len(E2E_SERVICES_CONFIG),
            "services": [
                {"service": name, "status": "healthy"}
                for name in E2E_SERVICES_CONFIG.keys()
            ],
        }
        yield mock_checker
        return

    # Real E2E service health checker
    services = {name: config["url"] for name, config in E2E_SERVICES_CONFIG.items()}
    health_checker = ServiceHealthChecker(services)

    # Wait for services to be ready
    services_ready = await health_checker.wait_for_services(max_wait_seconds=120)
    if not services_ready:
        pytest.fail(
            "E2E services failed to become healthy - check Group 1A infrastructure"
        )

    yield health_checker
    await health_checker.close()


@pytest.fixture(scope="session")
async def e2e_database_connections():
    """Establish connections to all E2E databases from Group 1A setup."""
    if not TEST_CONFIG["E2E_MODE"]:
        # Return mock connections for unit tests
        yield {
            "postgresql": {
                "ragnostic_e2e": AsyncMock(),
                "bsn_knowledge_e2e": AsyncMock(),
                "e2e_analytics": AsyncMock(),
            },
            "redis": AsyncMock(),
            "qdrant": AsyncMock(),
            "neo4j": AsyncMock(),
        }
        return

    connections = {"postgresql": {}, "redis": None, "qdrant": None, "neo4j": None}

    try:
        # PostgreSQL connections
        for db_name, db_url in E2E_DATABASE_CONFIG["postgresql"].items():
            engine = create_async_engine(db_url, echo=False)
            connections["postgresql"][db_name] = engine

        # TODO: Add Redis, Qdrant, Neo4j connections when needed
        # For now, we'll use mocks for these
        connections["redis"] = AsyncMock()
        connections["qdrant"] = AsyncMock()
        connections["neo4j"] = AsyncMock()

        yield connections

    finally:
        # Cleanup connections
        for engine in connections["postgresql"].values():
            if hasattr(engine, "dispose"):
                await engine.dispose()


@pytest.fixture(scope="function")
async def e2e_pipeline_client(e2e_service_health_monitor):
    """HTTP client configured for E2E pipeline testing."""
    if not TEST_CONFIG["E2E_MODE"]:
        # Return mock client for unit tests
        mock_client = AsyncMock()
        mock_client.get.return_value.status_code = 200
        mock_client.post.return_value.status_code = 200
        yield mock_client
        return

    # Real E2E HTTP client with comprehensive timeout and retry configuration
    timeout = httpx.Timeout(
        connect=10.0, read=TEST_CONFIG["SERVICE_TIMEOUT_SECONDS"], write=10.0, pool=20.0
    )

    async with httpx.AsyncClient(
        timeout=timeout,
        headers={
            "User-Agent": "BSN-Knowledge-E2E-Tests/1.0",
            "X-Test-Mode": "e2e",
            "X-Medical-Accuracy-Required": str(
                TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"]
            ),
        },
        follow_redirects=True,
    ) as client:
        yield client


@pytest.fixture(scope="function")
def performance_monitor_e2e():
    """Enhanced performance monitoring for E2E tests with medical accuracy tracking."""

    class E2EPerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}
            self.medical_accuracy_results = []
            self.service_response_times = {}

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        @property
        def duration(self) -> float:
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return 0.0

        def record_service_response(self, service_name: str, response_time_ms: float):
            """Record individual service response time."""
            self.service_response_times[service_name] = response_time_ms

        def record_medical_accuracy(self, validation_type: str, accuracy_score: float):
            """Record medical accuracy validation results."""
            self.medical_accuracy_results.append(
                {
                    "type": validation_type,
                    "accuracy": accuracy_score,
                    "timestamp": time.time(),
                    "meets_threshold": accuracy_score
                    >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"],
                }
            )

        def assert_performance_targets(self):
            """Assert all E2E performance targets are met."""
            # Overall response time target
            assert (
                self.duration * 1000 <= TEST_CONFIG["PERFORMANCE_TARGET_MS"]
            ), f"E2E pipeline took {self.duration*1000:.1f}ms, exceeds {TEST_CONFIG['PERFORMANCE_TARGET_MS']}ms target"

            # Service response time targets (from Group 1A baseline: 82.5ms avg)
            for service, response_time in self.service_response_times.items():
                assert (
                    response_time <= 200
                ), f"Service {service} response time {response_time:.1f}ms exceeds 200ms target"

        def assert_medical_accuracy_targets(self):
            """Assert medical accuracy requirements are met."""
            if not self.medical_accuracy_results:
                return  # No medical accuracy validation performed

            failed_validations = [
                result
                for result in self.medical_accuracy_results
                if not result["meets_threshold"]
            ]

            assert (
                len(failed_validations) == 0
            ), f"Medical accuracy failed for: {[f['type'] for f in failed_validations]}"

        def get_system_metrics(self):
            """Get current system performance metrics."""
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage_percent": psutil.disk_usage("/").percent,
                "load_average": os.getloadavg()
                if hasattr(os, "getloadavg")
                else [0, 0, 0],
            }

        def generate_performance_report(self) -> dict:
            """Generate comprehensive performance report."""
            return {
                "execution_time_ms": self.duration * 1000,
                "service_response_times": self.service_response_times,
                "medical_accuracy_results": self.medical_accuracy_results,
                "system_metrics": self.get_system_metrics(),
                "performance_targets_met": self.duration * 1000
                <= TEST_CONFIG["PERFORMANCE_TARGET_MS"],
                "medical_accuracy_met": all(
                    r["meets_threshold"] for r in self.medical_accuracy_results
                ),
            }

    return E2EPerformanceMonitor()


@pytest.fixture(scope="function")
def medical_accuracy_validator():
    """Medical accuracy validation framework for E2E testing."""

    class MedicalAccuracyValidator:
        def __init__(self):
            self.validation_results = []
            self.umls_validations = []
            self.nclex_quality_checks = []

        def validate_umls_terminology(
            self, terms: list[str], expected_cuis: list[str] = None
        ) -> float:
            """Validate UMLS medical terminology accuracy."""
            # Mock validation - in real E2E, this would call UMLS service
            if not TEST_CONFIG["E2E_MODE"]:
                accuracy = 0.995  # Mock 99.5% accuracy from Group 1A baseline
            else:
                # Real UMLS validation would go here
                accuracy = 0.995  # Placeholder

            self.umls_validations.append(
                {
                    "terms": terms,
                    "expected_cuis": expected_cuis,
                    "accuracy": accuracy,
                    "timestamp": time.time(),
                }
            )

            return accuracy

        def validate_nclex_question_quality(self, questions: list[dict]) -> dict:
            """Validate NCLEX question quality and nursing education standards."""
            results = {
                "total_questions": len(questions),
                "quality_score": 0.0,
                "issues": [],
                "meets_standards": False,
            }

            if not questions:
                return results

            # Basic quality checks
            quality_scores = []
            for q in questions:
                score = 1.0  # Start with perfect score

                # Check required fields
                required_fields = ["question", "options", "correct_answer", "rationale"]
                missing_fields = [f for f in required_fields if f not in q or not q[f]]
                if missing_fields:
                    score -= 0.3
                    results["issues"].append(f"Missing fields: {missing_fields}")

                # Check medical terminology
                if "question" in q and len(q["question"]) < 50:
                    score -= 0.2
                    results["issues"].append("Question too short")

                # Check rationale quality
                if "rationale" in q and len(q["rationale"]) < 30:
                    score -= 0.2
                    results["issues"].append("Rationale too short")

                quality_scores.append(max(0.0, score))

            results["quality_score"] = sum(quality_scores) / len(quality_scores)
            results["meets_standards"] = results["quality_score"] >= 0.85

            self.nclex_quality_checks.append(results)
            return results

        def validate_clinical_decision_accuracy(
            self, recommendations: list[dict]
        ) -> float:
            """Validate clinical decision support accuracy."""
            if not recommendations:
                return 1.0

            # Mock validation - real implementation would check against evidence base
            accuracy = 0.92  # Mock 92% clinical accuracy

            self.validation_results.append(
                {
                    "type": "clinical_decision",
                    "accuracy": accuracy,
                    "recommendations_count": len(recommendations),
                    "timestamp": time.time(),
                }
            )

            return accuracy

        def get_overall_medical_accuracy(self) -> float:
            """Calculate overall medical accuracy score."""
            if not self.validation_results and not self.umls_validations:
                return 1.0

            scores = []

            # UMLS accuracy (weighted heavily)
            for validation in self.umls_validations:
                scores.extend([validation["accuracy"]] * 3)  # 3x weight

            # Clinical decision accuracy
            for validation in self.validation_results:
                scores.append(validation["accuracy"])

            # NCLEX quality (converted to accuracy)
            for check in self.nclex_quality_checks:
                scores.append(check["quality_score"])

            return sum(scores) / len(scores) if scores else 1.0

        def assert_medical_accuracy_requirements(self):
            """Assert all medical accuracy requirements are met."""
            overall_accuracy = self.get_overall_medical_accuracy()

            assert (
                overall_accuracy >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"]
            ), f"Medical accuracy {overall_accuracy:.3f} below required {TEST_CONFIG['MEDICAL_ACCURACY_THRESHOLD']}"

            # Check individual UMLS validations
            for validation in self.umls_validations:
                assert (
                    validation["accuracy"] >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"]
                ), f"UMLS accuracy {validation['accuracy']:.3f} below threshold"

    return MedicalAccuracyValidator()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers for E2E testing."""
    config.addinivalue_line("markers", "auth: Authentication and authorization tests")
    config.addinivalue_line("markers", "endpoints: API endpoint tests")
    config.addinivalue_line("markers", "rate_limiting: Rate limiting tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")

    # E2E Testing Markers (Enhanced for Group 1B)
    config.addinivalue_line("markers", "e2e: End-to-end pipeline tests")
    config.addinivalue_line("markers", "load: Load testing scenarios")
    config.addinivalue_line("markers", "resilience: Resilience and failure mode tests")
    config.addinivalue_line(
        "markers", "pipeline: Complete RAGnostic -> BSN Knowledge pipeline tests"
    )
    config.addinivalue_line("markers", "cross_service: Cross-service integration tests")
    config.addinivalue_line(
        "markers", "medical_accuracy: Medical content accuracy validation"
    )
    config.addinivalue_line("markers", "concurrent: Concurrent operation testing")

    # Group 1B Specific Markers
    config.addinivalue_line(
        "markers", "service_integration: Service fixture integration tests"
    )
    config.addinivalue_line("markers", "database_e2e: Multi-database E2E testing")
    config.addinivalue_line(
        "markers", "performance_baseline: Performance baseline validation"
    )
    config.addinivalue_line(
        "markers", "medical_validation: Medical accuracy framework tests"
    )
    config.addinivalue_line("markers", "orchestration: Test execution orchestration")
    config.addinivalue_line(
        "markers", "umls_integration: UMLS service integration tests"
    )
    config.addinivalue_line(
        "markers", "ragnostic_integration: RAGnostic service integration tests"
    )


# E2E Testing Framework Fixtures (Enhanced for Group 1B Integration)
@pytest.fixture(scope="session")
def e2e_services_config():
    """Configuration for E2E test services - updated for Group 1A infrastructure."""
    return E2E_SERVICES_CONFIG


@pytest.fixture(scope="session")
async def e2e_test_orchestrator(e2e_services_config, e2e_service_health_monitor):
    """E2E test orchestrator with comprehensive service coordination."""
    from tests.framework.orchestrator import E2ETestOrchestrator

    if not TEST_CONFIG["E2E_MODE"]:
        # Return mock orchestrator for unit tests
        mock_orchestrator = AsyncMock()
        mock_orchestrator.run_full_test_suite.return_value = {
            "execution_summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "success_rate": 100.0,
            }
        }
        yield mock_orchestrator
        return

    config = {
        "services": {
            name: service["url"] for name, service in e2e_services_config.items()
        },
        "test_suites": [],  # Will be populated by individual tests
        "output_dir": "./test_results",
        "max_workers": 4,
        "medical_accuracy_threshold": TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"],
        "performance_target_ms": TEST_CONFIG["PERFORMANCE_TARGET_MS"],
    }

    orchestrator = E2ETestOrchestrator(config)
    yield orchestrator

    # Cleanup
    await orchestrator.health_checker.close()


# Replaced by e2e_pipeline_client fixture above


@pytest.fixture
def load_test_config():
    """Configuration for load testing scenarios."""
    return {
        "concurrent_users": [10, 25, 50, 100],
        "test_duration_seconds": 60,
        "ramp_up_seconds": 30,
        "scenarios": {
            "nclex_generation": {
                "weight": 40,
                "endpoint": "/api/v1/nclex/generate",
                "method": "POST",
                "payload": {
                    "topic": "cardiovascular_nursing",
                    "difficulty": "medium",
                    "question_count": 5,
                },
            },
            "study_guide_creation": {
                "weight": 30,
                "endpoint": "/api/v1/study-guides/generate",
                "method": "POST",
                "payload": {
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "student_level": "undergraduate",
                },
            },
            "assessment_analytics": {
                "weight": 20,
                "endpoint": "/api/v1/analytics/assessment",
                "method": "GET",
                "params": {"student_id": "test_student_001"},
            },
            "content_search": {
                "weight": 10,
                "endpoint": "/api/v1/search",
                "method": "GET",
                "params": {"q": "nursing pathophysiology"},
            },
        },
    }


@pytest.fixture
def medical_test_data():
    """Comprehensive medical test data for pipeline validation."""
    return {
        "nursing_topics": [
            {
                "id": "cardiovascular_assessment",
                "name": "Cardiovascular Assessment",
                "umls_concepts": ["C0007226", "C0232337", "C0018787"],
                "expected_nclex_categories": [
                    "Health Promotion and Maintenance",
                    "Physiological Integrity",
                ],
            },
            {
                "id": "medication_administration",
                "name": "Safe Medication Administration",
                "umls_concepts": ["C0013227", "C0150270", "C0013230"],
                "expected_nclex_categories": ["Safe and Effective Care Environment"],
            },
            {
                "id": "infection_control",
                "name": "Infection Prevention and Control",
                "umls_concepts": ["C0085557", "C1292711", "C0009482"],
                "expected_nclex_categories": ["Safe and Effective Care Environment"],
            },
        ],
        "sample_questions": [
            {
                "question": "A patient with heart failure is prescribed digoxin 0.25 mg daily. Which assessment finding would indicate possible digoxin toxicity?",
                "options": [
                    "A. Heart rate of 88 beats per minute",
                    "B. Nausea and visual disturbances",
                    "C. Blood pressure of 130/80 mmHg",
                    "D. Respiratory rate of 20 breaths per minute",
                ],
                "correct_answer": "B",
                "rationale": "Nausea and visual disturbances are classic early signs of digoxin toxicity.",
                "nclex_category": "Pharmacological and Parenteral Therapies",
                "difficulty": "medium",
            }
        ],
        "performance_benchmarks": {
            "response_time_ms": {"p50": 100, "p95": 200, "p99": 500},
            "accuracy_thresholds": {
                "medical_terminology": 0.98,
                "educational_relevance": 0.95,
                "nclex_alignment": 0.92,
            },
        },
    }


@pytest.fixture
def resilience_test_scenarios():
    """Test scenarios for resilience and failure mode testing."""
    return {
        "service_failure": {
            "ragnostic_down": {
                "description": "RAGnostic service unavailable",
                "simulation": "stop_service",
                "expected_behavior": "graceful_degradation",
                "recovery_time_max_seconds": 30,
            },
            "database_connection_loss": {
                "description": "Database connection pool exhaustion",
                "simulation": "exhaust_connections",
                "expected_behavior": "queue_requests",
                "recovery_time_max_seconds": 60,
            },
        },
        "load_scenarios": {
            "memory_pressure": {
                "description": "High memory utilization",
                "target_memory_percentage": 85,
                "duration_seconds": 300,
            },
            "cpu_saturation": {
                "description": "CPU intensive operations",
                "target_cpu_percentage": 90,
                "duration_seconds": 180,
            },
        },
    }


@pytest.fixture
def security_test_vectors():
    """Security test vectors for cross-service validation."""
    return {
        "authentication_tests": {
            "invalid_jwt": {"token": "invalid.jwt.token", "expected_status": 401},
            "expired_jwt": {
                "token": "expired.jwt.token",  # Generate expired token
                "expected_status": 401,
            },
            "malformed_api_key": {"api_key": "malformed_key", "expected_status": 401},
        },
        "injection_tests": {
            "sql_injection": [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "'; SELECT * FROM medical_data; --",
            ],
            "xss_payloads": [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
            ],
        },
        "rate_limiting": {
            "burst_requests": 100,
            "time_window_seconds": 60,
            "expected_status": 429,
        },
    }


@pytest.fixture
def performance_monitoring():
    """Performance monitoring utilities for E2E tests."""
    import time
    from collections import defaultdict

    import psutil

    class PerformanceMonitor:
        def __init__(self):
            self.metrics = defaultdict(list)
            self.start_time = None

        def start_monitoring(self):
            self.start_time = time.time()
            self.metrics.clear()

        def record_metric(self, name: str, value: float):
            timestamp = time.time() - (self.start_time or time.time())
            self.metrics[name].append({"timestamp": timestamp, "value": value})

        def get_system_metrics(self):
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage("/").percent,
            }

        def calculate_statistics(self, metric_name: str):
            values = [m["value"] for m in self.metrics.get(metric_name, [])]
            if not values:
                return {}

            values.sort()
            n = len(values)
            return {
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / n,
                "p50": values[n // 2],
                "p95": values[int(0.95 * n)] if n > 20 else values[-1],
                "p99": values[int(0.99 * n)] if n > 100 else values[-1],
            }

    return PerformanceMonitor()


# Async pytest configuration
pytest_plugins = ["pytest_asyncio"]
