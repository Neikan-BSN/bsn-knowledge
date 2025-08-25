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

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

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

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_bsn_knowledge.db"

# Test configuration
TEST_CONFIG = {
    "JWT_SECRET_KEY": "test_secret_key_for_testing_only",
    "TEST_MODE": True,
    "RATE_LIMIT_DISABLED": True,
    "EXTERNAL_SERVICE_MOCK": True,
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
            assert self.duration <= threshold_seconds, (
                f"Operation took {self.duration:.3f}s, exceeds threshold of {threshold_seconds}s"
            )

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
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                is_active=True,
            ),
            "instructor1": UserInDB(
                id=2,
                username="instructor1",
                email="instructor1@nursing.edu",
                role=UserRole.INSTRUCTOR,
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                is_active=True,
            ),
            "admin1": UserInDB(
                id=3,
                username="admin1",
                email="admin1@nursing.edu",
                role=UserRole.ADMIN,
                hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                is_active=True,
            ),
        }
    )


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "auth: Authentication and authorization tests")
    config.addinivalue_line("markers", "endpoints: API endpoint tests")
    config.addinivalue_line("markers", "rate_limiting: Rate limiting tests")
    config.addinivalue_line("markers", "security: Security tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")


# Async pytest configuration
pytest_plugins = ["pytest_asyncio"]
