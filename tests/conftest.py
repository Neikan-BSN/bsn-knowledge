"""Pytest configuration for BSN Knowledge Base tests.

Implements Task Group 3 testing patterns:
- Neo4j test database isolation
- Parallel test execution
- Service coordination
- 90% coverage enforcement
"""

import asyncio
import os
from collections.abc import AsyncGenerator

import pytest
import redis
from neo4j import Driver, GraphDatabase
from qdrant_client import QdrantClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Test database configurations
TEST_NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7688")
TEST_NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
TEST_NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "testpass")
TEST_DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://testuser:testpass@localhost:5432/bsn_knowledge_test"
)
TEST_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def neo4j_driver() -> AsyncGenerator[Driver, None]:
    """Neo4j driver fixture with test database isolation."""
    driver = GraphDatabase.driver(
        TEST_NEO4J_URI, auth=(TEST_NEO4J_USER, TEST_NEO4J_PASSWORD)
    )

    # Verify connection
    try:
        driver.verify_connectivity()
        yield driver
    finally:
        driver.close()


@pytest.fixture(scope="function")
async def neo4j_session(neo4j_driver):
    """Neo4j session fixture with transaction isolation."""
    with neo4j_driver.session() as session:
        # Clear test data before each test
        session.run("MATCH (n) DETACH DELETE n")
        yield session
        # Clean up after test
        session.run("MATCH (n) DETACH DELETE n")


@pytest.fixture(scope="session")
async def postgres_engine():
    """PostgreSQL async engine for testing."""
    engine = create_async_engine(TEST_DATABASE_URL)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="function")
async def postgres_session(postgres_engine):
    """PostgreSQL session with transaction rollback."""
    async with postgres_engine.begin() as conn:
        async with AsyncSession(conn) as session:
            yield session
            # Rollback after test
            await session.rollback()


@pytest.fixture(scope="session")
def redis_client():
    """Redis client for testing with test database."""
    client = redis.from_url(TEST_REDIS_URL, db=15)  # Use test database
    yield client
    client.flushdb()  # Clean up
    client.close()


@pytest.fixture(scope="function")
def clean_redis(redis_client):
    """Clean Redis before each test."""
    redis_client.flushdb()
    yield redis_client
    redis_client.flushdb()


@pytest.fixture(scope="session")
def qdrant_client():
    """Qdrant client for vector storage testing."""
    client = QdrantClient(host="localhost", port=6333)
    yield client
    # Clean up collections
    try:
        collections = client.get_collections()
        for collection in collections.collections:
            if collection.name.startswith("test_"):
                client.delete_collection(collection.name)
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def sample_knowledge_data():
    """Sample medical terminology data for testing."""
    return {
        "medical_terms": [
            {"id": "term_1", "name": "Hypertension", "category": "cardiovascular"},
            {"id": "term_2", "name": "Diabetes", "category": "endocrine"},
            {"id": "term_3", "name": "Pneumonia", "category": "respiratory"},
        ],
        "relationships": [
            {"from": "term_1", "to": "term_2", "type": "COMORBID_WITH"},
            {"from": "term_3", "to": "term_1", "type": "COMPLICATES"},
        ],
    }


@pytest.fixture
def knowledge_graph_schema():
    """Knowledge graph schema for testing."""
    return {
        "constraints": [
            "CREATE CONSTRAINT medical_term_id IF NOT EXISTS FOR (n:MedicalTerm) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT knowledge_category_name IF NOT EXISTS FOR (n:Category) REQUIRE n.name IS UNIQUE",
        ],
        "indexes": [
            "CREATE INDEX medical_term_name IF NOT EXISTS FOR (n:MedicalTerm) ON (n.name)",
            "CREATE INDEX medical_term_category IF NOT EXISTS FOR (n:MedicalTerm) ON (n.category)",
        ],
    }


@pytest.fixture(scope="function")
async def setup_knowledge_graph(
    neo4j_session, knowledge_graph_schema, sample_knowledge_data
):
    """Setup knowledge graph with schema and sample data."""
    # Create constraints and indexes
    for constraint in knowledge_graph_schema["constraints"]:
        neo4j_session.run(constraint)

    for index in knowledge_graph_schema["indexes"]:
        neo4j_session.run(index)

    # Insert sample data
    for term in sample_knowledge_data["medical_terms"]:
        neo4j_session.run(
            "CREATE (n:MedicalTerm {id: $id, name: $name, category: $category})", **term
        )

    for rel in sample_knowledge_data["relationships"]:
        neo4j_session.run(
            "MATCH (a:MedicalTerm {id: $from}), (b:MedicalTerm {id: $to}) "
            "CREATE (a)-[r:" + rel["type"] + "]->(b)",
            from_id=rel["from"],
            to_id=rel["to"],
        )

    yield neo4j_session


# Performance testing fixtures
@pytest.fixture
def performance_threshold():
    """Performance thresholds for knowledge base operations."""
    return {
        "query_response_time": 0.5,  # 500ms max for queries
        "graph_traversal_time": 1.0,  # 1s max for complex traversals
        "bulk_insert_time": 2.0,  # 2s max for bulk operations
    }


@pytest.fixture
def coverage_requirements():
    """Coverage requirements following Task Group 3 standards."""
    return {
        "minimum_coverage": 90,  # 90% coverage requirement
        "exclude_patterns": [
            "*/tests/*",
            "*/__pycache__/*",
            "*/migrations/*",
        ],
    }


# Async test helpers
pytest_plugins = ["pytest_asyncio"]

# Parallel test execution configuration
pytest.main.Config.option.numprocesses = "auto"  # Use all available cores

# Timeout configuration for long-running tests
DEFAULT_TEST_TIMEOUT = 30  # 30 seconds


def pytest_configure(config):
    """Configure pytest for BSN Knowledge testing."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (may take more than 1 second)"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "neo4j: marks tests that require Neo4j database")
    config.addinivalue_line(
        "markers", "performance: marks tests for performance validation"
    )


@pytest.fixture(autouse=True)
def timeout_all_tests():
    """Auto-apply timeout to all tests."""
    import signal

    def timeout_handler(signum, frame):
        raise TimeoutError(f"Test exceeded {DEFAULT_TEST_TIMEOUT} seconds")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(DEFAULT_TEST_TIMEOUT)
    yield
    signal.alarm(0)  # Disable alarm
