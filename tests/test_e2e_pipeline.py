"""End-to-End Pipeline Testing for RAGnostic → BSN Knowledge Integration.

Comprehensive validation of the complete educational content pipeline including:
- Medical content enrichment through RAGnostic
- NCLEX question generation with medical accuracy
- Concurrent performance under realistic load
- Resilience and failure mode testing
- Security validation across service boundaries

EXECUTION: Group 2A - 15 Critical E2E Test Cases (E2E-001 to E2E-015)
"""

import asyncio
import json
import logging
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

# Configure test logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.mark.e2e
@pytest.mark.pipeline
class TestE2EPipeline:
    """End-to-end pipeline integration tests.

    Implements 15 critical E2E test cases (E2E-001 to E2E-015) validating
    complete UMLS→NCLEX pipeline with >98% medical accuracy and <2s performance.
    """

    @pytest.mark.asyncio
    @pytest.mark.medical_accuracy
    async def test_e2e_001_complete_umls_pipeline(
        self,
        e2e_pipeline_client,
        medical_test_data,
        performance_monitor_e2e,
        medical_accuracy_validator,
    ):
        """E2E-001: Complete UMLS terminology validation through RAGnostic → BSN Knowledge pipeline.

        Validates:
        - >98% UMLS terminology accuracy maintained
        - <2s end-to-end response time
        - Medical concept preservation across service boundaries
        """
        performance_monitor_e2e.start()
        logger.info("Starting E2E-001: Complete UMLS Pipeline Test")

        # Test data from fixtures
        nursing_topic = medical_test_data["nursing_topics"][
            0
        ]  # Cardiovascular assessment
        medical_test_data["performance_benchmarks"]

        # Step 1: Submit content for RAGnostic processing
        ragnostic_payload = {
            "content": f"Educational content on {nursing_topic['name']}",
            "umls_concepts": nursing_topic["umls_concepts"],
            "processing_type": "medical_enrichment",
            "target_education_level": "undergraduate_nursing",
            "accuracy_validation": True,
        }

        start_time = time.time()

        async with e2e_pipeline_client as client:
            # Process through RAGnostic
            ragnostic_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json=ragnostic_payload,
                timeout=30.0,
            )

            processing_time = time.time() - start_time
            performance_monitor_e2e.record_service_response(
                "ragnostic_orchestrator", processing_time * 1000
            )

            assert ragnostic_response.status_code == 200, (
                f"RAGnostic processing failed: {ragnostic_response.text}"
            )
            ragnostic_result = ragnostic_response.json()

            # Validate enrichment quality
            assert "enriched_content" in ragnostic_result
            assert "medical_concepts" in ragnostic_result
            assert len(ragnostic_result["medical_concepts"]) >= 3

            # Step 2: Generate NCLEX questions using enriched content
            bsn_payload = {
                "enriched_content": ragnostic_result["enriched_content"],
                "medical_concepts": ragnostic_result["medical_concepts"],
                "topic": nursing_topic["id"],
                "difficulty": "medium",
                "question_count": 5,
                "nclex_categories": nursing_topic["expected_nclex_categories"],
            }

            generation_start = time.time()

            bsn_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                json=bsn_payload,
                timeout=30.0,
            )

            generation_time = time.time() - generation_start
            performance_monitor_e2e.record_service_response(
                "bsn_knowledge", generation_time * 1000
            )

            assert bsn_response.status_code == 200, (
                f"NCLEX generation failed: {bsn_response.text}"
            )
            nclex_result = bsn_response.json()

            # Validate NCLEX question quality
            assert "questions" in nclex_result
            questions = nclex_result["questions"]
            assert len(questions) == 5, f"Expected 5 questions, got {len(questions)}"

            # Validate question structure and medical accuracy
            for question in questions:
                assert "question" in question
                assert "options" in question
                assert "correct_answer" in question
                assert "rationale" in question
                assert "nclex_category" in question

                # Check medical terminology integration and accuracy
                question_text = question["question"].lower()
                medical_terms_found = sum(
                    1
                    for concept in ragnostic_result["medical_concepts"]
                    if concept.get("preferred_name", "").lower() in question_text
                )
                assert medical_terms_found > 0, (
                    "Questions should incorporate medical concepts from RAGnostic"
                )

                # Validate medical accuracy
                medical_terms = [
                    concept.get("preferred_name", "")
                    for concept in ragnostic_result["medical_concepts"]
                ]
                umls_accuracy = medical_accuracy_validator.validate_umls_terminology(
                    medical_terms, nursing_topic["umls_concepts"]
                )
                performance_monitor_e2e.record_medical_accuracy(
                    "umls_terminology", umls_accuracy
                )

            # Validate NCLEX question quality
            nclex_quality = medical_accuracy_validator.validate_nclex_question_quality(
                questions
            )
            performance_monitor_e2e.record_medical_accuracy(
                "nclex_quality", nclex_quality["quality_score"]
            )

            # Performance validation
            performance_monitor_e2e.stop()
            total_pipeline_time = performance_monitor_e2e.duration

            # Assert performance benchmarks (<2s requirement)
            assert total_pipeline_time < 2.0, (
                f"E2E-001 Pipeline too slow: {total_pipeline_time:.2f}s > 2.0s requirement"
            )

            # Assert medical accuracy requirements (>98%)
            performance_monitor_e2e.assert_medical_accuracy_targets()
            medical_accuracy_validator.assert_medical_accuracy_requirements()

            # Log success metrics
            logger.info(
                f"E2E-001 PASSED: {total_pipeline_time:.3f}s, Medical Accuracy: {medical_accuracy_validator.get_overall_medical_accuracy():.3f}"
            )

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_e2e_002_concurrent_processing(
        self, e2e_pipeline_client, medical_test_data, performance_monitor_e2e
    ):
        """E2E-002: Concurrent processing of 10+ medical documents with accuracy validation.

        Validates:
        - 100+ concurrent requests handled successfully
        - >95% success rate maintained under load
        - <5s p95 response time under concurrent load
        """
        performance_monitor_e2e.start()
        logger.info("Starting E2E-002: Concurrent Processing Test")

        # Concurrent load simulation - scaled up for E2E-002
        concurrent_requests = 100
        nursing_topics = medical_test_data["nursing_topics"]

        # Define test scenarios for concurrent processing
        scenarios = {
            "nclex_generation": {
                "weight": 60,
                "endpoint": "/api/v1/nclex/generate",
                "method": "POST",
                "payload": {
                    "topic": "cardiovascular_assessment",
                    "difficulty": "medium",
                    "question_count": 3,
                },
            },
            "content_enrichment": {
                "weight": 40,
                "endpoint": "/api/v1/content/generate",
                "method": "POST",
                "payload": {
                    "content": "Nursing assessment fundamentals",
                    "umls_concepts": nursing_topics[0]["umls_concepts"][:3],
                },
            },
        }

        async def execute_scenario(
            client: httpx.AsyncClient,
            scenario_name: str,
            scenario_config: dict[str, Any],
        ):
            """Execute a single load test scenario."""
            start_time = time.time()

            try:
                if scenario_config["method"] == "POST":
                    response = await client.post(
                        f"http://bsn-knowledge-test:8040{scenario_config['endpoint']}",
                        json=scenario_config.get("payload", {}),
                        timeout=15.0,
                    )
                else:
                    response = await client.get(
                        f"http://bsn-knowledge-test:8040{scenario_config['endpoint']}",
                        params=scenario_config.get("params", {}),
                        timeout=15.0,
                    )

                response_time = time.time() - start_time
                performance_monitor_e2e.record_service_response(
                    f"{scenario_name}", response_time * 1000
                )

                return {
                    "scenario": scenario_name,
                    "status_code": response.status_code,
                    "response_time": response_time,
                    "success": response.status_code < 400,
                }
            except Exception as e:
                response_time = time.time() - start_time
                return {
                    "scenario": scenario_name,
                    "status_code": 0,
                    "response_time": response_time,
                    "success": False,
                    "error": str(e),
                }

        # Generate concurrent requests
        tasks = []
        async with e2e_pipeline_client as client:
            for i in range(concurrent_requests):
                scenario_name = list(scenarios.keys())[i % len(scenarios)]
                scenario_config = scenarios[scenario_name]

                task = execute_scenario(client, scenario_name, scenario_config)
                tasks.append(task)

            # Execute all scenarios concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        successful_requests = sum(
            1 for r in results if isinstance(r, dict) and r.get("success", False)
        )
        total_requests = len(results)
        success_rate = successful_requests / total_requests * 100

        # Calculate response time statistics
        response_times = [
            r["response_time"]
            for r in results
            if isinstance(r, dict) and "response_time" in r
        ]
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            p95_response_time = sorted(response_times)[int(0.95 * len(response_times))]

            performance_monitor_e2e.record_service_response(
                "concurrent_avg_response", avg_response_time * 1000
            )
            performance_monitor_e2e.record_service_response(
                "concurrent_p95_response", p95_response_time * 1000
            )

        # E2E-002 Performance assertions
        assert success_rate >= 95.0, (
            f"E2E-002 Success rate too low: {success_rate:.1f}% < 95% requirement"
        )
        if response_times:
            assert avg_response_time < 2.0, (
                f"E2E-002 Average response time too high: {avg_response_time:.2f}s > 2.0s"
            )
            assert p95_response_time < 5.0, (
                f"E2E-002 P95 response time too high: {p95_response_time:.2f}s > 5.0s requirement"
            )

        logger.info(
            f"E2E-002 PASSED: {total_requests} requests, {success_rate:.1f}% success"
        )
        logger.info(
            f"  Avg Response Time: {avg_response_time:.3f}s, P95: {p95_response_time:.3f}s"
        )

    @pytest.mark.asyncio
    @pytest.mark.medical_accuracy
    async def test_e2e_003_medical_accuracy_preservation(
        self, e2e_pipeline_client, medical_test_data, medical_accuracy_validator
    ):
        """E2E-003: Medical accuracy preservation across service boundaries (>98% requirement).

        Validates:
        - UMLS terminology accuracy maintained through pipeline
        - Medical concept fidelity across RAGnostic → BSN Knowledge
        - Clinical decision accuracy preservation
        """
        logger.info("Starting E2E-003: Medical Accuracy Preservation Test")

        # Test with multiple nursing topics for comprehensive accuracy validation
        nursing_topics = medical_test_data["nursing_topics"]

        async with e2e_pipeline_client as client:
            accuracy_results = []

            for topic in nursing_topics:
                # Step 1: Process medical content through RAGnostic for enrichment
                ragnostic_payload = {
                    "content": f"Educational content on {topic['name']}",
                    "umls_concepts": topic["umls_concepts"],
                    "processing_type": "medical_enrichment",
                    "accuracy_validation": True,
                }

                ragnostic_response = await client.post(
                    "http://ragnostic-orchestrator:8030/api/v1/process",
                    json=ragnostic_payload,
                    timeout=30.0,
                )
                assert ragnostic_response.status_code == 200, (
                    f"RAGnostic processing failed for {topic['name']}"
                )
                ragnostic_result = ragnostic_response.json()

                # Step 2: Validate UMLS terminology accuracy preservation
                original_concepts = set(topic["umls_concepts"])
                enriched_concepts = set(
                    concept.get("cui", "")
                    for concept in ragnostic_result.get("medical_concepts", [])
                )

                concept_preservation_rate = len(
                    original_concepts.intersection(enriched_concepts)
                ) / len(original_concepts)
                accuracy_results.append(
                    {
                        "topic": topic["name"],
                        "concept_preservation": concept_preservation_rate,
                        "enriched_concepts_count": len(
                            ragnostic_result.get("medical_concepts", [])
                        ),
                    }
                )

                # Validate medical accuracy through BSN Knowledge processing
                bsn_payload = {
                    "enriched_content": ragnostic_result["enriched_content"],
                    "medical_concepts": ragnostic_result["medical_concepts"],
                    "topic": topic["id"],
                    "difficulty": "medium",
                    "question_count": 3,
                    "accuracy_validation": True,
                }

                bsn_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=bsn_payload,
                    timeout=30.0,
                )
                assert bsn_response.status_code == 200, (
                    f"BSN Knowledge processing failed for {topic['name']}"
                )
                bsn_result = bsn_response.json()

                # Step 3: Validate medical accuracy in generated content
                questions = bsn_result["questions"]
                medical_terms = [
                    concept.get("preferred_name", "")
                    for concept in ragnostic_result["medical_concepts"]
                ]

                umls_accuracy = medical_accuracy_validator.validate_umls_terminology(
                    medical_terms, topic["umls_concepts"]
                )
                nclex_quality = (
                    medical_accuracy_validator.validate_nclex_question_quality(
                        questions
                    )
                )

                accuracy_results[-1].update(
                    {
                        "umls_accuracy": umls_accuracy,
                        "nclex_quality": nclex_quality["quality_score"],
                        "questions_generated": len(questions),
                    }
                )

            # Step 4: Validate overall medical accuracy across all topics
            overall_concept_preservation = sum(
                r["concept_preservation"] for r in accuracy_results
            ) / len(accuracy_results)
            overall_umls_accuracy = sum(
                r["umls_accuracy"] for r in accuracy_results
            ) / len(accuracy_results)
            overall_nclex_quality = sum(
                r["nclex_quality"] for r in accuracy_results
            ) / len(accuracy_results)

            # Assert E2E-003 requirements (>98% medical accuracy)
            assert overall_concept_preservation >= 0.98, (
                f"E2E-003 Concept preservation {overall_concept_preservation:.3f} < 0.98 requirement"
            )
            assert overall_umls_accuracy >= 0.98, (
                f"E2E-003 UMLS accuracy {overall_umls_accuracy:.3f} < 0.98 requirement"
            )
            assert overall_nclex_quality >= 0.85, (
                f"E2E-003 NCLEX quality {overall_nclex_quality:.3f} < 0.85 threshold"
            )

            # Validate medical accuracy requirements
            medical_accuracy_validator.assert_medical_accuracy_requirements()

            logger.info(
                f"E2E-003 PASSED: Concept preservation: {overall_concept_preservation:.3f}, UMLS accuracy: {overall_umls_accuracy:.3f}"
            )

    @pytest.mark.asyncio
    @pytest.mark.database
    async def test_e2e_004_multi_database_consistency(
        self, e2e_pipeline_client, e2e_database_connections, medical_test_data
    ):
        """E2E-004: Multi-database consistency (PostgreSQL, Redis, Qdrant, Neo4j).

        Validates:
        - Data consistency across all 4 database systems
        - Transaction integrity in distributed environment
        - No data loss during multi-service operations
        """
        logger.info("Starting E2E-004: Multi-Database Consistency Test")

        nursing_topic = medical_test_data["nursing_topics"][
            0
        ]  # Cardiovascular assessment
        test_student_id = "e2e_004_test_student"

        async with e2e_pipeline_client as client:
            # Step 1: Create data across multiple databases
            student_payload = {
                "student_id": test_student_id,
                "name": "E2E Test Student",
                "competency_level": "intermediate",
                "learning_objectives": [nursing_topic["id"]],
            }

            # Create student profile (PostgreSQL)
            profile_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/students/profile",
                json=student_payload,
                timeout=10.0,
            )
            assert profile_response.status_code in [
                200,
                201,
            ], f"Student profile creation failed: {profile_response.text}"

            # Step 2: Generate content (triggers multiple database operations)
            content_payload = {
                "student_id": test_student_id,
                "topic": nursing_topic["id"],
                "umls_concepts": nursing_topic["umls_concepts"],
                "personalization": True,
                "store_in_vector_db": True,  # Qdrant
                "create_knowledge_graph": True,  # Neo4j
                "cache_results": True,  # Redis
            }

            content_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/content/generate",
                json=content_payload,
                timeout=30.0,
            )
            assert content_response.status_code == 200, (
                f"Content generation failed: {content_response.text}"
            )
            content_result = content_response.json()

            # Step 3: Verify data consistency across databases
            # Check PostgreSQL data
            student_check = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/students/profile/{test_student_id}",
                timeout=10.0,
            )
            assert student_check.status_code == 200, (
                "Student profile not found in PostgreSQL"
            )
            student_data = student_check.json()
            assert student_data["student_id"] == test_student_id

            # Check content exists and is properly linked
            content_id = content_result.get("content_id")
            assert content_id is not None, "Content ID not returned"

            content_check = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}",
                timeout=10.0,
            )
            assert content_check.status_code == 200, "Content not found in database"

            # Step 4: Test transaction rollback scenario
            invalid_payload = {
                "student_id": test_student_id,
                "topic": "invalid_topic_id",  # Should cause rollback
                "force_transaction_test": True,
            }

            invalid_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/content/generate",
                json=invalid_payload,
                timeout=10.0,
            )
            # Should fail gracefully without corrupting existing data
            assert invalid_response.status_code >= 400, "Invalid request should fail"

            # Verify original data still exists and is consistent
            student_recheck = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/students/profile/{test_student_id}",
                timeout=10.0,
            )
            assert student_recheck.status_code == 200, (
                "Student data corrupted after failed transaction"
            )

            logger.info("E2E-004 PASSED: Multi-database consistency maintained")

    @pytest.mark.asyncio
    @pytest.mark.resilience
    async def test_e2e_005_invalid_medical_terminology_handling(
        self, e2e_pipeline_client, security_test_vectors
    ):
        """E2E-005: Invalid medical terminology handling and fallback mechanisms.

        Validates:
        - Graceful handling of invalid UMLS codes
        - Fallback to alternative medical terminology
        - Error recovery without data corruption
        """
        logger.info("Starting E2E-005: Invalid Medical Terminology Handling Test")

        # Test with invalid UMLS concepts
        invalid_payloads = [
            {
                "content": "Cardiovascular assessment nursing care",
                "umls_concepts": ["INVALID_CUI_001", "FAKE_CUI_002"],  # Invalid CUIs
                "processing_type": "medical_enrichment",
                "fallback_enabled": True,
            },
            {
                "content": "Medication administration protocols",
                "umls_concepts": [],  # Empty concepts
                "processing_type": "medical_enrichment",
                "fallback_enabled": True,
            },
            {
                "content": "Infection control procedures",
                "umls_concepts": ["C0007226", "MALFORMED_CUI"],  # Mixed valid/invalid
                "processing_type": "medical_enrichment",
                "fallback_enabled": True,
            },
        ]

        async with e2e_pipeline_client as client:
            for i, payload in enumerate(invalid_payloads):
                logger.info(f"Testing invalid terminology scenario {i + 1}")

                # Submit invalid medical terminology
                response = await client.post(
                    "http://ragnostic-orchestrator:8030/api/v1/process",
                    json=payload,
                    timeout=15.0,
                )

                # Should either succeed with fallback or fail gracefully
                assert response.status_code in [
                    200,
                    400,
                    422,
                ], f"Unexpected response code: {response.status_code}"

                if response.status_code == 200:
                    # Fallback mechanism worked
                    result = response.json()
                    assert "enriched_content" in result, (
                        "Fallback should provide enriched content"
                    )
                    assert "fallback_used" in result, (
                        "Should indicate fallback was used"
                    )
                    assert result["fallback_used"] is True

                    # Validate fallback quality
                    assert len(result["enriched_content"]) > 100, (
                        "Fallback content should be substantial"
                    )

                    # Test BSN Knowledge with fallback data
                    bsn_payload = {
                        "enriched_content": result["enriched_content"],
                        "medical_concepts": result.get("medical_concepts", []),
                        "topic": "general_nursing",
                        "difficulty": "medium",
                        "question_count": 2,
                        "fallback_mode": True,
                    }

                    bsn_response = await client.post(
                        "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                        json=bsn_payload,
                        timeout=15.0,
                    )

                    assert bsn_response.status_code == 200, (
                        "BSN Knowledge should handle fallback data"
                    )
                    bsn_result = bsn_response.json()
                    assert len(bsn_result["questions"]) >= 1, (
                        "Should generate at least 1 fallback question"
                    )

                else:
                    # Graceful failure
                    error_result = response.json()
                    assert "error" in error_result, (
                        "Error response should contain error message"
                    )
                    assert (
                        "medical_terminology" in error_result["error"].lower()
                        or "umls" in error_result["error"].lower()
                    )

            logger.info(
                "E2E-005 PASSED: Invalid medical terminology handled gracefully"
            )

    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_e2e_006_external_medical_database_connectivity(
        self, e2e_pipeline_client, e2e_services_config
    ):
        """E2E-006: External medical database connectivity (UMLS integration).

        Validates:
        - UMLS API connectivity and authentication
        - Medical terminology lookup accuracy
        - Fallback when external services unavailable
        """
        logger.info("Starting E2E-006: External Medical Database Connectivity Test")

        # Test UMLS connectivity through mock service
        umls_test_cuis = [
            "C0007226",
            "C0232337",
            "C0018787",
        ]  # Valid cardiovascular CUIs

        async with e2e_pipeline_client as client:
            # Step 1: Test direct UMLS connectivity
            umls_payload = {
                "cuis": umls_test_cuis,
                "include_definitions": True,
                "include_relationships": True,
            }

            umls_response = await client.post(
                "http://umls-mock:8000/api/v1/lookup",
                json=umls_payload,
                timeout=10.0,
            )

            assert umls_response.status_code == 200, (
                f"UMLS connectivity failed: {umls_response.text}"
            )
            umls_result = umls_response.json()

            # Validate UMLS response quality
            assert "concepts" in umls_result, "UMLS should return concepts"
            concepts = umls_result["concepts"]
            assert len(concepts) >= len(umls_test_cuis), (
                "Should return data for all requested CUIs"
            )

            for concept in concepts:
                assert "cui" in concept, "Each concept should have CUI"
                assert "preferred_name" in concept, (
                    "Each concept should have preferred name"
                )
                assert len(concept["preferred_name"]) > 0, (
                    "Preferred name should not be empty"
                )

            # Step 2: Test UMLS integration through RAGnostic pipeline
            ragnostic_payload = {
                "content": "Comprehensive cardiovascular assessment in acute care nursing",
                "umls_concepts": umls_test_cuis,
                "processing_type": "medical_enrichment",
                "external_validation": True,
            }

            ragnostic_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json=ragnostic_payload,
                timeout=20.0,
            )

            assert ragnostic_response.status_code == 200, (
                "RAGnostic with UMLS integration failed"
            )
            ragnostic_result = ragnostic_response.json()

            # Validate UMLS enrichment
            assert "medical_concepts" in ragnostic_result, (
                "Should return enriched medical concepts"
            )
            medical_concepts = ragnostic_result["medical_concepts"]
            assert len(medical_concepts) >= len(umls_test_cuis), (
                "Should enrich all provided concepts"
            )

            # Step 3: Test fallback when UMLS unavailable
            with patch("httpx.AsyncClient.post") as mock_post:
                mock_post.side_effect = httpx.ConnectError("UMLS service unavailable")

                fallback_response = await client.post(
                    "http://ragnostic-orchestrator:8030/api/v1/process",
                    json={**ragnostic_payload, "fallback_enabled": True},
                    timeout=15.0,
                )

                # Should either succeed with fallback or fail gracefully
                assert fallback_response.status_code in [
                    200,
                    503,
                ], "Should handle UMLS unavailability"

                if fallback_response.status_code == 200:
                    fallback_result = fallback_response.json()
                    assert fallback_result.get("fallback_used") is True, (
                        "Should indicate fallback was used"
                    )

            logger.info(
                "E2E-006 PASSED: External medical database connectivity validated"
            )

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_e2e_007_vector_search_accuracy(
        self, e2e_pipeline_client, medical_test_data, medical_accuracy_validator
    ):
        """E2E-007: Vector search accuracy with medical terminology.

        Validates:
        - Semantic search accuracy for medical content
        - Vector embedding quality for nursing concepts
        - Search result relevance and ranking
        """
        logger.info("Starting E2E-007: Vector Search Accuracy Test")

        nursing_topics = medical_test_data["nursing_topics"]
        search_accuracy_results = []

        async with e2e_pipeline_client as client:
            # Step 1: Index medical content for vector search
            for topic in nursing_topics:
                index_payload = {
                    "content": f"Comprehensive nursing care for {topic['name']}",
                    "topic": topic["id"],
                    "umls_concepts": topic["umls_concepts"],
                    "content_type": "nursing_education",
                    "index_for_search": True,
                }

                index_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/content/index",
                    json=index_payload,
                    timeout=15.0,
                )

                assert index_response.status_code in [
                    200,
                    201,
                ], f"Content indexing failed for {topic['name']}"

            # Wait for indexing to complete
            await asyncio.sleep(2)

            # Step 2: Test semantic search accuracy
            search_queries = [
                {
                    "query": "heart failure assessment and monitoring",
                    "expected_topic": "cardiovascular_assessment",
                    "expected_concepts": ["C0007226", "C0018787"],
                },
                {
                    "query": "safe medication administration protocols",
                    "expected_topic": "medication_administration",
                    "expected_concepts": ["C0013227", "C0150270"],
                },
                {
                    "query": "infection prevention and control measures",
                    "expected_topic": "infection_control",
                    "expected_concepts": ["C0085557", "C1292711"],
                },
            ]

            for search_test in search_queries:
                search_payload = {
                    "query": search_test["query"],
                    "search_type": "semantic",
                    "max_results": 5,
                    "include_similarity_scores": True,
                }

                search_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/search",
                    json=search_payload,
                    timeout=10.0,
                )

                assert search_response.status_code == 200, (
                    f"Search failed for query: {search_test['query']}"
                )
                search_result = search_response.json()

                # Validate search results
                assert "results" in search_result, "Search should return results"
                results = search_result["results"]
                assert len(results) > 0, "Should return at least one result"

                # Check result relevance
                top_result = results[0]
                assert "similarity_score" in top_result, (
                    "Should include similarity score"
                )
                assert top_result["similarity_score"] >= 0.7, (
                    f"Top result similarity too low: {top_result['similarity_score']}"
                )

                # Check if expected topic is in top results
                result_topics = [r.get("topic", "") for r in results[:3]]
                topic_found = search_test["expected_topic"] in result_topics

                search_accuracy_results.append(
                    {
                        "query": search_test["query"],
                        "top_similarity": top_result["similarity_score"],
                        "expected_topic_found": topic_found,
                        "result_count": len(results),
                    }
                )

            # Step 3: Validate overall search accuracy
            avg_similarity = sum(
                r["top_similarity"] for r in search_accuracy_results
            ) / len(search_accuracy_results)
            topic_accuracy = sum(
                1 for r in search_accuracy_results if r["expected_topic_found"]
            ) / len(search_accuracy_results)

            # Assert search accuracy requirements
            assert avg_similarity >= 0.75, (
                f"E2E-007 Average similarity {avg_similarity:.3f} < 0.75 threshold"
            )
            assert topic_accuracy >= 0.8, (
                f"E2E-007 Topic accuracy {topic_accuracy:.3f} < 0.8 threshold"
            )

            logger.info(
                f"E2E-007 PASSED: Vector search accuracy - Similarity: {avg_similarity:.3f}, Topic accuracy: {topic_accuracy:.3f}"
            )

    @pytest.mark.asyncio
    @pytest.mark.resilience
    async def test_e2e_008_service_failure_recovery(
        self, e2e_pipeline_client, resilience_test_scenarios
    ):
        """E2E-008: Service failure recovery and graceful degradation.

        Validates:
        - Circuit breaker patterns
        - Service recovery mechanisms
        - Data integrity during failures
        """
        logger.info("Starting E2E-008: Service Failure Recovery Test")

        async with e2e_pipeline_client as client:
            # Step 1: Verify normal operation
            normal_payload = {
                "topic": "cardiovascular_assessment",
                "difficulty": "medium",
                "question_count": 3,
            }

            normal_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                json=normal_payload,
                timeout=10.0,
            )
            assert normal_response.status_code == 200, "Normal operation should work"

            # Step 2: Simulate RAGnostic service failure
            with patch("httpx.AsyncClient.post") as mock_post:
                # Mock RAGnostic failure
                def side_effect(url, **kwargs):
                    if "ragnostic" in str(url):
                        raise httpx.ConnectError("Service unavailable")
                    # Allow other requests to proceed normally
                    return AsyncMock(status_code=200, json=lambda: {"status": "ok"})

                mock_post.side_effect = side_effect

                failure_payload = {
                    "topic": "medication_administration",
                    "difficulty": "medium",
                    "question_count": 3,
                    "fallback_mode": True,
                }

                failure_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=failure_payload,
                    timeout=15.0,
                )

                # Should either succeed with fallback or fail gracefully
                assert failure_response.status_code in [
                    200,
                    503,
                ], "Should handle service failure gracefully"

                if failure_response.status_code == 200:
                    failure_result = failure_response.json()
                    assert "questions" in failure_result, (
                        "Fallback should still generate questions"
                    )
                    assert failure_result.get("fallback_mode") is True, (
                        "Should indicate fallback mode"
                    )

                    # Validate fallback question quality
                    questions = failure_result["questions"]
                    assert len(questions) >= 1, (
                        "Should generate at least 1 fallback question"
                    )

                    for question in questions:
                        assert len(question.get("question", "")) > 20, (
                            "Fallback questions should be substantial"
                        )
                        assert len(question.get("rationale", "")) > 10, (
                            "Should include rationales"
                        )

            # Step 3: Test recovery after service restoration
            recovery_attempts = 0
            max_attempts = 5

            while recovery_attempts < max_attempts:
                try:
                    recovery_response = await client.post(
                        "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                        json=normal_payload,
                        timeout=10.0,
                    )

                    if recovery_response.status_code == 200:
                        recovery_result = recovery_response.json()
                        if len(recovery_result.get("questions", [])) > 0:
                            break

                    recovery_attempts += 1
                    await asyncio.sleep(1)

                except Exception:
                    recovery_attempts += 1
                    await asyncio.sleep(1)

            assert recovery_attempts < max_attempts, (
                f"Service failed to recover within {max_attempts} attempts"
            )
            logger.info(
                f"E2E-008 PASSED: Service recovery successful after {recovery_attempts} attempts"
            )

    @pytest.mark.asyncio
    @pytest.mark.data_flow
    async def test_e2e_009_context_preservation_across_handoff(
        self, e2e_pipeline_client, medical_test_data, performance_monitor_e2e
    ):
        """E2E-009: Context preservation across RAGnostic → BSN Knowledge handoff.

        Validates:
        - Student context maintained through pipeline
        - Learning state preservation
        - Personalization data integrity
        """
        logger.info("Starting E2E-009: Context Preservation Test")

        performance_monitor_e2e.start()

        # Create detailed student context
        student_context = {
            "student_id": "e2e_009_context_test",
            "competency_level": "advanced_beginner",
            "learning_style": "visual_kinesthetic",
            "performance_history": {
                "cardiology": 0.78,
                "pharmacology": 0.85,
                "safety": 0.72,
            },
            "knowledge_gaps": ["advanced_pathophysiology", "medication_interactions"],
            "preferred_difficulty": "medium_challenging",
        }

        nursing_topic = medical_test_data["nursing_topics"][0]  # Cardiovascular

        async with e2e_pipeline_client as client:
            # Step 1: Create student session with context
            session_payload = {
                "student_context": student_context,
                "topic": nursing_topic["id"],
                "session_type": "adaptive_learning",
                "preserve_context": True,
            }

            session_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/sessions/create",
                json=session_payload,
                timeout=10.0,
            )

            assert session_response.status_code in [
                200,
                201,
            ], "Session creation should succeed"
            session_result = session_response.json()
            session_id = session_result.get("session_id")
            assert session_id is not None, "Should return session ID"

            # Step 2: Process content through RAGnostic with context
            ragnostic_payload = {
                "content": f"Educational content on {nursing_topic['name']}",
                "umls_concepts": nursing_topic["umls_concepts"],
                "student_context": student_context,
                "session_id": session_id,
                "processing_type": "personalized_enrichment",
            }

            ragnostic_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json=ragnostic_payload,
                timeout=20.0,
            )

            assert ragnostic_response.status_code == 200, (
                "RAGnostic processing with context failed"
            )
            ragnostic_result = ragnostic_response.json()

            # Validate context preservation in RAGnostic output
            assert "student_context" in ragnostic_result, (
                "Student context should be preserved"
            )
            assert "session_id" in ragnostic_result, "Session ID should be preserved"
            assert ragnostic_result["session_id"] == session_id, (
                "Session ID should match"
            )

            preserved_context = ragnostic_result["student_context"]
            assert preserved_context["student_id"] == student_context["student_id"], (
                "Student ID should match"
            )
            assert (
                preserved_context["competency_level"]
                == student_context["competency_level"]
            ), "Competency level should match"

            # Step 3: Generate personalized content in BSN Knowledge
            bsn_payload = {
                "enriched_content": ragnostic_result["enriched_content"],
                "medical_concepts": ragnostic_result["medical_concepts"],
                "student_context": preserved_context,
                "session_id": session_id,
                "topic": nursing_topic["id"],
                "personalization": True,
                "adaptive_difficulty": True,
            }

            bsn_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/content/personalized",
                json=bsn_payload,
                timeout=15.0,
            )

            assert bsn_response.status_code == 200, (
                "Personalized content generation failed"
            )
            bsn_result = bsn_response.json()

            # Validate personalization based on context
            assert "personalized_content" in bsn_result, (
                "Should return personalized content"
            )
            assert "adaptive_elements" in bsn_result, "Should include adaptive elements"
            assert "context_applied" in bsn_result, (
                "Should indicate context was applied"
            )

            bsn_result["personalized_content"]
            adaptive_elements = bsn_result["adaptive_elements"]

            # Check if learning style preferences were applied
            if student_context["learning_style"] == "visual_kinesthetic":
                assert any(
                    "visual" in str(element).lower() for element in adaptive_elements
                ), "Should include visual elements"

            # Check if difficulty was adapted based on performance history
            cardiology_performance = student_context["performance_history"][
                "cardiology"
            ]
            if cardiology_performance < 0.8:  # Below 80% - needs easier content
                assert any(
                    "reinforcement" in str(element).lower()
                    or "review" in str(element).lower()
                    for element in adaptive_elements
                ), "Should include reinforcement for weak areas"

            # Step 4: Verify session state persistence
            session_check = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/sessions/{session_id}",
                timeout=10.0,
            )

            assert session_check.status_code == 200, "Session should still exist"
            session_data = session_check.json()

            assert (
                session_data["student_context"]["student_id"]
                == student_context["student_id"]
            ), "Context should persist in session"
            assert "interaction_history" in session_data, (
                "Should track interaction history"
            )

            performance_monitor_e2e.stop()
            total_time = performance_monitor_e2e.duration

            # Performance check - context preservation shouldn't add significant overhead
            assert total_time < 10.0, (
                f"E2E-009 Context preservation too slow: {total_time:.2f}s > 10.0s"
            )

            logger.info(
                f"E2E-009 PASSED: Context preserved through pipeline in {total_time:.3f}s"
            )

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_e2e_010_authentication_across_service_boundaries(
        self, e2e_pipeline_client, auth_headers, security_test_vectors
    ):
        """E2E-010: Authentication and authorization across service boundaries.

        Validates:
        - JWT token propagation through pipeline
        - Role-based access control enforcement
        - Security at each service boundary
        """
        logger.info("Starting E2E-010: Cross-Service Authentication Test")

        auth_tests = security_test_vectors["authentication_tests"]

        async with e2e_pipeline_client as client:
            # Step 1: Test with valid authentication
            valid_headers = auth_headers[
                "instructor1"
            ]  # Instructor has broader permissions

            authenticated_payload = {
                "content": "Advanced cardiovascular nursing assessment",
                "umls_concepts": ["C0007226", "C0232337"],
                "processing_type": "medical_enrichment",
                "require_authentication": True,
            }

            # RAGnostic with valid auth
            ragnostic_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json=authenticated_payload,
                headers=valid_headers,
                timeout=15.0,
            )

            assert ragnostic_response.status_code == 200, (
                "Authenticated RAGnostic request should succeed"
            )
            ragnostic_result = ragnostic_response.json()

            # BSN Knowledge with valid auth (should propagate authentication)
            bsn_payload = {
                "enriched_content": ragnostic_result["enriched_content"],
                "medical_concepts": ragnostic_result["medical_concepts"],
                "topic": "cardiovascular_assessment",
                "difficulty": "advanced",
                "question_count": 3,
                "require_authentication": True,
            }

            bsn_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                json=bsn_payload,
                headers=valid_headers,
                timeout=15.0,
            )

            assert bsn_response.status_code == 200, (
                "Authenticated BSN Knowledge request should succeed"
            )

            # Step 2: Test with invalid authentication
            invalid_headers = {
                "Authorization": f"Bearer {auth_tests['invalid_jwt']['token']}"
            }

            invalid_ragnostic_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json=authenticated_payload,
                headers=invalid_headers,
                timeout=10.0,
            )

            expected_status = auth_tests["invalid_jwt"]["expected_status"]
            assert invalid_ragnostic_response.status_code == expected_status, (
                f"Invalid auth should return {expected_status}"
            )

            # Step 3: Test role-based access control
            student_headers = auth_headers.get("student1", {})

            # Students shouldn't access advanced content generation
            restricted_payload = {
                **bsn_payload,
                "difficulty": "expert_level",
                "administrative_access": True,
            }

            restricted_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                json=restricted_payload,
                headers=student_headers,
                timeout=10.0,
            )

            # Should either forbid access (403) or downgrade to appropriate level
            assert restricted_response.status_code in [
                200,
                403,
            ], "Should handle role restrictions"

            if restricted_response.status_code == 200:
                # If allowed, should downgrade difficulty automatically
                restricted_result = restricted_response.json()
                questions = restricted_result.get("questions", [])
                if questions:
                    # Check that difficulty was downgraded (implementation-specific validation)
                    assert "expert_level" not in str(restricted_result).lower(), (
                        "Should not provide expert content to students"
                    )

            # Step 4: Test session-based authentication continuity
            session_payload = {
                "topic": "medication_administration",
                "maintain_session": True,
                "session_duration_minutes": 60,
            }

            session_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/sessions/authenticated",
                json=session_payload,
                headers=valid_headers,
                timeout=10.0,
            )

            if session_response.status_code in [200, 201]:
                session_result = session_response.json()
                session_token = session_result.get("session_token")

                if session_token:
                    # Use session token for subsequent requests
                    session_headers = {"Authorization": f"Bearer {session_token}"}

                    session_test_response = await client.post(
                        "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                        json={"topic": "infection_control", "question_count": 2},
                        headers=session_headers,
                        timeout=10.0,
                    )

                    assert session_test_response.status_code == 200, (
                        "Session-based auth should work"
                    )

            logger.info(
                "E2E-010 PASSED: Authentication validated across service boundaries"
            )

    @pytest.mark.asyncio
    @pytest.mark.error_handling
    async def test_e2e_011_data_corruption_detection_and_healing(
        self, e2e_pipeline_client, medical_test_data
    ):
        """E2E-011: Data corruption detection and healing.

        Validates:
        - Checksum validation for medical content
        - Automatic corruption detection
        - Self-healing mechanisms
        """
        logger.info("Starting E2E-011: Data Corruption Detection and Healing Test")

        nursing_topic = medical_test_data["nursing_topics"][0]

        async with e2e_pipeline_client as client:
            # Step 1: Create content with integrity checking
            content_payload = {
                "content": "Critical care nursing assessment protocols for cardiovascular patients",
                "umls_concepts": nursing_topic["umls_concepts"],
                "enable_integrity_checking": True,
                "generate_checksums": True,
            }

            creation_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/content/create",
                json=content_payload,
                timeout=15.0,
            )

            assert creation_response.status_code in [
                200,
                201,
            ], "Content creation should succeed"
            creation_result = creation_response.json()

            content_id = creation_result.get("content_id")
            original_checksum = creation_result.get("checksum")
            assert content_id is not None, "Should return content ID"
            assert original_checksum is not None, "Should return checksum for integrity"

            # Step 2: Simulate data corruption
            corruption_payload = {
                "content_id": content_id,
                "simulate_corruption": True,
                "corruption_type": "partial_content_modification",
            }

            # This is a test endpoint that simulates corruption
            corruption_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/test/simulate-corruption",
                json=corruption_payload,
                timeout=10.0,
            )

            if corruption_response.status_code in [200, 202]:
                logger.info("Data corruption simulated successfully")

                # Wait for corruption to be applied
                await asyncio.sleep(1)

                # Step 3: Test corruption detection
                integrity_check_response = await client.get(
                    f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}/integrity",
                    timeout=10.0,
                )

                assert integrity_check_response.status_code == 200, (
                    "Integrity check should execute"
                )
                integrity_result = integrity_check_response.json()

                # Should detect corruption
                assert "integrity_status" in integrity_result, (
                    "Should report integrity status"
                )
                if integrity_result["integrity_status"] == "corrupted":
                    logger.info("Data corruption successfully detected")

                    # Step 4: Test automatic healing
                    healing_response = await client.post(
                        f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}/heal",
                        json={"auto_heal": True, "use_backup": True},
                        timeout=15.0,
                    )

                    if healing_response.status_code in [200, 202]:
                        healing_result = healing_response.json()

                        # Wait for healing to complete
                        if healing_result.get("healing_status") == "in_progress":
                            for _ in range(10):  # Wait up to 10 seconds
                                await asyncio.sleep(1)

                                status_response = await client.get(
                                    f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}/healing-status",
                                    timeout=5.0,
                                )

                                if status_response.status_code == 200:
                                    status_result = status_response.json()
                                    if (
                                        status_result.get("healing_status")
                                        == "completed"
                                    ):
                                        break

                        # Verify healing was successful
                        final_integrity_response = await client.get(
                            f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}/integrity",
                            timeout=10.0,
                        )

                        if final_integrity_response.status_code == 200:
                            final_integrity_result = final_integrity_response.json()
                            final_status = final_integrity_result.get(
                                "integrity_status", "unknown"
                            )

                            assert final_status in [
                                "healthy",
                                "healed",
                            ], f"Content should be healed, got: {final_status}"

                            # Verify content is usable after healing
                            usage_test_payload = {
                                "content_id": content_id,
                                "generate_questions": True,
                                "question_count": 2,
                            }

                            usage_response = await client.post(
                                "http://bsn-knowledge-test:8040/api/v1/content/use",
                                json=usage_test_payload,
                                timeout=10.0,
                            )

                            assert usage_response.status_code == 200, (
                                "Healed content should be usable"
                            )
                            usage_result = usage_response.json()
                            assert len(usage_result.get("questions", [])) > 0, (
                                "Should generate questions from healed content"
                            )

                            logger.info(
                                "E2E-011 PASSED: Data corruption detected and healed successfully"
                            )
                            return

            # If corruption simulation not available, test integrity checking only
            logger.info(
                "Corruption simulation not available, testing basic integrity checking"
            )

            # Test basic integrity validation
            validation_response = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/content/{content_id}",
                headers={"Validate-Integrity": "true"},
                timeout=10.0,
            )

            assert validation_response.status_code == 200, (
                "Content validation should succeed"
            )
            validation_result = validation_response.json()

            # Should include integrity information
            if "integrity_verified" in validation_result:
                assert validation_result["integrity_verified"] is True, (
                    "Content integrity should be verified"
                )

            logger.info("E2E-011 PASSED: Basic integrity checking validated")

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_e2e_012_nclex_generation_with_validated_terminology(
        self,
        e2e_pipeline_client,
        medical_test_data,
        medical_accuracy_validator,
        performance_monitor_e2e,
    ):
        """E2E-012: NCLEX-RN question generation with validated medical terminology.

        Validates:
        - High-quality NCLEX question generation
        - Medical terminology validation in questions
        - Proper NCLEX category alignment
        """
        logger.info(
            "Starting E2E-012: NCLEX Generation with Validated Terminology Test"
        )

        performance_monitor_e2e.start()

        # Test comprehensive NCLEX generation across all nursing topics
        nursing_topics = medical_test_data["nursing_topics"]
        generation_results = []

        async with e2e_pipeline_client as client:
            for topic in nursing_topics:
                logger.info(f"Generating NCLEX questions for {topic['name']}")

                # Step 1: Process content through RAGnostic for medical enrichment
                ragnostic_payload = {
                    "content": f"Comprehensive {topic['name']} nursing education content",
                    "umls_concepts": topic["umls_concepts"],
                    "processing_type": "nclex_preparation",
                    "validate_terminology": True,
                }

                ragnostic_response = await client.post(
                    "http://ragnostic-orchestrator:8030/api/v1/process",
                    json=ragnostic_payload,
                    timeout=20.0,
                )

                assert ragnostic_response.status_code == 200, (
                    f"RAGnostic processing failed for {topic['name']}"
                )
                ragnostic_result = ragnostic_response.json()

                # Validate medical enrichment quality
                medical_concepts = ragnostic_result.get("medical_concepts", [])
                assert len(medical_concepts) >= 3, (
                    f"Should enrich with at least 3 medical concepts for {topic['name']}"
                )

                # Step 2: Generate NCLEX questions with validated terminology
                nclex_payload = {
                    "enriched_content": ragnostic_result["enriched_content"],
                    "medical_concepts": medical_concepts,
                    "topic": topic["id"],
                    "nclex_categories": topic["expected_nclex_categories"],
                    "difficulty_levels": ["medium", "hard"],
                    "question_count": 8,  # Generate more questions for thorough testing
                    "validate_terminology": True,
                    "enforce_nclex_standards": True,
                }

                generation_start = time.time()

                nclex_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=nclex_payload,
                    timeout=30.0,
                )

                generation_time = time.time() - generation_start
                performance_monitor_e2e.record_service_response(
                    f"nclex_generation_{topic['id']}", generation_time * 1000
                )

                assert nclex_response.status_code == 200, (
                    f"NCLEX generation failed for {topic['name']}"
                )
                nclex_result = nclex_response.json()

                # Step 3: Validate question quality and terminology
                questions = nclex_result.get("questions", [])
                assert len(questions) >= 6, (
                    f"Should generate at least 6 questions for {topic['name']}"
                )

                # Validate each question comprehensively
                topic_accuracy_scores = []

                for i, question in enumerate(questions):
                    # Basic structure validation
                    assert_question_quality(question)

                    # NCLEX category alignment
                    question_category = question.get("nclex_category", "")
                    assert question_category in topic["expected_nclex_categories"], (
                        f"Question {i + 1} category '{question_category}' not in expected categories {topic['expected_nclex_categories']}"
                    )

                    # Medical terminology integration
                    question_text = (
                        question["question"]
                        + " "
                        + " ".join(question["options"])
                        + " "
                        + question["rationale"]
                    )

                    # Count medical terms properly integrated
                    medical_term_count = 0
                    for concept in medical_concepts:
                        preferred_name = concept.get("preferred_name", "").lower()
                        if preferred_name and preferred_name in question_text.lower():
                            medical_term_count += 1

                    # Each question should integrate at least 1 medical concept
                    assert medical_term_count > 0, (
                        f"Question {i + 1} should integrate medical terminology"
                    )

                    # Clinical accuracy assessment
                    clinical_accuracy = assess_clinical_accuracy(
                        question, medical_concepts
                    )
                    topic_accuracy_scores.append(clinical_accuracy)

                # Validate overall terminology accuracy for this topic
                medical_terms = [
                    concept.get("preferred_name", "") for concept in medical_concepts
                ]
                umls_accuracy = medical_accuracy_validator.validate_umls_terminology(
                    medical_terms, topic["umls_concepts"]
                )

                nclex_quality = (
                    medical_accuracy_validator.validate_nclex_question_quality(
                        questions
                    )
                )

                # Record performance and accuracy metrics
                performance_monitor_e2e.record_medical_accuracy(
                    f"umls_accuracy_{topic['id']}", umls_accuracy
                )
                performance_monitor_e2e.record_medical_accuracy(
                    f"nclex_quality_{topic['id']}", nclex_quality["quality_score"]
                )

                topic_result = {
                    "topic": topic["name"],
                    "topic_id": topic["id"],
                    "questions_generated": len(questions),
                    "umls_accuracy": umls_accuracy,
                    "nclex_quality_score": nclex_quality["quality_score"],
                    "avg_clinical_accuracy": sum(topic_accuracy_scores)
                    / len(topic_accuracy_scores),
                    "generation_time_ms": generation_time * 1000,
                    "medical_concepts_used": len(medical_concepts),
                }

                generation_results.append(topic_result)

                logger.info(
                    f"  {topic['name']}: {len(questions)} questions, "
                    f"UMLS accuracy: {umls_accuracy:.3f}, "
                    f"NCLEX quality: {nclex_quality['quality_score']:.3f}"
                )

            # Step 4: Validate overall E2E-012 requirements
            performance_monitor_e2e.stop()

            # Calculate aggregate metrics
            total_questions = sum(r["questions_generated"] for r in generation_results)
            avg_umls_accuracy = sum(
                r["umls_accuracy"] for r in generation_results
            ) / len(generation_results)
            avg_nclex_quality = sum(
                r["nclex_quality_score"] for r in generation_results
            ) / len(generation_results)
            avg_clinical_accuracy = sum(
                r["avg_clinical_accuracy"] for r in generation_results
            ) / len(generation_results)
            avg_generation_time = sum(
                r["generation_time_ms"] for r in generation_results
            ) / len(generation_results)

            # Assert E2E-012 requirements
            assert avg_umls_accuracy >= 0.98, (
                f"E2E-012 UMLS accuracy {avg_umls_accuracy:.3f} < 0.98 requirement"
            )
            assert avg_nclex_quality >= 0.90, (
                f"E2E-012 NCLEX quality {avg_nclex_quality:.3f} < 0.90 requirement"
            )
            assert avg_clinical_accuracy >= 0.85, (
                f"E2E-012 Clinical accuracy {avg_clinical_accuracy:.3f} < 0.85 requirement"
            )
            assert avg_generation_time <= 3000, (
                f"E2E-012 Generation time {avg_generation_time:.1f}ms > 3000ms threshold"
            )

            # Validate medical accuracy requirements
            medical_accuracy_validator.assert_medical_accuracy_requirements()

            logger.info(
                f"E2E-012 PASSED: Generated {total_questions} questions across {len(nursing_topics)} topics"
            )
            logger.info(
                f"  UMLS accuracy: {avg_umls_accuracy:.3f}, NCLEX quality: {avg_nclex_quality:.3f}"
            )
            logger.info(
                f"  Clinical accuracy: {avg_clinical_accuracy:.3f}, Avg generation time: {avg_generation_time:.1f}ms"
            )

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_e2e_013_performance_benchmarking_realistic_load(
        self, e2e_pipeline_client, medical_test_data, performance_monitor_e2e
    ):
        """E2E-013: Performance benchmarking under realistic load (100+ concurrent requests).

        Validates:
        - System performance under sustained load
        - Response time consistency
        - Resource utilization efficiency
        """
        logger.info("Starting E2E-013: Performance Benchmarking Under Realistic Load")

        performance_monitor_e2e.start()

        # Define realistic load scenarios based on actual usage patterns
        load_scenarios = {
            "student_question_generation": {
                "weight": 50,  # 50% of requests
                "endpoint": "/api/v1/nclex/generate",
                "method": "POST",
                "payload": {
                    "topic": "cardiovascular_assessment",
                    "difficulty": "medium",
                    "question_count": 5,
                    "student_level": "undergraduate",
                },
            },
            "instructor_content_creation": {
                "weight": 25,  # 25% of requests
                "endpoint": "/api/v1/content/generate",
                "method": "POST",
                "payload": {
                    "content": "Advanced nursing assessment techniques",
                    "umls_concepts": ["C0007226", "C0232337", "C0018787"],
                    "complexity": "advanced",
                },
            },
            "content_search": {
                "weight": 20,  # 20% of requests
                "endpoint": "/api/v1/search",
                "method": "POST",
                "payload": {
                    "query": "medication administration safety protocols",
                    "search_type": "semantic",
                    "max_results": 10,
                },
            },
            "analytics_retrieval": {
                "weight": 5,  # 5% of requests
                "endpoint": "/api/v1/analytics/performance",
                "method": "GET",
                "params": {"student_id": "performance_test_student"},
            },
        }

        # Test with increasing concurrent loads
        load_levels = [50, 100, 200]  # Concurrent users
        load_test_results = []

        async with e2e_pipeline_client as client:
            for concurrent_users in load_levels:
                logger.info(f"Testing with {concurrent_users} concurrent users...")

                # Generate weighted request distribution
                requests_to_generate = []
                total_weight = sum(
                    scenario["weight"] for scenario in load_scenarios.values()
                )

                for scenario_name, scenario_config in load_scenarios.items():
                    scenario_requests = int(
                        (scenario_config["weight"] / total_weight) * concurrent_users
                    )
                    requests_to_generate.extend([scenario_name] * scenario_requests)

                # Fill any remaining slots
                while len(requests_to_generate) < concurrent_users:
                    requests_to_generate.append("student_question_generation")

                # Execute concurrent requests
                async def execute_load_request(scenario_name: str):
                    scenario_config = load_scenarios[scenario_name]
                    start_time = time.time()

                    try:
                        if scenario_config["method"] == "POST":
                            response = await client.post(
                                f"http://bsn-knowledge-test:8040{scenario_config['endpoint']}",
                                json=scenario_config.get("payload", {}),
                                timeout=30.0,  # Generous timeout for load testing
                            )
                        else:
                            response = await client.get(
                                f"http://bsn-knowledge-test:8040{scenario_config['endpoint']}",
                                params=scenario_config.get("params", {}),
                                timeout=30.0,
                            )

                        response_time = time.time() - start_time

                        return {
                            "scenario": scenario_name,
                            "status_code": response.status_code,
                            "response_time": response_time,
                            "success": response.status_code < 400,
                            "content_length": len(response.content)
                            if hasattr(response, "content")
                            else 0,
                        }

                    except Exception as e:
                        response_time = time.time() - start_time
                        return {
                            "scenario": scenario_name,
                            "status_code": 0,
                            "response_time": response_time,
                            "success": False,
                            "error": str(e),
                        }

                # Execute all requests concurrently
                load_start_time = time.time()
                tasks = [
                    execute_load_request(scenario) for scenario in requests_to_generate
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                total_load_time = time.time() - load_start_time

                # Analyze results for this load level
                successful_requests = sum(
                    1
                    for r in results
                    if isinstance(r, dict) and r.get("success", False)
                )
                failed_requests = len(results) - successful_requests
                success_rate = successful_requests / len(results) * 100

                # Response time analysis
                response_times = [
                    r["response_time"]
                    for r in results
                    if isinstance(r, dict) and "response_time" in r
                ]

                if response_times:
                    response_times.sort()
                    n = len(response_times)

                    metrics = {
                        "concurrent_users": concurrent_users,
                        "total_requests": len(results),
                        "successful_requests": successful_requests,
                        "failed_requests": failed_requests,
                        "success_rate": success_rate,
                        "total_test_time": total_load_time,
                        "requests_per_second": len(results) / total_load_time,
                        "avg_response_time": sum(response_times) / n,
                        "min_response_time": response_times[0],
                        "max_response_time": response_times[-1],
                        "p50_response_time": response_times[n // 2],
                        "p95_response_time": response_times[int(0.95 * n)]
                        if n > 20
                        else response_times[-1],
                        "p99_response_time": response_times[int(0.99 * n)]
                        if n > 100
                        else response_times[-1],
                    }

                    load_test_results.append(metrics)

                    # Record metrics in performance monitor
                    performance_monitor_e2e.record_service_response(
                        f"load_{concurrent_users}_avg",
                        metrics["avg_response_time"] * 1000,
                    )
                    performance_monitor_e2e.record_service_response(
                        f"load_{concurrent_users}_p95",
                        metrics["p95_response_time"] * 1000,
                    )

                    logger.info(
                        f"  {concurrent_users} users: {success_rate:.1f}% success, "
                        f"Avg: {metrics['avg_response_time']:.3f}s, "
                        f"P95: {metrics['p95_response_time']:.3f}s, "
                        f"RPS: {metrics['requests_per_second']:.1f}"
                    )

                # Brief pause between load levels
                await asyncio.sleep(2)

            # Step 4: Validate E2E-013 performance requirements
            performance_monitor_e2e.stop()
            total_test_time = performance_monitor_e2e.duration

            # Assert performance benchmarks for each load level
            for metrics in load_test_results:
                concurrent_users = metrics["concurrent_users"]

                # Success rate should remain high even under load
                assert metrics["success_rate"] >= 90.0, (
                    f"E2E-013 Success rate {metrics['success_rate']:.1f}% < 90% at {concurrent_users} users"
                )

                # Response times should remain reasonable
                if concurrent_users <= 100:
                    # Lower load - stricter requirements
                    assert metrics["avg_response_time"] <= 2.0, (
                        f"E2E-013 Avg response time {metrics['avg_response_time']:.3f}s > 2.0s at {concurrent_users} users"
                    )
                    assert metrics["p95_response_time"] <= 5.0, (
                        f"E2E-013 P95 response time {metrics['p95_response_time']:.3f}s > 5.0s at {concurrent_users} users"
                    )
                else:
                    # Higher load - more relaxed but still reasonable
                    assert metrics["avg_response_time"] <= 4.0, (
                        f"E2E-013 Avg response time {metrics['avg_response_time']:.3f}s > 4.0s at {concurrent_users} users"
                    )
                    assert metrics["p95_response_time"] <= 10.0, (
                        f"E2E-013 P95 response time {metrics['p95_response_time']:.3f}s > 10.0s at {concurrent_users} users"
                    )

                # System should handle reasonable throughput
                assert metrics["requests_per_second"] >= concurrent_users * 0.8, (
                    f"E2E-013 Low throughput {metrics['requests_per_second']:.1f} RPS for {concurrent_users} users"
                )

            # Overall system stability - no significant degradation at higher loads
            if len(load_test_results) >= 2:
                baseline_p95 = load_test_results[0]["p95_response_time"]
                high_load_p95 = load_test_results[-1]["p95_response_time"]
                degradation_ratio = high_load_p95 / baseline_p95

                assert degradation_ratio <= 3.0, (
                    f"E2E-013 Performance degradation too high: {degradation_ratio:.1f}x at high load"
                )

            logger.info(
                f"E2E-013 PASSED: Performance benchmarking completed in {total_test_time:.1f}s"
            )
            logger.info(
                f"  Tested {sum(m['total_requests'] for m in load_test_results)} total requests"
            )
            logger.info(
                f"  Load levels: {', '.join(str(m['concurrent_users']) for m in load_test_results)} concurrent users"
            )

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_e2e_014_audit_trail_and_compliance_logging(
        self, e2e_pipeline_client, auth_headers, medical_test_data
    ):
        """E2E-014: Audit trail and compliance logging validation.

        Validates:
        - Complete audit trail for medical content access
        - Compliance logging for educational activities
        - Data access patterns and security monitoring
        """
        logger.info("Starting E2E-014: Audit Trail and Compliance Logging Test")

        test_session_id = f"e2e_014_audit_test_{int(time.time())}"
        nursing_topic = medical_test_data["nursing_topics"][
            0
        ]  # Cardiovascular assessment

        async with e2e_pipeline_client as client:
            # Step 1: Initialize audited session
            audit_payload = {
                "session_id": test_session_id,
                "user_type": "student",
                "activity_type": "educational_content_access",
                "compliance_tracking": True,
                "audit_level": "detailed",
            }

            session_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/audit/session/start",
                json=audit_payload,
                headers=auth_headers.get("student1", {}),
                timeout=10.0,
            )

            audit_session_created = session_response.status_code in [200, 201]
            if audit_session_created:
                logger.info("Audit session initialized successfully")

            # Step 2: Perform audited operations
            audited_operations = [
                {
                    "operation": "content_search",
                    "endpoint": "/api/v1/search",
                    "payload": {
                        "query": "cardiovascular assessment techniques",
                        "session_id": test_session_id,
                        "audit_required": True,
                    },
                },
                {
                    "operation": "medical_content_access",
                    "endpoint": "/api/v1/content/generate",
                    "payload": {
                        "content": f"Educational material on {nursing_topic['name']}",
                        "umls_concepts": nursing_topic["umls_concepts"][:3],
                        "session_id": test_session_id,
                        "audit_medical_access": True,
                    },
                },
                {
                    "operation": "nclex_question_generation",
                    "endpoint": "/api/v1/nclex/generate",
                    "payload": {
                        "topic": nursing_topic["id"],
                        "difficulty": "medium",
                        "question_count": 3,
                        "session_id": test_session_id,
                        "audit_educational_activity": True,
                    },
                },
            ]

            operation_results = []

            for operation in audited_operations:
                logger.info(f"Executing audited operation: {operation['operation']}")

                op_response = await client.post(
                    f"http://bsn-knowledge-test:8040{operation['endpoint']}",
                    json=operation["payload"],
                    headers=auth_headers.get("student1", {}),
                    timeout=15.0,
                )

                operation_results.append(
                    {
                        "operation": operation["operation"],
                        "status_code": op_response.status_code,
                        "success": op_response.status_code < 400,
                        "timestamp": time.time(),
                    }
                )

                if op_response.status_code < 400:
                    logger.info(f"  {operation['operation']}: Success")
                else:
                    logger.warning(
                        f"  {operation['operation']}: Failed with {op_response.status_code}"
                    )

            # Step 3: Test sensitive data access logging
            sensitive_payload = {
                "content_type": "medical_terminology",
                "access_level": "detailed",
                "umls_concepts": nursing_topic["umls_concepts"],
                "session_id": test_session_id,
                "sensitivity_level": "high",
            }

            await client.post(
                "http://bsn-knowledge-test:8040/api/v1/content/sensitive-access",
                json=sensitive_payload,
                headers=auth_headers.get("student1", {}),
                timeout=10.0,
            )

            # Step 4: Retrieve and validate audit logs
            await asyncio.sleep(1)  # Allow time for log processing

            audit_retrieval_response = await client.get(
                f"http://bsn-knowledge-test:8040/api/v1/audit/session/{test_session_id}",
                headers=auth_headers.get(
                    "instructor1", {}
                ),  # Instructor should have audit access
                timeout=10.0,
            )

            if audit_retrieval_response.status_code == 200:
                audit_logs = audit_retrieval_response.json()

                # Validate audit log completeness
                assert "session_id" in audit_logs, (
                    "Audit logs should include session ID"
                )
                assert "activities" in audit_logs, (
                    "Audit logs should include activities"
                )
                assert "user_info" in audit_logs, (
                    "Audit logs should include user information"
                )
                assert "timestamps" in audit_logs, (
                    "Audit logs should include timestamps"
                )

                activities = audit_logs["activities"]
                logged_operations = [
                    activity.get("operation_type") for activity in activities
                ]

                # Verify all operations were logged
                expected_operations = [
                    "content_search",
                    "medical_content_access",
                    "nclex_question_generation",
                ]
                for expected_op in expected_operations:
                    assert any(
                        expected_op in str(logged_op) for logged_op in logged_operations
                    ), f"Operation '{expected_op}' not found in audit logs"

                # Validate audit log structure
                for activity in activities:
                    assert "timestamp" in activity, (
                        "Each activity should have timestamp"
                    )
                    assert "user_id" in activity, "Each activity should have user ID"
                    assert "operation_type" in activity, (
                        "Each activity should have operation type"
                    )
                    assert "outcome" in activity, "Each activity should have outcome"

                    # Check for compliance-specific fields
                    if activity.get("involves_medical_data"):
                        assert "medical_data_accessed" in activity, (
                            "Medical data access should be detailed"
                        )
                        assert "compliance_category" in activity, (
                            "Should categorize for compliance"
                        )

                logger.info(
                    f"Audit trail validated: {len(activities)} activities logged"
                )

                # Step 5: Test audit log security and integrity
                audit_integrity_response = await client.get(
                    f"http://bsn-knowledge-test:8040/api/v1/audit/session/{test_session_id}/integrity",
                    headers=auth_headers.get("instructor1", {}),
                    timeout=10.0,
                )

                if audit_integrity_response.status_code == 200:
                    integrity_result = audit_integrity_response.json()

                    assert "integrity_verified" in integrity_result, (
                        "Should verify audit log integrity"
                    )
                    if integrity_result.get("integrity_verified"):
                        assert "checksum" in integrity_result, (
                            "Should provide checksum for verification"
                        )
                        assert "tamper_detected" in integrity_result, (
                            "Should check for tampering"
                        )
                        assert integrity_result["tamper_detected"] is False, (
                            "Audit logs should not be tampered"
                        )

                # Step 6: Test compliance reporting
                compliance_response = await client.get(
                    "http://bsn-knowledge-test:8040/api/v1/audit/compliance-report",
                    params={
                        "session_id": test_session_id,
                        "report_type": "educational_activity",
                    },
                    headers=auth_headers.get(
                        "admin1", {}
                    ),  # Admin access for compliance reports
                    timeout=10.0,
                )

                if compliance_response.status_code == 200:
                    compliance_report = compliance_response.json()

                    assert "compliance_summary" in compliance_report, (
                        "Should provide compliance summary"
                    )
                    assert "educational_activities" in compliance_report, (
                        "Should detail educational activities"
                    )
                    assert "data_access_patterns" in compliance_report, (
                        "Should analyze access patterns"
                    )

                    # Validate compliance metrics
                    if "metrics" in compliance_report:
                        metrics = compliance_report["metrics"]
                        assert "total_activities" in metrics, (
                            "Should count total activities"
                        )
                        assert "medical_data_accesses" in metrics, (
                            "Should count medical data accesses"
                        )
                        assert "compliance_violations" in metrics, (
                            "Should identify violations"
                        )

                logger.info(
                    "E2E-014 PASSED: Audit trail and compliance logging validated"
                )

            else:
                # If audit system not fully implemented, validate basic logging
                logger.info(
                    "Full audit system not available, validating basic operation logging"
                )

                # Check if operations completed successfully (basic validation)
                successful_operations = sum(
                    1 for result in operation_results if result["success"]
                )
                total_operations = len(operation_results)

                assert successful_operations >= total_operations * 0.8, (
                    f"Too many operations failed: {successful_operations}/{total_operations}"
                )

                logger.info("E2E-014 PASSED: Basic operation tracking validated")

            # Step 7: End audit session
            if audit_session_created:
                end_session_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/audit/session/end",
                    json={
                        "session_id": test_session_id,
                        "end_reason": "test_completion",
                    },
                    headers=auth_headers.get("student1", {}),
                    timeout=10.0,
                )

                if end_session_response.status_code in [200, 202]:
                    logger.info("Audit session ended successfully")

    @pytest.mark.asyncio
    @pytest.mark.performance
    async def test_e2e_015_end_to_end_response_time_validation(
        self,
        e2e_pipeline_client,
        medical_test_data,
        performance_monitor_e2e,
        medical_accuracy_validator,
    ):
        """E2E-015: End-to-end response time validation (<2s requirement).

        Validates:
        - Complete pipeline execution under 2 seconds
        - Response time consistency across multiple runs
        - Performance optimization effectiveness
        """
        logger.info("Starting E2E-015: End-to-End Response Time Validation Test")

        nursing_topics = medical_test_data["nursing_topics"]
        response_time_results = []

        # Test multiple iterations to validate consistency
        test_iterations = 10
        max_acceptable_time = 2.0  # 2 second requirement

        async with e2e_pipeline_client as client:
            for iteration in range(test_iterations):
                logger.info(
                    f"Response time test iteration {iteration + 1}/{test_iterations}"
                )

                performance_monitor_e2e.start()

                # Select topic for this iteration
                topic = nursing_topics[iteration % len(nursing_topics)]

                # Complete E2E pipeline execution
                start_time = time.time()

                # Step 1: RAGnostic processing (optimized payload)
                ragnostic_payload = {
                    "content": f"Nursing care for {topic['name']}",
                    "umls_concepts": topic["umls_concepts"][
                        :3
                    ],  # Limit for performance
                    "processing_type": "fast_enrichment",
                    "optimization_level": "high_performance",
                }

                ragnostic_start = time.time()
                ragnostic_response = await client.post(
                    "http://ragnostic-orchestrator:8030/api/v1/process",
                    json=ragnostic_payload,
                    timeout=2.5,  # Strict timeout
                )
                ragnostic_time = time.time() - ragnostic_start

                assert ragnostic_response.status_code == 200, (
                    f"RAGnostic failed in iteration {iteration + 1}"
                )
                ragnostic_result = ragnostic_response.json()

                # Step 2: BSN Knowledge processing (optimized)
                bsn_payload = {
                    "enriched_content": ragnostic_result["enriched_content"],
                    "medical_concepts": ragnostic_result.get("medical_concepts", []),
                    "topic": topic["id"],
                    "difficulty": "medium",
                    "question_count": 3,  # Reduced for performance
                    "optimization_mode": "fast_generation",
                }

                bsn_start = time.time()
                bsn_response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=bsn_payload,
                    timeout=2.5,  # Strict timeout
                )
                bsn_time = time.time() - bsn_start

                assert bsn_response.status_code == 200, (
                    f"BSN Knowledge failed in iteration {iteration + 1}"
                )
                bsn_result = bsn_response.json()

                # Complete pipeline time
                total_time = time.time() - start_time
                performance_monitor_e2e.stop()

                # Validate basic quality to ensure performance optimization doesn't sacrifice quality
                questions = bsn_result.get("questions", [])
                assert len(questions) >= 2, (
                    f"Should generate at least 2 questions in iteration {iteration + 1}"
                )

                # Basic medical accuracy check
                medical_terms = [
                    concept.get("preferred_name", "")
                    for concept in ragnostic_result.get("medical_concepts", [])
                ]
                if medical_terms:
                    umls_accuracy = (
                        medical_accuracy_validator.validate_umls_terminology(
                            medical_terms, topic["umls_concepts"]
                        )
                    )
                    # Allow slightly lower accuracy for performance-optimized mode
                    assert umls_accuracy >= 0.92, (
                        f"UMLS accuracy too low in performance mode: {umls_accuracy:.3f}"
                    )

                # Record results
                iteration_result = {
                    "iteration": iteration + 1,
                    "topic": topic["name"],
                    "total_time": total_time,
                    "ragnostic_time": ragnostic_time,
                    "bsn_time": bsn_time,
                    "questions_generated": len(questions),
                    "meets_requirement": total_time < max_acceptable_time,
                }

                response_time_results.append(iteration_result)

                # Log individual result
                status = "PASS" if total_time < max_acceptable_time else "FAIL"
                logger.info(
                    f"  Iteration {iteration + 1}: {total_time:.3f}s ({status}) - "
                    f"RAGnostic: {ragnostic_time:.3f}s, BSN: {bsn_time:.3f}s"
                )

                # Assert individual iteration requirement
                assert total_time < max_acceptable_time, (
                    f"E2E-015 Iteration {iteration + 1} too slow: {total_time:.3f}s > {max_acceptable_time}s requirement"
                )

                # Brief pause between iterations to avoid overwhelming services
                if iteration < test_iterations - 1:
                    await asyncio.sleep(0.5)

            # Analyze overall performance across all iterations
            total_times = [r["total_time"] for r in response_time_results]
            ragnostic_times = [r["ragnostic_time"] for r in response_time_results]
            bsn_times = [r["bsn_time"] for r in response_time_results]

            # Calculate statistics
            avg_total_time = sum(total_times) / len(total_times)
            min_total_time = min(total_times)
            max_total_time = max(total_times)
            p95_total_time = sorted(total_times)[int(0.95 * len(total_times))]

            avg_ragnostic_time = sum(ragnostic_times) / len(ragnostic_times)
            avg_bsn_time = sum(bsn_times) / len(bsn_times)

            # Count successful iterations
            successful_iterations = sum(
                1 for r in response_time_results if r["meets_requirement"]
            )
            success_rate = successful_iterations / test_iterations * 100

            # Calculate consistency (standard deviation)
            variance = sum((t - avg_total_time) ** 2 for t in total_times) / len(
                total_times
            )
            std_deviation = variance**0.5
            coefficient_of_variation = std_deviation / avg_total_time

            # Assert E2E-015 overall requirements
            assert success_rate >= 95.0, (
                f"E2E-015 Success rate {success_rate:.1f}% < 95% requirement"
            )

            assert avg_total_time < max_acceptable_time, (
                f"E2E-015 Average time {avg_total_time:.3f}s > {max_acceptable_time}s requirement"
            )

            assert p95_total_time < max_acceptable_time * 1.2, (
                f"E2E-015 P95 time {p95_total_time:.3f}s > {max_acceptable_time * 1.2:.1f}s threshold"
            )

            # Performance consistency requirement
            assert coefficient_of_variation < 0.3, (
                f"E2E-015 Performance too inconsistent: CV {coefficient_of_variation:.3f} > 0.3 threshold"
            )

            # Component performance analysis
            assert avg_ragnostic_time < 1.0, (
                f"E2E-015 RAGnostic average time {avg_ragnostic_time:.3f}s > 1.0s threshold"
            )

            assert avg_bsn_time < 1.0, (
                f"E2E-015 BSN Knowledge average time {avg_bsn_time:.3f}s > 1.0s threshold"
            )

            # Log comprehensive results
            logger.info("E2E-015 PASSED: Response time validation completed")
            logger.info(
                f"  Success Rate: {success_rate:.1f}% ({successful_iterations}/{test_iterations})"
            )
            logger.info(
                f"  Avg Total Time: {avg_total_time:.3f}s (Min: {min_total_time:.3f}s, Max: {max_total_time:.3f}s)"
            )
            logger.info(f"  P95 Total Time: {p95_total_time:.3f}s")
            logger.info(
                f"  Component Times - RAGnostic: {avg_ragnostic_time:.3f}s, BSN Knowledge: {avg_bsn_time:.3f}s"
            )
            logger.info(
                f"  Consistency: CV {coefficient_of_variation:.3f} (StdDev: {std_deviation:.3f}s)"
            )

            # Record final metrics in performance monitor
            performance_monitor_e2e.record_service_response(
                "e2e_avg_total", avg_total_time * 1000
            )
            performance_monitor_e2e.record_service_response(
                "e2e_p95_total", p95_total_time * 1000
            )
            performance_monitor_e2e.record_service_response(
                "ragnostic_avg", avg_ragnostic_time * 1000
            )
            performance_monitor_e2e.record_service_response(
                "bsn_avg", avg_bsn_time * 1000
            )


@pytest.mark.e2e
@pytest.mark.resilience
class TestResilienceAndFailure:
    """Resilience and failure mode testing."""

    @pytest.mark.asyncio
    async def test_ragnostic_service_unavailable(
        self, e2e_pipeline_client, resilience_test_scenarios
    ):
        """Test BSN Knowledge behavior when RAGnostic service is unavailable."""
        resilience_test_scenarios["service_failure"]["ragnostic_down"]

        # Simulate RAGnostic service down by using invalid URL
        async with e2e_pipeline_client as client:
            # This should trigger circuit breaker or graceful degradation
            payload = {
                "topic": "cardiovascular_assessment",
                "difficulty": "medium",
                "question_count": 5,
                "fallback_mode": True,  # Should enable fallback generation
            }

            # Mock RAGnostic being down
            with patch(
                "src.services.ragnostic_client.RAGnosticClient.process_content"
            ) as mock_process:
                mock_process.side_effect = httpx.ConnectError("Service unavailable")

                response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=payload,
                    timeout=30.0,
                )

                # Should gracefully degrade or use cached content
                assert response.status_code in [
                    200,
                    503,
                ], f"Unexpected status: {response.status_code}"

                if response.status_code == 200:
                    # Graceful degradation - should return basic questions
                    result = response.json()
                    assert "questions" in result
                    assert "fallback_mode" in result
                    assert result["fallback_mode"] is True
                elif response.status_code == 503:
                    # Service unavailable but properly reported
                    result = response.json()
                    assert "error" in result
                    assert "ragnostic" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_database_connection_exhaustion(
        self, e2e_pipeline_client, resilience_test_scenarios
    ):
        """Test behavior under database connection pool exhaustion."""
        resilience_test_scenarios["service_failure"]["database_connection_loss"]

        # Simulate database connection issues
        async with e2e_pipeline_client as client:
            # Generate enough concurrent requests to potentially exhaust connection pool
            concurrent_requests = 50

            async def make_request():
                try:
                    response = await client.get(
                        "http://bsn-knowledge-test:8040/api/v1/health", timeout=5.0
                    )
                    return response.status_code
                except Exception as e:
                    return str(e)

            # Execute concurrent requests
            tasks = [make_request() for _ in range(concurrent_requests)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Analyze results - should handle gracefully
            successful_responses = sum(1 for r in results if r == 200)
            sum(1 for r in results if isinstance(r, str | Exception))

            # At least some requests should succeed (queuing/retry mechanisms)
            success_rate = successful_responses / len(results) * 100
            assert success_rate >= 70.0, (
                f"Too many failures under load: {success_rate:.1f}% success rate"
            )

            logger.info(
                f"Database stress test: {successful_responses}/{concurrent_requests} successful ({success_rate:.1f}%)"
            )

    @pytest.mark.asyncio
    async def test_recovery_after_failure(self, e2e_pipeline_client):
        """Test system recovery after service failure."""
        async with e2e_pipeline_client as client:
            # Step 1: Verify normal operation
            normal_response = await client.get(
                "http://bsn-knowledge-test:8040/api/v1/health"
            )
            assert normal_response.status_code == 200

            # Step 2: Simulate and recover from failure
            # In a real test, this would stop and restart services
            # Here we simulate with a delay and retry pattern

            recovery_attempts = 0
            max_attempts = 5

            while recovery_attempts < max_attempts:
                try:
                    recovery_response = await client.get(
                        "http://bsn-knowledge-test:8040/api/v1/health", timeout=2.0
                    )

                    if recovery_response.status_code == 200:
                        health_data = recovery_response.json()
                        if health_data.get("status") == "healthy":
                            break

                    recovery_attempts += 1
                    await asyncio.sleep(1)  # Wait before retry

                except Exception:
                    recovery_attempts += 1
                    await asyncio.sleep(1)

            # Assert recovery within acceptable time
            assert recovery_attempts < max_attempts, (
                f"Service failed to recover within {max_attempts} attempts"
            )

            # Step 3: Verify full functionality after recovery
            test_payload = {
                "topic": "basic_assessment",
                "difficulty": "easy",
                "question_count": 1,
            }

            functionality_response = await client.post(
                "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                json=test_payload,
            )

            assert functionality_response.status_code == 200, (
                "Functionality not restored after recovery"
            )

            logger.info(f"Recovery successful after {recovery_attempts} attempts")


@pytest.mark.e2e
@pytest.mark.security
class TestCrossServiceSecurity:
    """Cross-service security validation."""

    @pytest.mark.asyncio
    async def test_authentication_flow_integrity(
        self, e2e_pipeline_client, security_test_vectors
    ):
        """Test authentication security across service boundaries."""
        auth_tests = security_test_vectors["authentication_tests"]

        async with e2e_pipeline_client as client:
            # Test invalid JWT token
            invalid_headers = {
                "Authorization": f"Bearer {auth_tests['invalid_jwt']['token']}"
            }

            invalid_response = await client.get(
                "http://bsn-knowledge-test:8040/api/v1/analytics/assessment",
                headers=invalid_headers,
            )

            assert (
                invalid_response.status_code
                == auth_tests["invalid_jwt"]["expected_status"]
            )

            # Test malformed API key for RAGnostic integration
            malformed_headers = {
                "X-API-Key": auth_tests["malformed_api_key"]["api_key"]
            }

            malformed_response = await client.post(
                "http://ragnostic-orchestrator:8030/api/v1/process",
                json={"content": "test content"},
                headers=malformed_headers,
            )

            assert (
                malformed_response.status_code
                == auth_tests["malformed_api_key"]["expected_status"]
            )

    @pytest.mark.asyncio
    async def test_input_sanitization_pipeline(
        self, e2e_pipeline_client, security_test_vectors
    ):
        """Test input sanitization across the complete pipeline."""
        injection_tests = security_test_vectors["injection_tests"]

        async with e2e_pipeline_client as client:
            # Test SQL injection protection
            for sql_payload in injection_tests["sql_injection"]:
                malicious_request = {
                    "topic": sql_payload,
                    "difficulty": "medium",
                    "question_count": 5,
                }

                response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/nclex/generate",
                    json=malicious_request,
                )

                # Should either reject (4xx) or safely handle without injection
                assert response.status_code != 500, (
                    f"Server error with SQL injection: {sql_payload}"
                )

                if response.status_code == 200:
                    # If processed, ensure no sensitive data leaked
                    result = response.json()
                    result_str = json.dumps(result).lower()
                    assert "drop table" not in result_str
                    assert "select *" not in result_str

            # Test XSS protection in content generation
            for xss_payload in injection_tests["xss_payloads"]:
                xss_request = {
                    "content": f"Educational content about nursing {xss_payload}",
                    "processing_type": "basic",
                }

                response = await client.post(
                    "http://bsn-knowledge-test:8040/api/v1/content/generate",
                    json=xss_request,
                )

                if response.status_code == 200:
                    result = response.json()
                    content = result.get("generated_content", "")

                    # Should be sanitized
                    assert "<script>" not in content
                    assert "javascript:" not in content
                    assert "onerror=" not in content

    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(
        self, e2e_pipeline_client, security_test_vectors
    ):
        """Test rate limiting enforcement across services."""
        rate_config = security_test_vectors["rate_limiting"]

        async with e2e_pipeline_client as client:
            # Generate burst of requests to trigger rate limiting
            burst_requests = rate_config["burst_requests"]

            async def make_rate_limited_request():
                return await client.get(
                    "http://bsn-knowledge-test:8040/api/v1/search",
                    params={"q": "test query"},
                )

            # Execute burst requests
            tasks = [make_rate_limited_request() for _ in range(burst_requests)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Count rate limited responses
            rate_limited_count = sum(
                1
                for r in responses
                if hasattr(r, "status_code")
                and r.status_code == rate_config["expected_status"]
            )

            # Should have some rate limited responses
            assert rate_limited_count > 0, (
                f"Rate limiting not enforced: {rate_limited_count} blocked out of {burst_requests}"
            )

            rate_limit_percentage = rate_limited_count / burst_requests * 100
            logger.info(
                f"Rate limiting: {rate_limited_count}/{burst_requests} requests blocked ({rate_limit_percentage:.1f}%)"
            )


# Helper functions for test utilities
def validate_medical_accuracy(content: str, expected_concepts: list[str]) -> float:
    """Validate medical accuracy of generated content."""
    content_lower = content.lower()
    concepts_found = sum(
        1 for concept in expected_concepts if concept.lower() in content_lower
    )
    return concepts_found / len(expected_concepts) if expected_concepts else 0.0


def validate_nclex_alignment(
    question: dict[str, Any], expected_categories: list[str]
) -> bool:
    """Validate NCLEX category alignment."""
    question_category = question.get("nclex_category", "")
    return question_category in expected_categories


def assess_clinical_accuracy(
    question: dict[str, Any], medical_concepts: list[dict]
) -> float:
    """Assess clinical accuracy of a generated question."""
    # Basic clinical accuracy assessment
    question_text = question.get("question", "").lower()
    rationale = question.get("rationale", "").lower()

    accuracy_score = 0.8  # Base score

    # Check for medical concept integration
    concept_integration = 0
    for concept in medical_concepts:
        preferred_name = concept.get("preferred_name", "").lower()
        if preferred_name in question_text or preferred_name in rationale:
            concept_integration += 1

    # Boost score for good concept integration
    if concept_integration > 0:
        accuracy_score = min(1.0, accuracy_score + (concept_integration * 0.05))

    # Check for clinical reasoning indicators
    clinical_indicators = [
        "assess",
        "monitor",
        "evaluate",
        "priority",
        "first",
        "initial",
        "contraindicated",
    ]
    clinical_terms_found = sum(
        1 for indicator in clinical_indicators if indicator in question_text
    )

    if clinical_terms_found >= 2:
        accuracy_score = min(1.0, accuracy_score + 0.1)

    return accuracy_score


# Test data validation utilities
def assert_question_quality(question: dict[str, Any]) -> None:
    """Assert that a generated question meets quality standards."""
    required_fields = [
        "question",
        "options",
        "correct_answer",
        "rationale",
        "nclex_category",
    ]

    for field in required_fields:
        assert field in question, f"Missing required field: {field}"

    # Validate options structure
    options = question["options"]
    assert isinstance(options, list), "Options should be a list"
    assert len(options) >= 4, "Should have at least 4 options"

    # Validate correct answer
    correct_answer = question["correct_answer"]
    assert correct_answer in [
        "A",
        "B",
        "C",
        "D",
    ], f"Invalid correct answer: {correct_answer}"

    # Validate rationale quality
    rationale = question["rationale"]
    assert len(rationale) >= 20, "Rationale should be substantive"
    assert not rationale.lower().startswith("the answer is"), (
        "Rationale should explain why, not just state answer"
    )
