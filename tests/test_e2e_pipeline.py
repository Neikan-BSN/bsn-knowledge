"""End-to-End Pipeline Testing for RAGnostic → BSN Knowledge Integration.

Comprehensive validation of the complete educational content pipeline including:
- Medical content enrichment through RAGnostic
- NCLEX question generation with medical accuracy
- Concurrent performance under realistic load
- Resilience and failure mode testing
- Security validation across service boundaries
"""

import asyncio
import json
import time
from typing import Any
from unittest.mock import patch

import httpx
import pytest


@pytest.mark.e2e
@pytest.mark.pipeline
class TestE2EPipeline:
    """End-to-end pipeline integration tests."""

    @pytest.mark.asyncio
    async def test_umls_to_nclex_generation_pipeline(
        self, pipeline_test_client, medical_test_data, performance_monitoring
    ):
        """Test complete UMLS medical term enrichment to NCLEX question generation."""
        performance_monitoring.start_monitoring()

        # Test data from fixtures
        nursing_topic = medical_test_data["nursing_topics"][
            0
        ]  # Cardiovascular assessment
        performance_benchmarks = medical_test_data["performance_benchmarks"]

        # Step 1: Submit content for RAGnostic processing
        ragnostic_payload = {
            "content": f"Educational content on {nursing_topic['name']}",
            "umls_concepts": nursing_topic["umls_concepts"],
            "processing_type": "medical_enrichment",
            "target_education_level": "undergraduate_nursing",
        }

        start_time = time.time()

        async with pipeline_test_client as client:
            # Process through RAGnostic
            ragnostic_response = await client.post(
                "http://ragnostic-mock:8000/api/v1/process",
                json=ragnostic_payload,
                timeout=30.0,
            )

            processing_time = time.time() - start_time
            performance_monitoring.record_metric(
                "ragnostic_processing_time", processing_time
            )

            assert (
                ragnostic_response.status_code == 200
            ), f"RAGnostic processing failed: {ragnostic_response.text}"
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
                "http://bsn-knowledge-test:8000/api/v1/nclex/generate",
                json=bsn_payload,
                timeout=30.0,
            )

            generation_time = time.time() - generation_start
            performance_monitoring.record_metric(
                "nclex_generation_time", generation_time
            )

            assert (
                bsn_response.status_code == 200
            ), f"NCLEX generation failed: {bsn_response.text}"
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

                # Check medical terminology integration
                question_text = question["question"].lower()
                medical_terms_found = sum(
                    1
                    for concept in ragnostic_result["medical_concepts"]
                    if concept.get("preferred_name", "").lower() in question_text
                )
                assert (
                    medical_terms_found > 0
                ), "Questions should incorporate medical concepts from RAGnostic"

            # Performance validation
            total_pipeline_time = time.time() - start_time
            performance_monitoring.record_metric(
                "total_pipeline_time", total_pipeline_time
            )

            # Assert performance benchmarks
            max_acceptable_time = (
                performance_benchmarks["response_time_ms"]["p95"] / 1000
            )  # Convert to seconds
            assert (
                total_pipeline_time < max_acceptable_time
            ), f"Pipeline too slow: {total_pipeline_time:.2f}s > {max_acceptable_time:.2f}s"

            # Log success metrics
            pipeline_stats = performance_monitoring.calculate_statistics(
                "total_pipeline_time"
            )
            print(f"\nPipeline Performance: {pipeline_stats}")

    @pytest.mark.asyncio
    async def test_concurrent_load_performance(
        self, pipeline_test_client, load_test_config, performance_monitoring
    ):
        """Test concurrent performance with both RAGnostic and BSN Knowledge operations."""
        performance_monitoring.start_monitoring()

        # Concurrent load simulation
        concurrent_requests = 20
        scenarios = load_test_config["scenarios"]

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
                        f"http://bsn-knowledge-test:8000{scenario_config['endpoint']}",
                        json=scenario_config.get("payload", {}),
                        timeout=10.0,
                    )
                else:
                    response = await client.get(
                        f"http://bsn-knowledge-test:8000{scenario_config['endpoint']}",
                        params=scenario_config.get("params", {}),
                        timeout=10.0,
                    )

                response_time = time.time() - start_time
                performance_monitoring.record_metric(
                    f"{scenario_name}_response_time", response_time
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
        async with pipeline_test_client as client:
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

            performance_monitoring.record_metric(
                "concurrent_avg_response_time", avg_response_time
            )
            performance_monitoring.record_metric(
                "concurrent_p95_response_time", p95_response_time
            )

        # Performance assertions
        assert success_rate >= 95.0, f"Success rate too low: {success_rate:.1f}% < 95%"
        if response_times:
            assert (
                avg_response_time < 2.0
            ), f"Average response time too high: {avg_response_time:.2f}s"
            assert (
                p95_response_time < 5.0
            ), f"P95 response time too high: {p95_response_time:.2f}s"

        print("\nConcurrent Load Results:")
        print(f"  Total Requests: {total_requests}")
        print(f"  Success Rate: {success_rate:.1f}%")
        print(
            f"  Avg Response Time: {avg_response_time:.3f}s"
            if response_times
            else "  No timing data"
        )
        print(
            f"  P95 Response Time: {p95_response_time:.3f}s" if response_times else ""
        )

    @pytest.mark.asyncio
    async def test_transaction_integrity(self, pipeline_test_client, medical_test_data):
        """Test multi-service transaction integrity and data consistency."""
        nursing_topic = medical_test_data["nursing_topics"][
            1
        ]  # Medication administration

        async with pipeline_test_client as client:
            # Step 1: Create student profile
            student_data = {
                "student_id": "test_student_integrity_001",
                "competency_level": "intermediate",
                "learning_objectives": [nursing_topic["id"]],
            }

            profile_response = await client.post(
                "http://bsn-knowledge-test:8000/api/v1/students/profile",
                json=student_data,
            )
            assert profile_response.status_code in [200, 201]

            # Step 2: Generate personalized content
            content_request = {
                "student_id": student_data["student_id"],
                "topic": nursing_topic["id"],
                "umls_concepts": nursing_topic["umls_concepts"],
                "personalization": True,
            }

            content_response = await client.post(
                "http://bsn-knowledge-test:8000/api/v1/content/generate",
                json=content_request,
            )
            assert content_response.status_code == 200
            content_result = content_response.json()

            # Step 3: Record learning activity
            activity_data = {
                "student_id": student_data["student_id"],
                "content_id": content_result.get("content_id"),
                "activity_type": "content_review",
                "time_spent_minutes": 30,
                "completion_status": "completed",
            }

            activity_response = await client.post(
                "http://bsn-knowledge-test:8000/api/v1/activities/record",
                json=activity_data,
            )
            assert activity_response.status_code in [200, 201]

            # Step 4: Verify data consistency across services
            # Check student profile exists
            profile_check = await client.get(
                f"http://bsn-knowledge-test:8000/api/v1/students/profile/{student_data['student_id']}"
            )
            assert profile_check.status_code == 200
            profile_data = profile_check.json()
            assert profile_data["student_id"] == student_data["student_id"]

            # Check content exists and is linked
            content_check = await client.get(
                f"http://bsn-knowledge-test:8000/api/v1/content/{content_result.get('content_id')}"
            )
            assert content_check.status_code == 200

            # Check activity record exists
            activities_check = await client.get(
                f"http://bsn-knowledge-test:8000/api/v1/activities/{student_data['student_id']}"
            )
            assert activities_check.status_code == 200
            activities_data = activities_check.json()
            assert len(activities_data.get("activities", [])) >= 1

            # Verify relational integrity
            recorded_activity = activities_data["activities"][0]
            assert recorded_activity["content_id"] == content_result.get("content_id")
            assert recorded_activity["student_id"] == student_data["student_id"]

            print("\nTransaction integrity validated successfully")


@pytest.mark.e2e
@pytest.mark.resilience
class TestResilienceAndFailure:
    """Resilience and failure mode testing."""

    @pytest.mark.asyncio
    async def test_ragnostic_service_unavailable(
        self, pipeline_test_client, resilience_test_scenarios
    ):
        """Test BSN Knowledge behavior when RAGnostic service is unavailable."""
        resilience_test_scenarios["service_failure"]["ragnostic_down"]

        # Simulate RAGnostic service down by using invalid URL
        async with pipeline_test_client as client:
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
                    "http://bsn-knowledge-test:8000/api/v1/nclex/generate",
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
        self, pipeline_test_client, resilience_test_scenarios
    ):
        """Test behavior under database connection pool exhaustion."""
        resilience_test_scenarios["service_failure"]["database_connection_loss"]

        # Simulate database connection issues
        async with pipeline_test_client as client:
            # Generate enough concurrent requests to potentially exhaust connection pool
            concurrent_requests = 50

            async def make_request():
                try:
                    response = await client.get(
                        "http://bsn-knowledge-test:8000/api/v1/health", timeout=5.0
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
            assert (
                success_rate >= 70.0
            ), f"Too many failures under load: {success_rate:.1f}% success rate"

            print(
                f"Database stress test: {successful_responses}/{concurrent_requests} successful ({success_rate:.1f}%)"
            )

    @pytest.mark.asyncio
    async def test_recovery_after_failure(self, pipeline_test_client):
        """Test system recovery after service failure."""
        async with pipeline_test_client as client:
            # Step 1: Verify normal operation
            normal_response = await client.get(
                "http://bsn-knowledge-test:8000/api/v1/health"
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
                        "http://bsn-knowledge-test:8000/api/v1/health", timeout=2.0
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
            assert (
                recovery_attempts < max_attempts
            ), f"Service failed to recover within {max_attempts} attempts"

            # Step 3: Verify full functionality after recovery
            test_payload = {
                "topic": "basic_assessment",
                "difficulty": "easy",
                "question_count": 1,
            }

            functionality_response = await client.post(
                "http://bsn-knowledge-test:8000/api/v1/nclex/generate",
                json=test_payload,
            )

            assert (
                functionality_response.status_code == 200
            ), "Functionality not restored after recovery"

            print(f"Recovery successful after {recovery_attempts} attempts")


@pytest.mark.e2e
@pytest.mark.security
class TestCrossServiceSecurity:
    """Cross-service security validation."""

    @pytest.mark.asyncio
    async def test_authentication_flow_integrity(
        self, pipeline_test_client, security_test_vectors
    ):
        """Test authentication security across service boundaries."""
        auth_tests = security_test_vectors["authentication_tests"]

        async with pipeline_test_client as client:
            # Test invalid JWT token
            invalid_headers = {
                "Authorization": f"Bearer {auth_tests['invalid_jwt']['token']}"
            }

            invalid_response = await client.get(
                "http://bsn-knowledge-test:8000/api/v1/analytics/assessment",
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
                "http://ragnostic-mock:8000/api/v1/process",
                json={"content": "test content"},
                headers=malformed_headers,
            )

            assert (
                malformed_response.status_code
                == auth_tests["malformed_api_key"]["expected_status"]
            )

    @pytest.mark.asyncio
    async def test_input_sanitization_pipeline(
        self, pipeline_test_client, security_test_vectors
    ):
        """Test input sanitization across the complete pipeline."""
        injection_tests = security_test_vectors["injection_tests"]

        async with pipeline_test_client as client:
            # Test SQL injection protection
            for sql_payload in injection_tests["sql_injection"]:
                malicious_request = {
                    "topic": sql_payload,
                    "difficulty": "medium",
                    "question_count": 5,
                }

                response = await client.post(
                    "http://bsn-knowledge-test:8000/api/v1/nclex/generate",
                    json=malicious_request,
                )

                # Should either reject (4xx) or safely handle without injection
                assert (
                    response.status_code != 500
                ), f"Server error with SQL injection: {sql_payload}"

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
                    "http://bsn-knowledge-test:8000/api/v1/content/generate",
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
        self, pipeline_test_client, security_test_vectors
    ):
        """Test rate limiting enforcement across services."""
        rate_config = security_test_vectors["rate_limiting"]

        async with pipeline_test_client as client:
            # Generate burst of requests to trigger rate limiting
            burst_requests = rate_config["burst_requests"]

            async def make_rate_limited_request():
                return await client.get(
                    "http://bsn-knowledge-test:8000/api/v1/search",
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
            assert (
                rate_limited_count > 0
            ), f"Rate limiting not enforced: {rate_limited_count} blocked out of {burst_requests}"

            rate_limit_percentage = rate_limited_count / burst_requests * 100
            print(
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
    assert not rationale.lower().startswith(
        "the answer is"
    ), "Rationale should explain why, not just state answer"
