"""
E2E Service Integration Tests for Group 1B Test Framework Foundation.

Validates pytest framework integration with deployed services from Group 1A
infrastructure, including service health checks, authentication, and basic
communication patterns.
"""

import time

import pytest

from tests.conftest import E2E_SERVICES_CONFIG, TEST_CONFIG


@pytest.mark.e2e
@pytest.mark.service_integration
@pytest.mark.asyncio
async def test_service_health_monitoring_integration(e2e_service_health_monitor):
    """Test integration with E2E service health monitoring from Group 1A."""

    # Get comprehensive health status
    health_status = await e2e_service_health_monitor.get_all_health_status()

    # Validate health status structure
    assert "services" in health_status
    assert "healthy_count" in health_status
    assert "total_count" in health_status

    # Validate service count matches expected services from Group 1A
    expected_service_count = len(E2E_SERVICES_CONFIG)
    assert health_status["total_count"] == expected_service_count

    # In E2E mode, all services should be healthy (from Group 1A success)
    if TEST_CONFIG["E2E_MODE"]:
        assert health_status["healthy_count"] == health_status["total_count"], (
            f"Expected all {expected_service_count} services healthy, got {health_status['healthy_count']}"
        )

    # Validate individual service health
    service_results = health_status["services"]
    assert len(service_results) == expected_service_count

    for service_result in service_results:
        assert "service" in service_result
        assert "status" in service_result

        if TEST_CONFIG["E2E_MODE"]:
            assert service_result["status"] == "healthy", (
                f"Service {service_result['service']} not healthy: {service_result}"
            )


@pytest.mark.e2e
@pytest.mark.service_integration
@pytest.mark.ragnostic_integration
@pytest.mark.asyncio
async def test_ragnostic_service_integration(
    e2e_pipeline_client, performance_monitor_e2e
):
    """Test integration with RAGnostic microservices cluster."""

    performance_monitor_e2e.start()

    # Test RAGnostic Orchestrator service
    orchestrator_url = E2E_SERVICES_CONFIG["ragnostic_orchestrator"]["url"]

    start_time = time.time()
    response = await e2e_pipeline_client.get(f"{orchestrator_url}/health")
    response_time = (time.time() - start_time) * 1000

    performance_monitor_e2e.record_service_response(
        "ragnostic_orchestrator", response_time
    )

    if TEST_CONFIG["E2E_MODE"]:
        # Real E2E validation
        assert response.status_code == 200, (
            f"RAGnostic Orchestrator health check failed: {response.status_code}"
        )
        assert response_time <= 200, (
            f"RAGnostic Orchestrator response time {response_time}ms exceeds 200ms"
        )
    else:
        # Mock validation
        assert response.status_code == 200

    # Test RAGnostic Storage service
    storage_url = E2E_SERVICES_CONFIG["ragnostic_storage"]["url"]

    start_time = time.time()
    response = await e2e_pipeline_client.get(f"{storage_url}/health")
    response_time = (time.time() - start_time) * 1000

    performance_monitor_e2e.record_service_response("ragnostic_storage", response_time)

    if TEST_CONFIG["E2E_MODE"]:
        assert response.status_code == 200, (
            f"RAGnostic Storage health check failed: {response.status_code}"
        )
        assert response_time <= 200, (
            f"RAGnostic Storage response time {response_time}ms exceeds 200ms"
        )

    # Test RAGnostic Nursing Processor
    processor_url = E2E_SERVICES_CONFIG["ragnostic_nursing_processor"]["url"]

    start_time = time.time()
    response = await e2e_pipeline_client.get(f"{processor_url}/health")
    response_time = (time.time() - start_time) * 1000

    performance_monitor_e2e.record_service_response(
        "ragnostic_nursing_processor", response_time
    )

    if TEST_CONFIG["E2E_MODE"]:
        assert response.status_code == 200, (
            f"RAGnostic Processor health check failed: {response.status_code}"
        )
        assert response_time <= 200, (
            f"RAGnostic Processor response time {response_time}ms exceeds 200ms"
        )

    performance_monitor_e2e.stop()
    performance_monitor_e2e.assert_performance_targets()


@pytest.mark.e2e
@pytest.mark.service_integration
@pytest.mark.asyncio
async def test_bsn_knowledge_service_integration(
    e2e_pipeline_client, performance_monitor_e2e
):
    """Test integration with BSN Knowledge services cluster."""

    performance_monitor_e2e.start()

    # Test BSN Knowledge main API service
    api_url = E2E_SERVICES_CONFIG["bsn_knowledge"]["url"]

    start_time = time.time()
    response = await e2e_pipeline_client.get(f"{api_url}/health")
    response_time = (time.time() - start_time) * 1000

    performance_monitor_e2e.record_service_response("bsn_knowledge", response_time)

    if TEST_CONFIG["E2E_MODE"]:
        assert response.status_code == 200, (
            f"BSN Knowledge API health check failed: {response.status_code}"
        )
        assert response_time <= 200, (
            f"BSN Knowledge API response time {response_time}ms exceeds 200ms"
        )

    # Test BSN Analytics service
    analytics_url = E2E_SERVICES_CONFIG["bsn_analytics"]["url"]

    start_time = time.time()
    response = await e2e_pipeline_client.get(f"{analytics_url}/health")
    response_time = (time.time() - start_time) * 1000

    performance_monitor_e2e.record_service_response("bsn_analytics", response_time)

    if TEST_CONFIG["E2E_MODE"]:
        assert response.status_code == 200, (
            f"BSN Analytics health check failed: {response.status_code}"
        )
        assert response_time <= 200, (
            f"BSN Analytics response time {response_time}ms exceeds 200ms"
        )

    performance_monitor_e2e.stop()
    performance_monitor_e2e.assert_performance_targets()


@pytest.mark.e2e
@pytest.mark.service_integration
@pytest.mark.umls_integration
@pytest.mark.medical_validation
@pytest.mark.asyncio
async def test_umls_mock_service_integration(
    e2e_pipeline_client, medical_accuracy_validator
):
    """Test integration with UMLS mock service for medical accuracy validation."""

    umls_url = E2E_SERVICES_CONFIG["umls_mock"]["url"]

    # Test UMLS service health
    response = await e2e_pipeline_client.get(f"{umls_url}/health")

    if TEST_CONFIG["E2E_MODE"]:
        assert response.status_code == 200, (
            f"UMLS Mock service health check failed: {response.status_code}"
        )

    # Test medical terminology validation
    test_terms = [
        "cardiovascular assessment",
        "medication administration",
        "infection control",
    ]
    accuracy = medical_accuracy_validator.validate_umls_terminology(test_terms)

    # Should meet Group 1A baseline of 99.5% accuracy
    assert accuracy >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"], (
        f"UMLS accuracy {accuracy:.3f} below required {TEST_CONFIG['MEDICAL_ACCURACY_THRESHOLD']}"
    )

    # Validate accuracy meets Group 1A established baseline
    if TEST_CONFIG["E2E_MODE"]:
        assert accuracy >= 0.995, (
            f"UMLS accuracy {accuracy:.3f} below Group 1A baseline of 99.5%"
        )


@pytest.mark.e2e
@pytest.mark.database_e2e
@pytest.mark.asyncio
async def test_database_connections_integration(e2e_database_connections):
    """Test integration with multi-database setup from Group 1A."""

    connections = e2e_database_connections

    # Validate connection structure
    assert "postgresql" in connections
    assert "redis" in connections
    assert "qdrant" in connections
    assert "neo4j" in connections

    # Validate PostgreSQL connections (from Group 1A multi-DB setup)
    pg_connections = connections["postgresql"]
    expected_databases = ["ragnostic_e2e", "bsn_knowledge_e2e", "e2e_analytics"]

    for db_name in expected_databases:
        assert db_name in pg_connections, f"Missing PostgreSQL database: {db_name}"

        # In E2E mode, connections should be real async engines
        if TEST_CONFIG["E2E_MODE"]:
            assert hasattr(pg_connections[db_name], "dispose"), (
                f"Invalid PostgreSQL connection for {db_name}"
            )


@pytest.mark.e2e
@pytest.mark.performance_baseline
@pytest.mark.asyncio
async def test_service_response_time_baselines(
    e2e_pipeline_client, performance_monitor_e2e
):
    """Test service response times meet Group 1A established baselines."""

    performance_monitor_e2e.start()

    # Test all services and record response times
    for service_name, service_config in E2E_SERVICES_CONFIG.items():
        service_url = service_config["url"]
        health_endpoint = service_config["health_endpoint"]

        start_time = time.time()

        try:
            response = await e2e_pipeline_client.get(f"{service_url}{health_endpoint}")
            response_time = (time.time() - start_time) * 1000

            performance_monitor_e2e.record_service_response(service_name, response_time)

            if TEST_CONFIG["E2E_MODE"]:
                # Validate against Group 1A baseline (82.5ms avg, 156ms max)
                assert response_time <= 200, (
                    f"Service {service_name} response time {response_time:.1f}ms exceeds 200ms baseline"
                )
                assert response.status_code == 200, (
                    f"Service {service_name} health check failed: {response.status_code}"
                )

        except Exception as e:
            if TEST_CONFIG["E2E_MODE"]:
                pytest.fail(f"Service {service_name} health check failed: {str(e)}")

    performance_monitor_e2e.stop()

    # Generate performance report
    report = performance_monitor_e2e.generate_performance_report()

    # Validate overall performance targets
    if TEST_CONFIG["E2E_MODE"]:
        assert report["performance_targets_met"], (
            f"Performance targets not met: {report['execution_time_ms']:.1f}ms > {TEST_CONFIG['PERFORMANCE_TARGET_MS']}ms"
        )

        # Validate service response times meet Group 1A baselines
        for service, response_time in report["service_response_times"].items():
            assert response_time <= 200, (
                f"Service {service} response time {response_time:.1f}ms exceeds 200ms Group 1A baseline"
            )


@pytest.mark.e2e
@pytest.mark.orchestration
@pytest.mark.asyncio
async def test_orchestration_framework_integration(e2e_test_orchestrator):
    """Test integration with E2E test orchestration framework."""

    # Validate orchestrator is properly configured
    assert hasattr(e2e_test_orchestrator, "config"), (
        "Orchestrator missing configuration"
    )
    assert hasattr(e2e_test_orchestrator, "health_checker"), (
        "Orchestrator missing health checker"
    )
    assert hasattr(e2e_test_orchestrator, "executor"), "Orchestrator missing executor"
    assert hasattr(e2e_test_orchestrator, "reporter"), "Orchestrator missing reporter"

    # Test orchestrator configuration
    config = e2e_test_orchestrator.config

    if TEST_CONFIG["E2E_MODE"]:
        assert "services" in config, "Orchestrator missing services configuration"
        assert "max_workers" in config, "Orchestrator missing max_workers configuration"
        assert "medical_accuracy_threshold" in config, (
            "Orchestrator missing medical accuracy threshold"
        )
        assert "performance_target_ms" in config, (
            "Orchestrator missing performance target"
        )

        # Validate medical accuracy threshold from Group 1A
        assert config["medical_accuracy_threshold"] >= 0.98, (
            f"Medical accuracy threshold too low: {config['medical_accuracy_threshold']}"
        )

        # Validate services match Group 1A infrastructure
        expected_services = set(E2E_SERVICES_CONFIG.keys())
        actual_services = set(config["services"].keys())
        assert expected_services == actual_services, (
            f"Service mismatch. Expected: {expected_services}, Got: {actual_services}"
        )


@pytest.mark.e2e
@pytest.mark.cross_service
@pytest.mark.asyncio
async def test_inter_service_communication(
    e2e_pipeline_client, performance_monitor_e2e
):
    """Test inter-service communication patterns from Group 1A validation."""

    performance_monitor_e2e.start()

    # Test RAGnostic → BSN Knowledge communication pattern
    # This simulates the validated 42.3ms inter-service communication from Group 1A

    if TEST_CONFIG["E2E_MODE"]:
        # Real E2E inter-service test
        ragnostic_url = E2E_SERVICES_CONFIG["ragnostic_orchestrator"]["url"]
        bsn_url = E2E_SERVICES_CONFIG["bsn_knowledge"]["url"]

        # Test sequential service calls (simulating inter-service communication)
        start_time = time.time()

        # Call RAGnostic service
        ragnostic_response = await e2e_pipeline_client.get(f"{ragnostic_url}/health")
        assert ragnostic_response.status_code == 200

        # Call BSN Knowledge service (simulating handoff)
        bsn_response = await e2e_pipeline_client.get(f"{bsn_url}/health")
        assert bsn_response.status_code == 200

        total_communication_time = (time.time() - start_time) * 1000

        # Should meet Group 1A inter-service communication baseline (42.3ms)
        assert total_communication_time <= 100, (
            f"Inter-service communication {total_communication_time:.1f}ms exceeds 100ms target"
        )

        performance_monitor_e2e.record_service_response(
            "inter_service_communication", total_communication_time
        )

    performance_monitor_e2e.stop()
    performance_monitor_e2e.assert_performance_targets()


@pytest.mark.e2e
@pytest.mark.medical_accuracy
@pytest.mark.asyncio
async def test_medical_accuracy_validation_framework(medical_accuracy_validator):
    """Test medical accuracy validation framework integration."""

    # Test UMLS terminology validation
    medical_terms = [
        "myocardial infraction",
        "diabetes mellitus",
        "hypertension",
        "chronic obstructive pulmonary disease",
        "acute respiratory distress syndrome",
    ]

    umls_accuracy = medical_accuracy_validator.validate_umls_terminology(medical_terms)

    # Should exceed Group 1A baseline of 99.5%
    assert umls_accuracy >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"], (
        f"UMLS accuracy {umls_accuracy:.3f} below required threshold"
    )

    # Test NCLEX question quality validation
    sample_questions = [
        {
            "question": "A patient with heart failure is prescribed digoxin 0.25 mg daily. Which assessment finding would indicate possible digoxin toxicity?",
            "options": [
                "A. Heart rate of 88 beats per minute",
                "B. Nausea and visual disturbances",
                "C. Blood pressure of 130/80 mmHg",
                "D. Respiratory rate of 20 breaths per minute",
            ],
            "correct_answer": "B",
            "rationale": "Nausea and visual disturbances are classic early signs of digoxin toxicity, often occurring before more serious cardiac effects.",
        }
    ]

    quality_results = medical_accuracy_validator.validate_nclex_question_quality(
        sample_questions
    )

    assert quality_results["meets_standards"], (
        f"NCLEX question quality below standards: {quality_results['quality_score']:.2f}"
    )

    # Test overall medical accuracy
    overall_accuracy = medical_accuracy_validator.get_overall_medical_accuracy()
    assert overall_accuracy >= TEST_CONFIG["MEDICAL_ACCURACY_THRESHOLD"], (
        f"Overall medical accuracy {overall_accuracy:.3f} below required threshold"
    )

    # Assert all medical accuracy requirements are met
    medical_accuracy_validator.assert_medical_accuracy_requirements()


if __name__ == "__main__":
    # Run E2E service integration tests
    pytest.main([__file__, "-v", "--tb=short", "-m", "e2e and service_integration"])
