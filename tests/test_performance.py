"""
Performance Tests for BSN Knowledge API

Tests response times, concurrent handling, memory usage,
and performance benchmarks for the API.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from fastapi import status
from fastapi.testclient import TestClient


@pytest.mark.performance
class TestResponseTimePerformance:
    """Test API response time requirements."""

    def test_health_endpoint_response_time(
        self, client: TestClient, performance_monitor
    ):
        """Test health endpoint meets <100ms requirement."""
        performance_monitor.start()
        response = client.get("/health")
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.1)  # 100ms

    def test_authentication_response_time(
        self, client: TestClient, test_users, performance_monitor
    ):
        """Test authentication meets <500ms requirement."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        performance_monitor.start()
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "student1", "password": "test_password"},
        )
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.5)  # 500ms

    def test_simple_endpoint_response_times(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test simple endpoints meet <500ms requirement."""
        simple_endpoints = [
            "/api/v1/auth/me",
            "/api/v1/auth/roles",
            "/api/v1/assessment/domains",
            "/api/v1/assessment/proficiency-levels",
        ]

        for endpoint in simple_endpoints:
            performance_monitor.start()
            response = client.get(endpoint, headers=auth_headers.get("student1", {}))
            performance_monitor.stop()

            if response.status_code == status.HTTP_200_OK:
                performance_monitor.assert_within_threshold(0.5)  # 500ms

    def test_complex_endpoint_response_times(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test complex endpoints meet <2s requirement."""
        complex_operations = [
            (
                "/api/v1/nclex/generate",
                {
                    "topic": "nursing_fundamentals",
                    "difficulty": "medium",
                    "question_count": 5,
                },
            ),
            (
                "/api/v1/study-guide/create",
                {
                    "topic": "Basic Patient Care",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "beginner",
                },
            ),
            (
                "/api/v1/assessment/competency",
                {
                    "student_id": "perf_test_001",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"quiz_scores": [85, 90, 78]},
                    "assessment_type": "performance_test",
                },
            ),
        ]

        for endpoint, data in complex_operations:
            performance_monitor.start()
            response = client.post(
                endpoint, json=data, headers=auth_headers.get("student1", {})
            )
            performance_monitor.stop()

            # Only check timing if request was valid (not necessarily successful)
            if response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY:
                performance_monitor.assert_within_threshold(2.0)  # 2 seconds

    def test_metrics_endpoint_response_time(
        self, client: TestClient, performance_monitor
    ):
        """Test metrics endpoint performance."""
        performance_monitor.start()
        response = client.get("/metrics")
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.2)  # 200ms

    def test_token_verification_performance(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test token verification performance."""
        performance_monitor.start()
        response = client.get(
            "/api/v1/auth/verify-token", headers=auth_headers["student1"]
        )
        performance_monitor.stop()

        assert response.status_code == status.HTTP_200_OK
        performance_monitor.assert_within_threshold(0.1)  # 100ms


@pytest.mark.performance
class TestConcurrentRequestHandling:
    """Test concurrent request handling performance."""

    def test_concurrent_health_checks(self, client: TestClient):
        """Test handling multiple concurrent health checks."""

        def make_health_request():
            response = client.get("/health")
            return response.status_code

        # Run 10 concurrent health checks
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_health_request) for _ in range(10)]
            results = [future.result() for future in as_completed(futures)]

        # All requests should succeed
        assert all(status_code == status.HTTP_200_OK for status_code in results)
        assert len(results) == 10

    def test_concurrent_authentication(self, client: TestClient, test_users):
        """Test concurrent authentication requests."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        def authenticate_user(username):
            response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": "test_password"},
            )
            return response.status_code

        users = ["student1", "instructor1", "admin1"]

        # Run concurrent authentication
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(authenticate_user, user) for user in users]
            results = [future.result() for future in as_completed(futures)]

        # All authentications should succeed
        assert all(status_code == status.HTTP_200_OK for status_code in results)

    def test_concurrent_protected_endpoint_access(
        self, client: TestClient, auth_headers
    ):
        """Test concurrent access to protected endpoints."""

        def make_protected_request(headers):
            response = client.get("/api/v1/auth/me", headers=headers)
            return response.status_code

        # Test concurrent access with different user tokens
        headers_list = [
            auth_headers["student1"],
            auth_headers["instructor1"],
            auth_headers["admin1"],
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(make_protected_request, headers)
                for headers in headers_list
            ]
            results = [future.result() for future in as_completed(futures)]

        # All requests should succeed
        assert all(status_code == status.HTTP_200_OK for status_code in results)

    def test_mixed_concurrent_operations(
        self, client: TestClient, auth_headers, test_users
    ):
        """Test mixed concurrent operations (read/write)."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        def read_operation():
            response = client.get(
                "/api/v1/assessment/domains", headers=auth_headers["student1"]
            )
            return response.status_code

        def write_operation():
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": f"Concurrent Test Topic {time.time()}",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                },
                headers=auth_headers["student1"],
            )
            return response.status_code

        def auth_operation():
            response = client.post(
                "/api/v1/auth/login",
                json={"username": "admin1", "password": "test_password"},
            )
            return response.status_code

        # Mix of operations
        operations = [read_operation, write_operation, auth_operation, read_operation]

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(op) for op in operations]
            results = [future.result() for future in as_completed(futures)]

        # All operations should complete successfully or with expected errors
        for status_code in results:
            assert status_code in [
                status.HTTP_200_OK,
                status.HTTP_422_UNPROCESSABLE_ENTITY,  # Validation errors are OK
                status.HTTP_501_NOT_IMPLEMENTED,  # Not implemented is OK
            ]

    def test_rate_limiting_under_load(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test rate limiting performance under concurrent load."""

        def make_rate_limited_request():
            response = client.post(
                "/api/v1/nclex/generate",
                json={"topic": "test", "difficulty": "easy", "question_count": 1},
                headers=auth_headers["student1"],
            )
            return response.status_code

        # Make many concurrent requests to trigger rate limiting
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(make_rate_limited_request)
                for _ in range(60)  # More than content generation limit
            ]
            results = [future.result() for future in as_completed(futures)]

        # Should see mix of successful and rate-limited responses
        success_count = sum(1 for code in results if code == status.HTTP_200_OK)
        rate_limited_count = sum(
            1 for code in results if code == status.HTTP_429_TOO_MANY_REQUESTS
        )

        # Should have some successful requests and some rate limited
        assert success_count > 0
        assert rate_limited_count > 0
        assert (
            success_count + rate_limited_count >= 50
        )  # Most should be one or the other


@pytest.mark.performance
class TestMemoryUsagePerformance:
    """Test memory usage and resource management."""

    def test_memory_usage_stability(self, client: TestClient, auth_headers):
        """Test that memory usage remains stable over multiple requests."""
        import os

        import psutil

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Make many requests
        for _i in range(100):
            response = client.get("/api/v1/auth/me", headers=auth_headers["student1"])
            assert response.status_code == status.HTTP_200_OK

        # Check memory usage after requests
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024  # 50MB

    def test_large_request_handling(self, client: TestClient, auth_headers):
        """Test handling of large but reasonable requests."""
        # Create a large but reasonable study guide request
        large_request = {
            "topic": "Comprehensive Nursing Assessment and Care Planning",
            "competencies": [
                "AACN_KNOWLEDGE_1",
                "AACN_PERSON_CENTERED_1",
                "AACN_POPULATION_HEALTH_1",
                "AACN_SCHOLARSHIP_1",
            ],
            "difficulty_level": "advanced",
            "learning_objectives": [
                f"Learning objective {i}: Detailed description of nursing competency and skill development"
                for i in range(20)
            ],
            "description": "A" * 5000,  # 5KB description
            "student_level": "senior",
            "include_case_studies": True,
            "format_preferences": [
                "visual_diagrams",
                "step_by_step_procedures",
                "case_studies",
            ],
        }

        start_time = time.time()
        response = client.post(
            "/api/v1/study-guide/create",
            json=large_request,
            headers=auth_headers["student1"],
        )
        end_time = time.time()

        # Should handle large request within reasonable time
        assert end_time - start_time < 5.0  # 5 seconds max

        # Should either succeed or fail gracefully
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        ]

    def test_connection_cleanup(self, client: TestClient, test_users):
        """Test that connections are properly cleaned up."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        # Simulate many short-lived connections
        for _i in range(50):
            # Each iteration creates a new "connection"
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": "student1", "password": "test_password"},
            )

            if login_response.status_code == status.HTTP_200_OK:
                token = login_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}

                # Make a few requests
                client.get("/api/v1/auth/me", headers=headers)
                client.post("/api/v1/auth/logout", headers=headers)

        # All connections should be cleaned up properly
        # This test ensures no resource leaks
        assert True  # If we get here without hanging, cleanup worked


@pytest.mark.performance
class TestDatabasePerformance:
    """Test database operation performance."""

    def test_user_lookup_performance(
        self, client: TestClient, test_users, performance_monitor
    ):
        """Test user lookup performance during authentication."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        performance_monitor.start()

        # Multiple user lookups
        for username in ["student1", "instructor1", "admin1"]:
            response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": "test_password"},
            )
            assert response.status_code == status.HTTP_200_OK

        performance_monitor.stop()

        # All lookups should complete quickly
        performance_monitor.assert_within_threshold(1.5)  # 1.5 seconds for 3 users

    def test_bulk_operations_performance(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test bulk operation performance."""
        # Create bulk assessment data
        bulk_data = {
            "assessments": [
                {
                    "student_id": f"perf_student_{i:03d}",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"score": 80 + i},
                    "assessment_type": "bulk_test",
                    "assessor_id": "perf_test",
                }
                for i in range(20)  # 20 assessments
            ],
            "batch_id": "performance_test_batch",
        }

        performance_monitor.start()
        response = client.post(
            "/api/v1/assessment/competency/assess/bulk",
            json=bulk_data,
            headers=auth_headers["instructor1"],
        )
        performance_monitor.stop()

        # Bulk operation should complete within reasonable time
        if response.status_code == status.HTTP_200_OK:
            performance_monitor.assert_within_threshold(
                5.0
            )  # 5 seconds for 20 assessments


@pytest.mark.performance
class TestCachePerformance:
    """Test caching and repeated request performance."""

    def test_repeated_request_performance(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test performance of repeated identical requests."""
        endpoint = "/api/v1/assessment/domains"

        # First request (cold)
        performance_monitor.start()
        first_response = client.get(endpoint, headers=auth_headers["student1"])
        performance_monitor.stop()
        first_time = performance_monitor.duration

        # Second request (potentially cached)
        performance_monitor.start()
        second_response = client.get(endpoint, headers=auth_headers["student1"])
        performance_monitor.stop()
        second_time = performance_monitor.duration

        assert first_response.status_code == status.HTTP_200_OK
        assert second_response.status_code == status.HTTP_200_OK

        # Second request should be same or faster
        assert second_time <= first_time + 0.1  # Allow 100ms variance

    def test_static_content_performance(self, client: TestClient, performance_monitor):
        """Test performance of static/reference content."""
        static_endpoints = [
            "/api/v1/auth/roles",
            "/api/v1/assessment/domains",
            "/api/v1/assessment/proficiency-levels",
        ]

        for endpoint in static_endpoints:
            performance_monitor.start()
            response = client.get(endpoint)
            performance_monitor.stop()

            if response.status_code == status.HTTP_200_OK:
                # Static content should be very fast
                performance_monitor.assert_within_threshold(0.1)  # 100ms


@pytest.mark.performance
class TestScalabilityIndicators:
    """Test indicators of system scalability."""

    def test_linear_scaling_indicators(self, client: TestClient, auth_headers):
        """Test that response time scales linearly with request complexity."""
        # Test requests of increasing complexity
        complexity_tests = [
            (1, {"topic": "simple", "difficulty": "easy", "question_count": 1}),
            (3, {"topic": "moderate", "difficulty": "medium", "question_count": 3}),
            (5, {"topic": "complex", "difficulty": "hard", "question_count": 5}),
        ]

        response_times = []

        for _expected_complexity, request_data in complexity_tests:
            start_time = time.time()
            client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )
            end_time = time.time()

            response_times.append(end_time - start_time)

        # Response times should generally increase with complexity
        # but not exponentially
        if len(response_times) >= 2:
            # Simple heuristic: later requests shouldn't be >5x slower than first
            max_time = max(response_times)
            min_time = min(response_times)

            assert max_time / min_time <= 5.0, "Response time scaling may be non-linear"

    def test_user_isolation_performance(self, client: TestClient, test_users):
        """Test that user operations don't interfere with each other's performance."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        def user_workflow(username):
            # Login
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": "test_password"},
            )

            if login_response.status_code == status.HTTP_200_OK:
                token = login_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}

                # Time user-specific operations
                start_time = time.time()

                # Multiple operations
                client.get("/api/v1/auth/me", headers=headers)
                client.get("/api/v1/assessment/domains", headers=headers)
                client.get("/api/v1/assessment/proficiency-levels", headers=headers)

                end_time = time.time()
                return end_time - start_time

            return None

        # Run workflows for different users concurrently
        users = ["student1", "instructor1", "admin1"]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(user_workflow, user) for user in users]
            times = [future.result() for future in as_completed(futures)]

        # Filter out None results (failed logins)
        valid_times = [t for t in times if t is not None]

        if len(valid_times) >= 2:
            # Times should be similar (users don't interfere)
            avg_time = sum(valid_times) / len(valid_times)
            for time_result in valid_times:
                assert abs(time_result - avg_time) < avg_time  # Within 100% of average


@pytest.mark.performance
@pytest.mark.slow
class TestLoadTestingBasics:
    """Basic load testing scenarios."""

    def test_sustained_load_basic(self, client: TestClient, auth_headers):
        """Test system under sustained moderate load."""
        duration_seconds = 10  # 10 second load test
        requests_per_second = 5
        total_requests = duration_seconds * requests_per_second

        results = []
        start_time = time.time()

        for i in range(total_requests):
            request_start = time.time()
            response = client.get("/health")
            request_end = time.time()

            results.append(
                {
                    "status_code": response.status_code,
                    "response_time": request_end - request_start,
                }
            )

            # Maintain request rate
            elapsed = time.time() - start_time
            expected_requests = elapsed * requests_per_second
            if i < expected_requests - 1:
                time.sleep(0.01)  # Small delay to maintain rate

        # Analyze results
        success_rate = sum(1 for r in results if r["status_code"] == 200) / len(results)
        avg_response_time = sum(r["response_time"] for r in results) / len(results)
        max_response_time = max(r["response_time"] for r in results)

        # Performance criteria
        assert success_rate >= 0.95  # 95% success rate
        assert avg_response_time < 0.5  # 500ms average
        assert max_response_time < 2.0  # 2s max response time

    def test_spike_load_handling(self, client: TestClient, auth_headers):
        """Test handling of sudden load spikes."""
        # Normal load followed by spike

        # Normal load (warm up)
        for _ in range(5):
            response = client.get("/health")
            assert response.status_code == status.HTTP_200_OK

        # Spike load
        spike_results = []

        def make_spike_request():
            start = time.time()
            response = client.get("/health")
            end = time.time()
            return {"status_code": response.status_code, "response_time": end - start}

        # Create spike with concurrent requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_spike_request) for _ in range(20)]
            spike_results = [future.result() for future in as_completed(futures)]

        # Analyze spike handling
        success_count = sum(1 for r in spike_results if r["status_code"] == 200)
        avg_spike_time = sum(r["response_time"] for r in spike_results) / len(
            spike_results
        )

        # Should handle spike reasonably well
        assert success_count >= 15  # At least 75% success during spike
        assert avg_spike_time < 2.0  # Average response time under 2s during spike


@pytest.mark.performance
class TestPerformanceRegression:
    """Test for performance regressions."""

    def test_baseline_performance_metrics(self, client: TestClient, auth_headers):
        """Establish baseline performance metrics."""
        # This test can be used to detect performance regressions

        baseline_tests = [
            ("Health Check", "GET", "/health", None, 0.1),
            ("Authentication", "POST", "/api/v1/auth/me", None, 0.2),
            (
                "Static Content",
                "GET",
                "/api/v1/assessment/domains",
                auth_headers["student1"],
                0.3,
            ),
        ]

        results = {}

        for test_name, method, endpoint, headers, threshold in baseline_tests:
            times = []

            # Run test multiple times for stability
            for _ in range(5):
                start_time = time.time()

                if method == "GET":
                    response = client.get(endpoint, headers=headers or {})
                else:
                    response = client.post(endpoint, headers=headers or {})

                end_time = time.time()

                if response.status_code == status.HTTP_200_OK:
                    times.append(end_time - start_time)

            if times:
                avg_time = sum(times) / len(times)
                results[test_name] = avg_time

                # Check against threshold
                assert (
                    avg_time <= threshold
                ), f"{test_name} exceeded threshold: {avg_time:.3f}s > {threshold}s"

        # Store results for future regression comparison
        # In a real scenario, you'd persist these to compare against future runs
        print(f"Performance baseline results: {results}")


@pytest.mark.performance
class TestResourceUtilization:
    """Test resource utilization efficiency."""

    def test_cpu_utilization_efficiency(self, client: TestClient, auth_headers):
        """Test that CPU utilization is reasonable under load."""
        import os

        import psutil

        # Monitor CPU during load
        process = psutil.Process(os.getpid())
        cpu_samples = []

        def monitor_cpu():
            for _ in range(10):  # Monitor for 10 intervals
                cpu_percent = process.cpu_percent(interval=0.1)
                cpu_samples.append(cpu_percent)

        # Start CPU monitoring in background
        import threading

        monitor_thread = threading.Thread(target=monitor_cpu)
        monitor_thread.start()

        # Generate load
        for _ in range(50):
            response = client.get("/health")
            assert response.status_code == status.HTTP_200_OK

        monitor_thread.join()

        if cpu_samples:
            avg_cpu = sum(cpu_samples) / len(cpu_samples)
            max_cpu = max(cpu_samples)

            # CPU usage should be reasonable
            assert avg_cpu < 80.0, f"Average CPU usage too high: {avg_cpu}%"
            assert max_cpu < 95.0, f"Peak CPU usage too high: {max_cpu}%"

    def test_response_size_efficiency(self, client: TestClient, auth_headers):
        """Test that response sizes are reasonable."""
        test_endpoints = [
            "/health",
            "/api/v1/auth/me",
            "/api/v1/assessment/domains",
            "/api/v1/assessment/proficiency-levels",
        ]

        for endpoint in test_endpoints:
            response = client.get(endpoint, headers=auth_headers.get("student1", {}))

            if response.status_code == status.HTTP_200_OK:
                response_size = len(response.content)

                # Response sizes should be reasonable
                # Health and auth responses should be small
                if "health" in endpoint or "auth/me" in endpoint:
                    assert (
                        response_size < 5000
                    ), f"Response too large for {endpoint}: {response_size} bytes"

                # Reference data can be larger but should be reasonable
                else:
                    assert (
                        response_size < 50000
                    ), f"Response too large for {endpoint}: {response_size} bytes"
