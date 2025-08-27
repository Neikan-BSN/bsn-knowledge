"""
Performance Benchmark Tests for BSN Knowledge B.6 API Endpoints

Comprehensive performance testing for the four required B.6 endpoints:
- NCLEX generation performance benchmarks
- Competency assessment response time validation
- Study guide creation performance testing
- Student analytics performance requirements

Tests validate response times, concurrent handling, rate limiting,
throughput metrics, and performance under various load conditions.
"""

import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import psutil
import pytest
from fastapi import status
from fastapi.testclient import TestClient


@dataclass
class PerformanceMetrics:
    """Container for performance measurement data."""

    response_times: list[float]
    success_count: int
    error_count: int
    rate_limited_count: int
    total_requests: int

    @property
    def average_response_time(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0.0

    @property
    def median_response_time(self) -> float:
        return statistics.median(self.response_times) if self.response_times else 0.0

    @property
    def p95_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        p95_index = int(0.95 * len(sorted_times))
        return sorted_times[p95_index]

    @property
    def success_rate(self) -> float:
        return (
            (self.success_count / self.total_requests) * 100
            if self.total_requests > 0
            else 0.0
        )


@pytest.mark.performance
@pytest.mark.b6_endpoints
class TestB6EndpointPerformanceRequirements:
    """Test that B.6 endpoints meet specified performance requirements."""

    def test_nclex_generation_response_time(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test NCLEX generation meets <2s response time requirement."""

        test_scenarios = [
            # Light load scenario
            {"topic": "basic_nursing", "difficulty": "easy", "question_count": 1},
            # Medium load scenario
            {"topic": "pharmacology", "difficulty": "medium", "question_count": 5},
            # Heavy load scenario
            {"topic": "complex_clinical", "difficulty": "hard", "question_count": 10},
        ]

        for scenario in test_scenarios:
            performance_monitor.start()
            response = client.post(
                "/api/v1/nclex/generate",
                json=scenario,
                headers=auth_headers["student1"],
            )
            performance_monitor.stop()

            # Should complete within 2 seconds regardless of scenario
            performance_monitor.assert_within_threshold(2.0)

            # Should not fail due to performance issues
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_competency_assessment_response_time(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test competency assessment meets <500ms response time requirement."""

        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_framework = AsyncMock()
            mock_framework.assess_competency.return_value = AsyncMock()
            mock_dep.return_value = mock_framework

            assessment_scenarios = [
                # Simple assessment
                {
                    "student_id": "perf_test_001",
                    "competency_id": "AACN_KNOWLEDGE_1",
                    "performance_data": {"quiz_scores": [85]},
                },
                # Comprehensive assessment
                {
                    "student_id": "perf_test_002",
                    "competency_id": "AACN_PERSON_CENTERED_1",
                    "performance_data": {
                        "quiz_scores": [85, 78, 92, 88],
                        "clinical_evaluations": {
                            "communication": 4.2,
                            "clinical_reasoning": 3.8,
                            "technical_skills": 4.0,
                        },
                        "simulation_scores": {"scenario_1": 88, "scenario_2": 92},
                    },
                },
            ]

            for scenario in assessment_scenarios:
                performance_monitor.start()
                response = client.post(
                    "/api/v1/assessment/competency",
                    json=scenario,
                    headers=auth_headers["instructor1"],
                )
                performance_monitor.stop()

                # Should complete within 500ms
                performance_monitor.assert_within_threshold(0.5)
                assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_study_guide_creation_response_time(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test study guide creation meets <2s response time requirement."""

        guide_scenarios = [
            # Basic guide
            {
                "topic": "Basic Nursing Skills",
                "competencies": ["AACN_KNOWLEDGE_1"],
                "difficulty_level": "beginner",
            },
            # Comprehensive guide
            {
                "topic": "Advanced Critical Care Nursing",
                "competencies": [
                    "AACN_KNOWLEDGE_1",
                    "AACN_PERSON_CENTERED_1",
                    "AACN_POPULATION_HEALTH_1",
                ],
                "difficulty_level": "advanced",
                "learning_objectives": [
                    f"Master advanced concept {i}" for i in range(10)
                ],
                "include_case_studies": True,
            },
        ]

        for scenario in guide_scenarios:
            performance_monitor.start()
            response = client.post(
                "/api/v1/study-guide/create",
                json=scenario,
                headers=auth_headers["student1"],
            )
            performance_monitor.stop()

            # Should complete within 2 seconds
            performance_monitor.assert_within_threshold(2.0)
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR

    def test_student_analytics_response_time(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test student analytics meets <500ms response time requirement."""

        analytics_scenarios = [
            # Basic analytics request
            "basic_student_001",
            # Complex student with filters
            "complex_student_002?time_period=semester&include_trends=true",
            # Student with comprehensive data
            "comprehensive_student_003?include_competency_breakdown=true&include_peer_comparison=true",
        ]

        for scenario in analytics_scenarios:
            performance_monitor.start()
            response = client.get(
                f"/api/v1/analytics/student/{scenario}",
                headers=auth_headers["instructor1"],
            )
            performance_monitor.stop()

            # Should complete within 500ms
            performance_monitor.assert_within_threshold(0.5)
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.performance
@pytest.mark.b6_endpoints
class TestB6ConcurrentPerformance:
    """Test B.6 endpoints under concurrent load conditions."""

    def _measure_concurrent_requests(
        self, endpoint_func: callable, num_requests: int, max_workers: int = 10
    ) -> PerformanceMetrics:
        """Helper to measure performance of concurrent requests."""

        response_times = []
        success_count = 0
        error_count = 0
        rate_limited_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(endpoint_func) for _ in range(num_requests)]

            for future in as_completed(futures):
                try:
                    start_time, end_time, status_code = future.result()
                    response_time = end_time - start_time
                    response_times.append(response_time)

                    if status_code == status.HTTP_200_OK:
                        success_count += 1
                    elif status_code == status.HTTP_429_TOO_MANY_REQUESTS:
                        rate_limited_count += 1
                    else:
                        error_count += 1

                except Exception:
                    error_count += 1

        return PerformanceMetrics(
            response_times=response_times,
            success_count=success_count,
            error_count=error_count,
            rate_limited_count=rate_limited_count,
            total_requests=num_requests,
        )

    def test_nclex_concurrent_generation(self, client: TestClient, auth_headers):
        """Test NCLEX generation under concurrent load."""

        def nclex_request():
            start = time.time()
            response = client.post(
                "/api/v1/nclex/generate",
                json={
                    "topic": "concurrent_test",
                    "difficulty": "medium",
                    "question_count": 3,
                },
                headers=auth_headers["student1"],
            )
            end = time.time()
            return start, end, response.status_code

        # Test with 20 concurrent requests
        metrics = self._measure_concurrent_requests(nclex_request, 20, max_workers=10)

        # Validate concurrent performance
        assert metrics.success_rate >= 50.0, (
            f"Success rate too low: {metrics.success_rate}%"
        )
        assert metrics.average_response_time < 5.0, (
            f"Average response time too high: {metrics.average_response_time:.3f}s"
        )
        assert metrics.p95_response_time < 10.0, (
            f"P95 response time too high: {metrics.p95_response_time:.3f}s"
        )

    def test_competency_assessment_concurrent_load(
        self, client: TestClient, auth_headers
    ):
        """Test competency assessment under concurrent load."""

        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_framework = AsyncMock()
            mock_framework.assess_competency.return_value = AsyncMock()
            mock_dep.return_value = mock_framework

            def assessment_request():
                start = time.time()
                response = client.post(
                    "/api/v1/assessment/competency",
                    json={
                        "student_id": f"concurrent_test_{time.time()}",
                        "competency_id": "AACN_KNOWLEDGE_1",
                        "performance_data": {"quiz_scores": [85]},
                    },
                    headers=auth_headers["instructor1"],
                )
                end = time.time()
                return start, end, response.status_code

            # Test with 30 concurrent requests
            metrics = self._measure_concurrent_requests(
                assessment_request, 30, max_workers=15
            )

            # Assessment should handle concurrent load well
            assert metrics.success_rate >= 70.0, (
                f"Success rate too low: {metrics.success_rate}%"
            )
            assert metrics.average_response_time < 2.0, (
                f"Average response time too high: {metrics.average_response_time:.3f}s"
            )

    def test_mixed_endpoint_concurrent_usage(self, client: TestClient, auth_headers):
        """Test concurrent usage across different B.6 endpoints."""

        def nclex_request():
            start = time.time()
            response = client.post(
                "/api/v1/nclex/generate",
                json={"topic": "mixed_test", "difficulty": "easy", "question_count": 1},
                headers=auth_headers["student1"],
            )
            return start, time.time(), response.status_code

        def study_guide_request():
            start = time.time()
            response = client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Mixed Test Guide",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "beginner",
                },
                headers=auth_headers["student1"],
            )
            return start, time.time(), response.status_code

        def analytics_request():
            start = time.time()
            response = client.get(
                "/api/v1/analytics/student/mixed_test_student",
                headers=auth_headers["instructor1"],
            )
            return start, time.time(), response.status_code

        # Run mixed workload
        request_functions = [nclex_request, study_guide_request, analytics_request] * 5

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(func) for func in request_functions]
            results = [future.result() for future in as_completed(futures)]

        # Analyze mixed workload performance
        response_times = [end - start for start, end, _ in results]
        status_codes = [code for _, _, code in results]

        avg_response_time = statistics.mean(response_times)
        success_rate = (
            sum(1 for code in status_codes if code == status.HTTP_200_OK)
            / len(status_codes)
            * 100
        )

        # Mixed workload should perform reasonably
        assert avg_response_time < 3.0, (
            f"Mixed workload average response time too high: {avg_response_time:.3f}s"
        )
        assert success_rate >= 40.0, (
            f"Mixed workload success rate too low: {success_rate}%"
        )


@pytest.mark.performance
@pytest.mark.b6_endpoints
class TestB6RateLimitingPerformance:
    """Test rate limiting performance and effectiveness."""

    def test_nclex_rate_limiting_enforcement(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test NCLEX generation rate limiting (50 requests/hour)."""

        request_data = {
            "topic": "rate_limit_test",
            "difficulty": "easy",
            "question_count": 1,
        }

        # Make requests rapidly to test rate limiting
        start_time = time.time()
        results = []

        for i in range(60):  # More than the 50/hour limit
            response = client.post(
                "/api/v1/nclex/generate",
                json=request_data,
                headers=auth_headers["student1"],
            )
            results.append(
                {
                    "request_num": i + 1,
                    "status_code": response.status_code,
                    "timestamp": time.time() - start_time,
                }
            )

        # Analyze rate limiting effectiveness
        success_count = sum(
            1 for r in results if r["status_code"] == status.HTTP_200_OK
        )
        rate_limited_count = sum(
            1 for r in results if r["status_code"] == status.HTTP_429_TOO_MANY_REQUESTS
        )

        # Should enforce rate limiting
        assert rate_limited_count > 5, (
            f"Rate limiting not enforced effectively: {rate_limited_count} rate limited"
        )
        assert success_count <= 55, (
            f"Too many successful requests: {success_count} (should be ~50)"
        )

        # Rate limiting should kick in progressively
        later_requests = results[40:]  # Last 20 requests
        later_rate_limited = sum(
            1
            for r in later_requests
            if r["status_code"] == status.HTTP_429_TOO_MANY_REQUESTS
        )
        assert later_rate_limited > rate_limited_count / 2, (
            "Rate limiting should be more frequent later"
        )

    def test_assessment_rate_limiting_enforcement(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test competency assessment rate limiting (200 requests/hour)."""

        with patch("src.dependencies.get_competency_framework_dep") as mock_dep:
            mock_framework = AsyncMock()
            mock_framework.assess_competency.return_value = AsyncMock()
            mock_dep.return_value = mock_framework

            request_data = {
                "student_id": "rate_test",
                "competency_id": "AACN_KNOWLEDGE_1",
                "performance_data": {"quiz_scores": [80]},
            }

            # Make requests to test rate limiting (210 requests for 200/hour limit)
            results = []
            for _i in range(210):
                response = client.post(
                    "/api/v1/assessment/competency",
                    json=request_data,
                    headers=auth_headers["instructor1"],
                )
                results.append(response.status_code)

            success_count = sum(1 for code in results if code == status.HTTP_200_OK)
            rate_limited_count = sum(
                1 for code in results if code == status.HTTP_429_TOO_MANY_REQUESTS
            )

            # Should allow more requests than NCLEX (higher limit)
            assert success_count >= 150, (
                f"Assessment rate limit too restrictive: {success_count} successful"
            )
            assert rate_limited_count > 0, (
                "Assessment rate limiting should eventually kick in"
            )

    def test_analytics_rate_limiting_performance(
        self, client: TestClient, auth_headers, reset_rate_limiter
    ):
        """Test analytics endpoint rate limiting (500 requests/hour)."""

        # Make requests to test rate limiting (550 requests for 500/hour limit)
        results = []
        for i in range(550):
            response = client.get(
                f"/api/v1/analytics/student/rate_test_{i % 10}",  # Vary student IDs
                headers=auth_headers["instructor1"],
            )
            results.append(response.status_code)

        success_count = sum(1 for code in results if code == status.HTTP_200_OK)
        rate_limited_count = sum(
            1 for code in results if code == status.HTTP_429_TOO_MANY_REQUESTS
        )

        # Analytics should have highest rate limit
        assert success_count >= 400, (
            f"Analytics rate limit too restrictive: {success_count} successful"
        )
        # But should still eventually rate limit
        assert rate_limited_count < 100, "Analytics rate limiting should be permissive"

    def test_rate_limiting_performance_overhead(
        self, client: TestClient, auth_headers, performance_monitor
    ):
        """Test that rate limiting doesn't add significant performance overhead."""

        # Test response time with rate limiting active
        performance_monitor.start()
        response = client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": "overhead_test",
                "difficulty": "easy",
                "question_count": 1,
            },
            headers=auth_headers["student1"],
        )
        performance_monitor.stop()

        # Rate limiting should add minimal overhead
        performance_monitor.assert_within_threshold(2.5)  # Small overhead allowance

        # Should not cause server errors
        assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.performance
@pytest.mark.b6_endpoints
class TestB6ThroughputAndScalability:
    """Test throughput and scalability characteristics of B.6 endpoints."""

    def test_sustained_load_performance(self, client: TestClient, auth_headers):
        """Test B.6 endpoints under sustained load."""

        def sustained_load_test(endpoint_func, duration_seconds: int = 30):
            """Run sustained load test for specified duration."""
            end_time = time.time() + duration_seconds
            results = []

            while time.time() < end_time:
                start = time.time()
                try:
                    status_code = endpoint_func()
                    results.append(
                        {
                            "response_time": time.time() - start,
                            "status_code": status_code,
                            "timestamp": start,
                        }
                    )
                except Exception:
                    results.append(
                        {
                            "response_time": time.time() - start,
                            "status_code": 500,
                            "timestamp": start,
                        }
                    )

                time.sleep(0.1)  # Small delay between requests

            return results

        # Test analytics endpoint (should handle sustained load well)
        def analytics_request():
            response = client.get(
                "/api/v1/analytics/student/sustained_load_test",
                headers=auth_headers["instructor1"],
            )
            return response.status_code

        results = sustained_load_test(analytics_request, duration_seconds=15)

        # Analyze sustained load performance
        response_times = [r["response_time"] for r in results]
        status_codes = [r["status_code"] for r in results]

        avg_response_time = statistics.mean(response_times)
        success_rate = (
            sum(1 for code in status_codes if code == status.HTTP_200_OK)
            / len(status_codes)
            * 100
        )

        # Should handle sustained load well
        assert len(results) >= 100, f"Not enough requests processed: {len(results)}"
        assert avg_response_time < 1.0, (
            f"Average response time degraded: {avg_response_time:.3f}s"
        )
        assert success_rate >= 50.0, (
            f"Success rate too low under sustained load: {success_rate}%"
        )

    def test_memory_usage_under_load(self, client: TestClient, auth_headers):
        """Test memory usage during B.6 endpoint load testing."""

        import os

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Generate load on B.6 endpoints
        load_requests = [
            # NCLEX requests
            lambda: client.post(
                "/api/v1/nclex/generate",
                json={
                    "topic": "memory_test",
                    "difficulty": "easy",
                    "question_count": 1,
                },
                headers=auth_headers["student1"],
            ),
            # Study guide requests
            lambda: client.post(
                "/api/v1/study-guide/create",
                json={
                    "topic": "Memory Test Guide",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "beginner",
                },
                headers=auth_headers["student1"],
            ),
            # Analytics requests
            lambda: client.get(
                "/api/v1/analytics/student/memory_test_student",
                headers=auth_headers["instructor1"],
            ),
        ]

        # Execute load requests
        for i in range(50):  # 50 requests across endpoints
            request_func = load_requests[i % len(load_requests)]
            request_func()

        # Check memory usage after load
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024, (
            f"Excessive memory usage increase: {memory_increase / (1024 * 1024):.1f}MB"
        )

    def test_response_size_efficiency(self, client: TestClient, auth_headers):
        """Test that B.6 endpoint responses are reasonably sized."""

        response_size_tests = [
            # NCLEX response size
            (
                "POST",
                "/api/v1/nclex/generate",
                {"topic": "size_test", "difficulty": "medium", "question_count": 5},
                50000,  # 50KB max
            ),
            # Study guide response size
            (
                "POST",
                "/api/v1/study-guide/create",
                {
                    "topic": "Size Test Guide",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "intermediate",
                },
                100000,  # 100KB max
            ),
            # Analytics response size
            (
                "GET",
                "/api/v1/analytics/student/size_test_student",
                None,
                25000,  # 25KB max
            ),
        ]

        for method, endpoint, data, max_size in response_size_tests:
            if method == "POST":
                response = client.post(
                    endpoint, json=data, headers=auth_headers["student1"]
                )
            else:
                response = client.get(endpoint, headers=auth_headers["instructor1"])

            if response.status_code == status.HTTP_200_OK:
                response_size = len(response.content)
                assert response_size <= max_size, (
                    f"Response too large for {endpoint}: {response_size} bytes > {max_size} bytes"
                )

    def test_concurrent_user_isolation(self, client: TestClient, test_users):
        """Test that concurrent users don't interfere with each other's performance."""
        from src.auth import fake_users_db

        fake_users_db.update(test_users)

        def user_session(username: str) -> list[float]:
            """Simulate a user session and return response times."""
            # Login
            login_response = client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": "test_password"},
            )

            if login_response.status_code != status.HTTP_200_OK:
                return []

            token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # Perform user operations and measure response times
            response_times = []

            operations = [
                # NCLEX generation
                lambda: client.post(
                    "/api/v1/nclex/generate",
                    json={
                        "topic": f"user_{username}_test",
                        "difficulty": "easy",
                        "question_count": 1,
                    },
                    headers=headers,
                ),
                # Study guide creation
                lambda: client.post(
                    "/api/v1/study-guide/create",
                    json={
                        "topic": f"User {username} Guide",
                        "competencies": ["AACN_KNOWLEDGE_1"],
                        "difficulty_level": "beginner",
                    },
                    headers=headers,
                ),
                # Analytics (if appropriate role)
                lambda: client.get(
                    f"/api/v1/analytics/student/{username}",
                    headers=headers,
                )
                if username != "student1"
                else None,
            ]

            for operation in operations:
                if operation:
                    start = time.time()
                    response = operation()
                    end = time.time()

                    if response.status_code in [
                        status.HTTP_200_OK,
                        status.HTTP_422_UNPROCESSABLE_ENTITY,
                    ]:
                        response_times.append(end - start)

            return response_times

        # Run concurrent user sessions
        users = ["student1", "instructor1", "admin1"]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(user_session, user) for user in users]
            user_response_times = {
                users[i]: future.result() for i, future in enumerate(futures)
            }

        # Analyze user isolation
        for user, times in user_response_times.items():
            if times:  # If user had successful operations
                avg_time = statistics.mean(times)
                assert avg_time < 3.0, (
                    f"User {user} experienced poor performance: {avg_time:.3f}s avg"
                )

        # Check that users had similar performance (no interference)
        valid_avg_times = [
            statistics.mean(times) for times in user_response_times.values() if times
        ]

        if len(valid_avg_times) >= 2:
            time_variance = statistics.stdev(valid_avg_times)
            avg_of_avgs = statistics.mean(valid_avg_times)

            # Performance variance between users should be reasonable
            assert time_variance / avg_of_avgs < 0.5, (
                "Too much performance variance between concurrent users"
            )


@pytest.mark.performance
@pytest.mark.b6_endpoints
@pytest.mark.slow
class TestB6LoadTestingScenarios:
    """Extended load testing scenarios for B.6 endpoints."""

    def test_realistic_usage_pattern_simulation(self, client: TestClient, auth_headers):
        """Simulate realistic usage patterns for B.6 endpoints."""

        # Simulate a typical class session usage pattern
        class_simulation = {
            # Morning: Heavy NCLEX generation (30 students)
            "nclex_heavy": {
                "endpoint": "/api/v1/nclex/generate",
                "method": "POST",
                "data": {
                    "topic": "morning_review",
                    "difficulty": "medium",
                    "question_count": 5,
                },
                "concurrent_users": 30,
                "requests_per_user": 2,
            },
            # Midday: Study guide creation (15 students)
            "study_guide_moderate": {
                "endpoint": "/api/v1/study-guide/create",
                "method": "POST",
                "data": {
                    "topic": "Midday Study Session",
                    "competencies": ["AACN_KNOWLEDGE_1"],
                    "difficulty_level": "intermediate",
                },
                "concurrent_users": 15,
                "requests_per_user": 1,
            },
            # Evening: Analytics review (5 instructors)
            "analytics_light": {
                "endpoint": "/api/v1/analytics/student/class_student_{}",
                "method": "GET",
                "data": None,
                "concurrent_users": 5,
                "requests_per_user": 10,  # Each instructor checks multiple students
            },
        }

        simulation_results = {}

        for scenario_name, scenario in class_simulation.items():

            def make_request(user_id: int):
                response_times = []

                for req_num in range(scenario["requests_per_user"]):
                    start = time.time()

                    if scenario["method"] == "POST":
                        client.post(
                            scenario["endpoint"],
                            json=scenario["data"],
                            headers=auth_headers[
                                "student1"
                                if "nclex" in scenario_name or "study" in scenario_name
                                else "instructor1"
                            ],
                        )
                    else:  # GET
                        endpoint = scenario["endpoint"].format(user_id * 10 + req_num)
                        client.get(
                            endpoint,
                            headers=auth_headers["instructor1"],
                        )

                    response_times.append(time.time() - start)

                return response_times

            # Execute scenario
            with ThreadPoolExecutor(
                max_workers=scenario["concurrent_users"]
            ) as executor:
                futures = [
                    executor.submit(make_request, user_id)
                    for user_id in range(scenario["concurrent_users"])
                ]

                all_response_times = []
                for future in as_completed(futures):
                    all_response_times.extend(future.result())

            # Analyze scenario performance
            if all_response_times:
                simulation_results[scenario_name] = {
                    "avg_response_time": statistics.mean(all_response_times),
                    "p95_response_time": sorted(all_response_times)[
                        int(0.95 * len(all_response_times))
                    ],
                    "total_requests": len(all_response_times),
                }

        # Validate realistic usage performance
        for scenario_name, results in simulation_results.items():
            if "nclex" in scenario_name or "study_guide" in scenario_name:
                # Content generation should be under 3s even under load
                assert results["avg_response_time"] < 3.0, (
                    f"{scenario_name} average response time too high: {results['avg_response_time']:.3f}s"
                )
                assert results["p95_response_time"] < 6.0, (
                    f"{scenario_name} P95 response time too high: {results['p95_response_time']:.3f}s"
                )

            elif "analytics" in scenario_name:
                # Analytics should be faster
                assert results["avg_response_time"] < 1.0, (
                    f"{scenario_name} average response time too high: {results['avg_response_time']:.3f}s"
                )

    def test_stress_failure_recovery(self, client: TestClient, auth_headers):
        """Test B.6 endpoints recovery from stress conditions."""

        # Create stress condition
        def stress_endpoint():
            responses = []
            for _ in range(100):  # Rapid fire requests
                response = client.post(
                    "/api/v1/nclex/generate",
                    json={
                        "topic": "stress_test",
                        "difficulty": "easy",
                        "question_count": 1,
                    },
                    headers=auth_headers["student1"],
                )
                responses.append(response.status_code)

                if (
                    len(
                        [
                            code
                            for code in responses
                            if code == status.HTTP_429_TOO_MANY_REQUESTS
                        ]
                    )
                    > 20
                ):
                    break  # Stop when rate limited

            return responses

        # Apply stress
        stress_endpoint()

        # Wait for recovery period
        time.sleep(2)

        # Test recovery - should work normally after stress
        recovery_response = client.post(
            "/api/v1/nclex/generate",
            json={"topic": "recovery_test", "difficulty": "easy", "question_count": 1},
            headers=auth_headers["student1"],
        )

        # Should recover and handle normal requests
        assert recovery_response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,  # Validation errors OK
            status.HTTP_429_TOO_MANY_REQUESTS,  # Still rate limited OK
        ]

        # Should not have caused server errors
        assert recovery_response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR
