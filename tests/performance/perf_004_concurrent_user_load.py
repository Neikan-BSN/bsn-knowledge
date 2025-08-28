"""PERF-004: Concurrent User Load Testing.

Validates BSN Knowledge concurrent user capacity:
- 150+ concurrent users with realistic behavior patterns
- User session management and authentication token handling
- Response time distribution analysis (p50, p95, p99)
- Session-based workflows and state management
- Performance targets: >100 users, <200ms p95, <500ms p99
"""

import asyncio
import logging
import random
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from locust.env import Environment
from locust.stats import StatsCSV
from locust.user import HttpUser, between, task
from performance_benchmarks import benchmark_manager, record_concurrent_users

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class UserSession:
    """Represents an active user session."""

    session_id: str
    user_type: str
    start_time: datetime
    last_activity: datetime
    requests_made: int
    errors_encountered: int
    auth_token: str | None
    session_data: dict


@dataclass
class ConcurrentUserResults:
    """Results from concurrent user load testing."""

    # Test Configuration
    target_concurrent_users: int
    actual_peak_concurrent_users: int
    test_duration_minutes: float
    ramp_up_duration_minutes: float

    # Performance Metrics
    total_requests: int
    total_failures: int
    avg_response_time_ms: float
    p50_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    requests_per_second: float

    # Error Analysis
    error_rate_percent: float
    success_rate_percent: float
    error_distribution: dict[str, int]

    # Session Management
    total_sessions_created: int
    active_sessions_peak: int
    avg_session_duration_minutes: float
    session_timeout_rate: float
    auth_failure_rate: float

    # Response Time Distribution
    response_time_distribution: dict[str, float]
    slowest_endpoints: list[dict]
    fastest_endpoints: list[dict]

    # Concurrency Analysis
    user_spawn_rate_achieved: float
    concurrency_scaling_efficiency: float
    resource_contention_detected: bool

    # Target Compliance
    meets_concurrent_user_target: bool
    meets_response_time_targets: bool
    meets_error_rate_targets: bool

    @property
    def meets_all_targets(self) -> bool:
        """Check if all concurrent user targets are met."""
        return (
            self.meets_concurrent_user_target
            and self.meets_response_time_targets
            and self.meets_error_rate_targets
        )


class RealisticUserBehavior(HttpUser):
    """Realistic user behavior with session management."""

    wait_time = between(2, 10)  # Realistic think time
    weight = 1

    def on_start(self):
        """Initialize user session."""
        self.session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        self.user_type = random.choice(["student", "instructor", "admin"])
        self.session_start = datetime.now()
        self.requests_made = 0
        self.auth_token = None
        self.session_data = {}

        # Authenticate user
        self._authenticate_user()

        logger.debug(f"User session started: {self.session_id} ({self.user_type})")

    def on_stop(self):
        """Clean up user session."""
        session_duration = (datetime.now() - self.session_start).total_seconds() / 60
        logger.debug(
            f"User session ended: {self.session_id}, duration: {session_duration:.1f}min"
        )

    def _authenticate_user(self):
        """Authenticate user and get session token."""
        credentials = self._get_user_credentials()

        with self.client.post(
            "/api/v1/auth/login",
            json=credentials,
            name="auth_login",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                self.auth_token = response.json().get("access_token")
                self.session_data["authenticated"] = True
                response.success()
            else:
                self.session_data["authenticated"] = False
                response.failure(f"Authentication failed: {response.status_code}")

    def _get_user_credentials(self) -> dict:
        """Get user credentials based on user type."""
        user_pools = {
            "student": [
                (f"student_{i:03d}", "student_password") for i in range(1, 201)
            ],
            "instructor": [
                (f"instructor_{i:02d}", "instructor_password") for i in range(1, 21)
            ],
            "admin": [(f"admin_{i:02d}", "admin_password") for i in range(1, 6)],
        }

        username, password = random.choice(user_pools[self.user_type])
        return {"username": username, "password": password}

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}

    def _track_request(self):
        """Track request for session analysis."""
        self.requests_made += 1
        self.session_data["last_activity"] = datetime.now()

    @task(25)
    def user_dashboard_access(self):
        """User accesses their dashboard."""
        self._track_request()
        headers = self._get_auth_headers()

        with self.client.get(
            "/api/v1/dashboard",
            headers=headers,
            name="dashboard_access",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Dashboard access failed: {response.status_code}")

    @task(20)
    def nclex_question_generation(self):
        """Generate NCLEX questions."""
        if self.user_type != "student":
            return  # Only students generate questions for practice

        self._track_request()
        headers = self._get_auth_headers()

        topics = [
            "nursing_fundamentals",
            "pharmacology",
            "medical_surgical",
            "pediatric",
            "maternal_newborn",
            "mental_health",
        ]

        request_data = {
            "topic": random.choice(topics),
            "difficulty": random.choice(["easy", "medium", "hard"]),
            "question_count": random.choice([5, 10, 15, 20]),
            "include_rationale": random.choice([True, False]),
        }

        with self.client.post(
            "/api/v1/nclex/generate",
            json=request_data,
            headers=headers,
            name="nclex_generation",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"NCLEX generation failed: {response.status_code}")

    @task(15)
    def study_guide_creation(self):
        """Create study guides."""
        self._track_request()
        headers = self._get_auth_headers()

        competencies = [
            "AACN_KNOWLEDGE_1",
            "AACN_KNOWLEDGE_2",
            "AACN_PERSON_CENTERED_1",
            "AACN_POPULATION_HEALTH_1",
            "AACN_SCHOLARSHIP_1",
        ]

        request_data = {
            "topic": random.choice(
                [
                    "Basic Patient Care",
                    "Medication Administration",
                    "Infection Control",
                    "Cardiovascular Assessment",
                    "Respiratory Care",
                ]
            ),
            "competencies": random.sample(competencies, random.randint(1, 3)),
            "difficulty_level": random.choice(["beginner", "intermediate", "advanced"]),
        }

        with self.client.post(
            "/api/v1/study-guide/create",
            json=request_data,
            headers=headers,
            name="study_guide_creation",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Study guide creation failed: {response.status_code}")

    @task(12)
    def analytics_access(self):
        """Access analytics and progress data."""
        self._track_request()
        headers = self._get_auth_headers()

        # Different analytics based on user type
        if self.user_type == "student":
            endpoint = "/api/v1/analytics/student/progress"
        elif self.user_type == "instructor":
            endpoint = "/api/v1/analytics/class/overview"
        else:  # admin
            endpoint = "/api/v1/analytics/system/overview"

        with self.client.get(
            endpoint, headers=headers, name="analytics_access", catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Analytics access failed: {response.status_code}")

    @task(10)
    def assessment_operations(self):
        """Perform assessment-related operations."""
        if self.user_type == "student":
            return  # Students don't create assessments

        self._track_request()
        headers = self._get_auth_headers()

        if self.user_type == "instructor":
            # Create competency assessment
            assessment_data = {
                "student_id": f"student_{random.randint(1, 200):03d}",
                "competency_id": random.choice(
                    [
                        "AACN_KNOWLEDGE_1",
                        "AACN_PERSON_CENTERED_1",
                        "AACN_POPULATION_HEALTH_1",
                    ]
                ),
                "performance_data": {
                    "quiz_scores": [random.randint(70, 95) for _ in range(3)],
                    "clinical_evaluation_score": random.randint(75, 95),
                },
                "assessment_type": "comprehensive",
            }

            with self.client.post(
                "/api/v1/assessment/competency/assess",
                json=assessment_data,
                headers=headers,
                name="create_assessment",
                catch_response=True,
            ) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(
                        f"Assessment creation failed: {response.status_code}"
                    )

    @task(8)
    def profile_management(self):
        """User profile and settings management."""
        self._track_request()
        headers = self._get_auth_headers()

        # Get current profile
        with self.client.get(
            "/api/v1/auth/me",
            headers=headers,
            name="profile_access",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Profile access failed: {response.status_code}")

        # Update profile occasionally
        if random.random() < 0.3:  # 30% chance
            profile_update = {
                "preferences": {
                    "theme": random.choice(["light", "dark"]),
                    "notifications": random.choice([True, False]),
                }
            }

            with self.client.patch(
                "/api/v1/auth/profile",
                json=profile_update,
                headers=headers,
                name="profile_update",
                catch_response=True,
            ) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Profile update failed: {response.status_code}")

    @task(5)
    def search_operations(self):
        """Search functionality testing."""
        self._track_request()
        headers = self._get_auth_headers()

        search_terms = [
            "nursing fundamentals",
            "patient assessment",
            "medication administration",
            "infection control",
            "cardiovascular",
            "respiratory care",
            "pain management",
        ]

        search_data = {
            "query": random.choice(search_terms),
            "filters": {
                "content_type": random.choice(["study_guide", "nclex_question", "all"]),
                "difficulty": random.choice(["easy", "medium", "hard", "all"]),
            },
        }

        with self.client.post(
            "/api/v1/search",
            json=search_data,
            headers=headers,
            name="search_operation",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Search operation failed: {response.status_code}")


class SessionManager:
    """Manages user sessions during concurrent load testing."""

    def __init__(self):
        self.active_sessions: dict[str, UserSession] = {}
        self.session_stats = {
            "created": 0,
            "active": 0,
            "expired": 0,
            "total_duration": 0.0,
        }

    def create_session(
        self, session_id: str, user_type: str, auth_token: str | None = None
    ) -> UserSession:
        """Create a new user session."""
        session = UserSession(
            session_id=session_id,
            user_type=user_type,
            start_time=datetime.now(),
            last_activity=datetime.now(),
            requests_made=0,
            errors_encountered=0,
            auth_token=auth_token,
            session_data={},
        )

        self.active_sessions[session_id] = session
        self.session_stats["created"] += 1
        self.session_stats["active"] = len(self.active_sessions)

        return session

    def update_session_activity(self, session_id: str):
        """Update session last activity time."""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.last_activity = datetime.now()
            session.requests_made += 1

    def expire_inactive_sessions(self, timeout_minutes: int = 30):
        """Expire sessions that have been inactive."""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        expired_sessions = []

        for session_id, session in list(self.active_sessions.items()):
            if session.last_activity < cutoff_time:
                expired_sessions.append(session_id)
                session_duration = (
                    session.last_activity - session.start_time
                ).total_seconds() / 60
                self.session_stats["total_duration"] += session_duration
                del self.active_sessions[session_id]

        if expired_sessions:
            self.session_stats["expired"] += len(expired_sessions)
            self.session_stats["active"] = len(self.active_sessions)
            logger.debug(f"Expired {len(expired_sessions)} inactive sessions")

        return expired_sessions

    def get_session_statistics(self) -> dict:
        """Get session management statistics."""
        avg_duration = 0.0
        if self.session_stats["expired"] > 0:
            avg_duration = (
                self.session_stats["total_duration"] / self.session_stats["expired"]
            )

        return {
            **self.session_stats,
            "avg_session_duration_minutes": avg_duration,
            "peak_concurrent_sessions": max(
                self.session_stats["active"], len(self.active_sessions)
            ),
        }


class ConcurrentUserTester:
    """Comprehensive concurrent user load testing framework."""

    def __init__(
        self,
        target_url: str = "http://localhost:8000",
        target_users: int = 150,
        test_duration_minutes: int = 30,
        ramp_up_duration_minutes: int = 10,
    ):
        self.target_url = target_url
        self.target_users = target_users
        self.test_duration_minutes = test_duration_minutes
        self.ramp_up_duration_minutes = ramp_up_duration_minutes

        self.session_manager = SessionManager()
        self.performance_data = []

        logger.info("Concurrent User Tester initialized:")
        logger.info(f"  Target URL: {target_url}")
        logger.info(f"  Target Users: {target_users}")
        logger.info(f"  Test Duration: {test_duration_minutes} minutes")
        logger.info(f"  Ramp-up Duration: {ramp_up_duration_minutes} minutes")

    async def run_concurrent_user_test(self) -> ConcurrentUserResults:
        """Execute comprehensive concurrent user load testing."""
        logger.info("=" * 80)
        logger.info("STARTING PERF-004: CONCURRENT USER LOAD TESTING")
        logger.info("=" * 80)

        # Setup Locust environment
        env = Environment(user_classes=[RealisticUserBehavior], host=self.target_url)

        # Configure CSV stats collection
        stats_csv = StatsCSV(env, "concurrent_user_test")

        # Create local runner
        runner = env.create_local_runner()

        try:
            # Start the test with gradual ramp-up
            logger.info(
                f"Starting ramp-up: 0 → {self.target_users} users over {self.ramp_up_duration_minutes} minutes"
            )

            spawn_rate = self.target_users / (
                self.ramp_up_duration_minutes * 60
            )  # users per second
            runner.start(self.target_users, spawn_rate=spawn_rate)

            # Monitor during ramp-up
            await self._monitor_ramp_up(env, self.ramp_up_duration_minutes)

            # Run at full load
            logger.info(
                f"Ramp-up complete. Running at {self.target_users} concurrent users for {self.test_duration_minutes} minutes"
            )

            # Monitor during full load
            await self._monitor_full_load(env, self.test_duration_minutes)

            # Graceful shutdown
            logger.info("Initiating graceful test shutdown...")
            runner.quit()

            # Collect final statistics
            final_stats = self._collect_final_statistics(env)

        except Exception as e:
            logger.error(f"Test execution failed: {str(e)}")
            if runner:
                runner.quit()
            raise

        finally:
            # Stop CSV collection
            stats_csv.close()

        # Analyze results
        results = await self._analyze_concurrent_user_results(final_stats)

        # Generate report
        self._generate_concurrent_user_report(results)

        # Record metrics
        self._record_concurrent_user_metrics(results)

        return results

    async def _monitor_ramp_up(self, env: Environment, duration_minutes: int):
        """Monitor system during user ramp-up phase."""
        start_time = time.time()
        duration_seconds = duration_minutes * 60

        while time.time() - start_time < duration_seconds:
            current_users = len(env.runner.user_instances)
            current_rps = env.stats.total.current_rps

            logger.info(
                f"Ramp-up progress: {current_users}/{self.target_users} users, {current_rps:.1f} RPS"
            )

            # Session management
            self.session_manager.expire_inactive_sessions()

            # Wait before next check
            await asyncio.sleep(30)  # Check every 30 seconds

    async def _monitor_full_load(self, env: Environment, duration_minutes: int):
        """Monitor system during full load phase."""
        start_time = time.time()
        duration_seconds = duration_minutes * 60
        monitoring_interval = 15  # seconds

        while time.time() - start_time < duration_seconds:
            # Collect performance snapshot
            snapshot = self._take_performance_snapshot(env)
            self.performance_data.append(snapshot)

            current_users = len(env.runner.user_instances)
            current_rps = env.stats.total.current_rps
            avg_response_time = env.stats.total.avg_response_time
            error_rate = (
                env.stats.total.num_failures / max(1, env.stats.total.num_requests)
            ) * 100

            logger.info(
                f"Full load: {current_users} users, {current_rps:.1f} RPS, "
                f"avg response: {avg_response_time:.0f}ms, errors: {error_rate:.1f}%"
            )

            # Session management
            self.session_manager.expire_inactive_sessions()

            # Check for performance issues
            if avg_response_time > 5000:  # 5 second threshold
                logger.warning(
                    f"High response time detected: {avg_response_time:.0f}ms"
                )

            if error_rate > 10:  # 10% error rate threshold
                logger.warning(f"High error rate detected: {error_rate:.1f}%")

            await asyncio.sleep(monitoring_interval)

    def _take_performance_snapshot(self, env: Environment) -> dict:
        """Take a performance snapshot."""
        stats = env.stats.total

        return {
            "timestamp": datetime.now(),
            "current_users": len(env.runner.user_instances),
            "requests_per_second": stats.current_rps,
            "avg_response_time_ms": stats.avg_response_time,
            "total_requests": stats.num_requests,
            "total_failures": stats.num_failures,
            "error_rate_percent": (stats.num_failures / max(1, stats.num_requests))
            * 100,
        }

    def _collect_final_statistics(self, env: Environment) -> dict:
        """Collect final test statistics."""
        stats = env.stats.total
        session_stats = self.session_manager.get_session_statistics()

        # Calculate response time percentiles
        response_times = list(stats.response_times.keys())
        response_time_counts = list(stats.response_times.values())

        # Weighted percentiles calculation
        total_requests = sum(response_time_counts)
        if total_requests > 0:
            # Create weighted list for percentile calculation
            weighted_response_times = []
            for rt, count in zip(response_times, response_time_counts, strict=False):
                weighted_response_times.extend([rt] * count)

            p50 = statistics.median(weighted_response_times)
            p95 = (
                statistics.quantiles(weighted_response_times, n=20)[18]
                if len(weighted_response_times) >= 20
                else max(weighted_response_times)
            )
            p99 = (
                statistics.quantiles(weighted_response_times, n=100)[98]
                if len(weighted_response_times) >= 100
                else max(weighted_response_times)
            )
        else:
            p50 = p95 = p99 = 0

        # Endpoint performance analysis
        endpoint_stats = []
        for name, stat_entry in env.stats.entries.items():
            endpoint_stats.append(
                {
                    "name": name,
                    "requests": stat_entry.num_requests,
                    "failures": stat_entry.num_failures,
                    "avg_response_time": stat_entry.avg_response_time,
                    "min_response_time": stat_entry.min_response_time,
                    "max_response_time": stat_entry.max_response_time,
                }
            )

        # Sort endpoints by performance
        slowest_endpoints = sorted(
            endpoint_stats, key=lambda x: x["avg_response_time"], reverse=True
        )[:5]
        fastest_endpoints = sorted(
            endpoint_stats, key=lambda x: x["avg_response_time"]
        )[:5]

        return {
            "locust_stats": stats,
            "session_stats": session_stats,
            "response_time_percentiles": {
                "p50": p50,
                "p95": p95,
                "p99": p99,
            },
            "endpoint_stats": endpoint_stats,
            "slowest_endpoints": slowest_endpoints,
            "fastest_endpoints": fastest_endpoints,
            "performance_snapshots": self.performance_data,
        }

    async def _analyze_concurrent_user_results(
        self, final_stats: dict
    ) -> ConcurrentUserResults:
        """Analyze concurrent user test results."""
        stats = final_stats["locust_stats"]
        session_stats = final_stats["session_stats"]
        percentiles = final_stats["response_time_percentiles"]

        # Calculate peak concurrent users achieved
        peak_users = max(
            (snapshot["current_users"] for snapshot in self.performance_data),
            default=self.target_users,
        )

        # Error distribution
        error_distribution = {}
        for name, stat_entry in stats.entries.items():
            if stat_entry.num_failures > 0:
                error_distribution[name] = stat_entry.num_failures

        # Response time distribution analysis
        response_time_ranges = {
            "<100ms": 0,
            "100-200ms": 0,
            "200-500ms": 0,
            "500ms-1s": 0,
            "1-2s": 0,
            ">2s": 0,
        }

        for rt, count in stats.response_times.items():
            if rt < 100:
                response_time_ranges["<100ms"] += count
            elif rt < 200:
                response_time_ranges["100-200ms"] += count
            elif rt < 500:
                response_time_ranges["200-500ms"] += count
            elif rt < 1000:
                response_time_ranges["500ms-1s"] += count
            elif rt < 2000:
                response_time_ranges["1-2s"] += count
            else:
                response_time_ranges[">2s"] += count

        # Normalize to percentages
        total_requests = sum(response_time_ranges.values())
        if total_requests > 0:
            response_time_distribution = {
                k: (v / total_requests) * 100 for k, v in response_time_ranges.items()
            }
        else:
            response_time_distribution = response_time_ranges

        # Calculate target compliance
        meets_concurrent_user_target = peak_users >= 100  # Target: >100 users
        meets_response_time_targets = (
            percentiles["p95"] < 200 and percentiles["p99"] < 500
        )  # Target: <200ms p95, <500ms p99
        meets_error_rate_targets = (
            stats.num_failures / max(1, stats.num_requests)
        ) * 100 < 1.0  # Target: <1% error rate

        return ConcurrentUserResults(
            # Test Configuration
            target_concurrent_users=self.target_users,
            actual_peak_concurrent_users=peak_users,
            test_duration_minutes=self.test_duration_minutes,
            ramp_up_duration_minutes=self.ramp_up_duration_minutes,
            # Performance Metrics
            total_requests=stats.num_requests,
            total_failures=stats.num_failures,
            avg_response_time_ms=stats.avg_response_time,
            p50_response_time_ms=percentiles["p50"],
            p95_response_time_ms=percentiles["p95"],
            p99_response_time_ms=percentiles["p99"],
            requests_per_second=stats.total_rps,
            # Error Analysis
            error_rate_percent=(stats.num_failures / max(1, stats.num_requests)) * 100,
            success_rate_percent=(
                (stats.num_requests - stats.num_failures) / max(1, stats.num_requests)
            )
            * 100,
            error_distribution=error_distribution,
            # Session Management
            total_sessions_created=session_stats["created"],
            active_sessions_peak=session_stats["peak_concurrent_sessions"],
            avg_session_duration_minutes=session_stats["avg_session_duration_minutes"],
            session_timeout_rate=(
                session_stats["expired"] / max(1, session_stats["created"])
            )
            * 100,
            auth_failure_rate=0.0,  # Would need to track separately
            # Response Time Distribution
            response_time_distribution=response_time_distribution,
            slowest_endpoints=final_stats["slowest_endpoints"],
            fastest_endpoints=final_stats["fastest_endpoints"],
            # Concurrency Analysis
            user_spawn_rate_achieved=peak_users / (self.ramp_up_duration_minutes * 60),
            concurrency_scaling_efficiency=self._calculate_scaling_efficiency(),
            resource_contention_detected=self._detect_resource_contention(),
            # Target Compliance
            meets_concurrent_user_target=meets_concurrent_user_target,
            meets_response_time_targets=meets_response_time_targets,
            meets_error_rate_targets=meets_error_rate_targets,
        )

    def _calculate_scaling_efficiency(self) -> float:
        """Calculate how efficiently the system scales with concurrent users."""
        if len(self.performance_data) < 2:
            return 1.0

        # Compare throughput per user at different concurrency levels
        early_data = self.performance_data[: len(self.performance_data) // 3]
        late_data = self.performance_data[-len(self.performance_data) // 3 :]

        if not early_data or not late_data:
            return 1.0

        early_avg_rps_per_user = statistics.mean(
            snapshot["requests_per_second"] / max(1, snapshot["current_users"])
            for snapshot in early_data
        )
        late_avg_rps_per_user = statistics.mean(
            snapshot["requests_per_second"] / max(1, snapshot["current_users"])
            for snapshot in late_data
        )

        if early_avg_rps_per_user == 0:
            return 1.0

        return late_avg_rps_per_user / early_avg_rps_per_user

    def _detect_resource_contention(self) -> bool:
        """Detect if resource contention is affecting performance."""
        if len(self.performance_data) < 10:
            return False

        # Check for response time degradation as users increase
        response_times = [
            snapshot["avg_response_time_ms"] for snapshot in self.performance_data
        ]
        [snapshot["current_users"] for snapshot in self.performance_data]

        # Simple correlation check - if response times increase significantly with users
        if len(response_times) >= 10:
            first_half_rt = statistics.mean(response_times[: len(response_times) // 2])
            second_half_rt = statistics.mean(response_times[len(response_times) // 2 :])

            # If response time increased >50% in second half
            return second_half_rt > first_half_rt * 1.5

        return False

    def _generate_concurrent_user_report(self, results: ConcurrentUserResults):
        """Generate comprehensive concurrent user test report."""
        logger.info("\n" + "=" * 80)
        logger.info("PERF-004 CONCURRENT USER LOAD TESTING RESULTS")
        logger.info("=" * 80)

        # Test Summary
        logger.info("\nTest Summary:")
        logger.info(f"  Target Concurrent Users: {results.target_concurrent_users}")
        logger.info(
            f"  Peak Concurrent Users Achieved: {results.actual_peak_concurrent_users}"
        )
        logger.info(f"  Test Duration: {results.test_duration_minutes} minutes")
        logger.info(f"  Ramp-up Duration: {results.ramp_up_duration_minutes} minutes")

        # Performance Metrics
        logger.info("\nPerformance Metrics:")
        logger.info(f"  Total Requests: {results.total_requests:,}")
        logger.info(f"  Total Failures: {results.total_failures:,}")
        logger.info(f"  Average Response Time: {results.avg_response_time_ms:.1f}ms")
        logger.info(f"  P50 Response Time: {results.p50_response_time_ms:.1f}ms")
        logger.info(f"  P95 Response Time: {results.p95_response_time_ms:.1f}ms")
        logger.info(f"  P99 Response Time: {results.p99_response_time_ms:.1f}ms")
        logger.info(f"  Requests per Second: {results.requests_per_second:.1f}")

        # Error Analysis
        logger.info("\nError Analysis:")
        logger.info(f"  Error Rate: {results.error_rate_percent:.2f}%")
        logger.info(f"  Success Rate: {results.success_rate_percent:.2f}%")
        if results.error_distribution:
            logger.info("  Top Error Sources:")
            for endpoint, count in sorted(
                results.error_distribution.items(), key=lambda x: x[1], reverse=True
            )[:5]:
                logger.info(f"    {endpoint}: {count} errors")

        # Session Management
        logger.info("\nSession Management:")
        logger.info(f"  Total Sessions Created: {results.total_sessions_created}")
        logger.info(f"  Peak Active Sessions: {results.active_sessions_peak}")
        logger.info(
            f"  Average Session Duration: {results.avg_session_duration_minutes:.1f} minutes"
        )
        logger.info(f"  Session Timeout Rate: {results.session_timeout_rate:.1f}%")

        # Response Time Distribution
        logger.info("\nResponse Time Distribution:")
        for range_name, percentage in results.response_time_distribution.items():
            logger.info(f"  {range_name}: {percentage:.1f}%")

        # Endpoint Performance
        logger.info("\nSlowest Endpoints:")
        for i, endpoint in enumerate(results.slowest_endpoints[:3], 1):
            logger.info(
                f"  {i}. {endpoint['name']}: {endpoint['avg_response_time']:.0f}ms avg "
                f"({endpoint['requests']} requests, {endpoint['failures']} failures)"
            )

        # Concurrency Analysis
        logger.info("\nConcurrency Analysis:")
        logger.info(
            f"  User Spawn Rate Achieved: {results.user_spawn_rate_achieved:.2f} users/second"
        )
        logger.info(
            f"  Concurrency Scaling Efficiency: {results.concurrency_scaling_efficiency:.3f}"
        )
        logger.info(
            f"  Resource Contention Detected: {results.resource_contention_detected}"
        )

        # Target Compliance
        logger.info("\nTarget Compliance:")
        logger.info(
            f"  Concurrent User Target (>100): {'✅' if results.meets_concurrent_user_target else '⚠️'} ({results.actual_peak_concurrent_users} users)"
        )
        logger.info(
            f"  Response Time Targets (<200ms p95, <500ms p99): {'✅' if results.meets_response_time_targets else '⚠️'} ({results.p95_response_time_ms:.0f}ms p95, {results.p99_response_time_ms:.0f}ms p99)"
        )
        logger.info(
            f"  Error Rate Target (<1%): {'✅' if results.meets_error_rate_targets else '⚠️'} ({results.error_rate_percent:.2f}%)"
        )

        if results.meets_all_targets:
            logger.info("\n✅ All concurrent user load testing targets met!")
        else:
            logger.warning("\n⚠️ Some concurrent user load testing targets not met")

        logger.info("\n" + "=" * 80)

    def _record_concurrent_user_metrics(self, results: ConcurrentUserResults):
        """Record concurrent user test metrics."""
        # Record concurrent user capacity
        record_concurrent_users(results.actual_peak_concurrent_users)

        # Record response time metrics
        benchmark_manager.record_measurement(
            "api_performance",
            "concurrent_user_p95_response_time",
            results.p95_response_time_ms / 1000,
            "s",
            context={
                "test_type": "concurrent_users",
                "users": results.actual_peak_concurrent_users,
            },
        )

        # Record throughput
        benchmark_manager.record_measurement(
            "throughput_performance",
            "concurrent_user_rps",
            results.requests_per_second,
            "req/s",
            context={
                "test_type": "concurrent_users",
                "users": results.actual_peak_concurrent_users,
            },
        )


# Main execution
async def run_perf_004_concurrent_user_test(
    target_url: str = "http://localhost:8000",
    target_users: int = 150,
    test_duration: int = 30,
    ramp_up_duration: int = 10,
) -> ConcurrentUserResults:
    """Run PERF-004 concurrent user load testing."""
    tester = ConcurrentUserTester(
        target_url=target_url,
        target_users=target_users,
        test_duration_minutes=test_duration,
        ramp_up_duration_minutes=ramp_up_duration,
    )

    return await tester.run_concurrent_user_test()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PERF-004: Concurrent User Load Testing"
    )
    parser.add_argument("--url", default="http://localhost:8000", help="Target URL")
    parser.add_argument(
        "--users", type=int, default=150, help="Target concurrent users"
    )
    parser.add_argument(
        "--duration", type=int, default=30, help="Test duration in minutes"
    )
    parser.add_argument(
        "--ramp-up", type=int, default=10, help="Ramp-up duration in minutes"
    )

    args = parser.parse_args()

    # Run the test
    results = asyncio.run(
        run_perf_004_concurrent_user_test(
            target_url=args.url,
            target_users=args.users,
            test_duration=args.duration,
            ramp_up_duration=args.ramp_up,
        )
    )

    # Exit with appropriate code
    exit_code = 0 if results.meets_all_targets else 1
    exit(exit_code)
