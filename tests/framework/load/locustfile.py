"""Locust Load Testing Configuration for E2E Pipeline Validation.

Provides realistic user behavior patterns for comprehensive performance testing
of the RAGnostic → BSN Knowledge pipeline under concurrent load.
"""

import json
import random
import time

from locust import HttpUser, between, events, task
from locust.log import setup_logging

# Configure logging
setup_logging("INFO", None)

# Performance tracking
performance_metrics = {
    "response_times": [],
    "error_rates": {},
    "throughput": [],
    "concurrent_users": [],
}


class BSNKnowledgeUser(HttpUser):
    """Simulated BSN Knowledge platform user with realistic behavior patterns."""

    wait_time = between(2, 8)  # Realistic user think time
    weight = 70  # Primary user type

    def on_start(self):
        """Initialize user session with authentication."""
        self.user_type = "student"
        self.session_data = {
            "student_id": f"student_{random.randint(1000, 9999)}",
            "competency_level": random.choice(["beginner", "intermediate", "advanced"]),
            "preferred_topics": random.sample(
                [
                    "cardiovascular",
                    "respiratory",
                    "neurological",
                    "pharmacology",
                    "critical_care",
                ],
                k=random.randint(2, 4),
            ),
        }

        # Authenticate user
        self.authenticate()

    def authenticate(self):
        """Perform user authentication."""
        auth_payload = {
            "username": self.session_data["student_id"],
            "password": "test_password",
        }

        with self.client.post(
            "/api/v1/auth/login", json=auth_payload, catch_response=True
        ) as response:
            if response.status_code == 200:
                token_data = response.json()
                self.client.headers.update(
                    {"Authorization": f"Bearer {token_data.get('access_token')}"}
                )
                response.success()
            else:
                response.failure(f"Authentication failed: {response.status_code}")

    @task(40)
    def generate_nclex_questions(self):
        """Generate NCLEX questions - primary use case."""
        topic = random.choice(self.session_data["preferred_topics"])
        difficulty = self.session_data["competency_level"]

        payload = {
            "topic": topic,
            "difficulty": difficulty,
            "question_count": random.randint(5, 15),
            "nclex_categories": [
                "Physiological Integrity",
                "Safe and Effective Care Environment",
            ],
        }

        with self.client.post(
            "/api/v1/nclex/generate",
            json=payload,
            name="Generate NCLEX Questions",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                questions = response.json()
                if len(questions.get("questions", [])) >= payload["question_count"]:
                    response.success()
                else:
                    response.failure(
                        f"Insufficient questions returned: {len(questions.get('questions', []))}"
                    )
            else:
                response.failure(f"NCLEX generation failed: {response.status_code}")

    @task(25)
    def create_study_guide(self):
        """Create personalized study guide."""
        competencies = random.sample(
            [
                "AACN_KNOWLEDGE_1",
                "AACN_KNOWLEDGE_2",
                "AACN_PERSON_CENTERED_1",
                "AACN_POPULATION_HEALTH_1",
                "AACN_SCHOLARSHIP_1",
            ],
            k=random.randint(1, 3),
        )

        payload = {
            "student_id": self.session_data["student_id"],
            "competencies": competencies,
            "student_level": "undergraduate",
            "learning_style": random.choice(
                ["visual", "auditory", "kinesthetic", "mixed"]
            ),
            "time_available_hours": random.randint(2, 8),
        }

        with self.client.post(
            "/api/v1/study-guides/generate",
            json=payload,
            name="Create Study Guide",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                guide = response.json()
                if guide.get("activities") and len(guide["activities"]) > 0:
                    response.success()
                else:
                    response.failure("Empty study guide generated")
            else:
                response.failure(f"Study guide creation failed: {response.status_code}")

    @task(20)
    def view_analytics(self):
        """View student performance analytics."""
        params = {
            "student_id": self.session_data["student_id"],
            "time_period": random.choice(["week", "month", "semester"]),
            "include_competencies": "true",
        }

        with self.client.get(
            "/api/v1/analytics/assessment",
            params=params,
            name="View Analytics",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                analytics = response.json()
                if analytics.get("overall_progress") is not None:
                    response.success()
                else:
                    response.failure("Invalid analytics data")
            else:
                response.failure(f"Analytics retrieval failed: {response.status_code}")

    @task(15)
    def search_content(self):
        """Search educational content."""
        search_terms = [
            "cardiovascular assessment",
            "medication administration",
            "infection control",
            "patient safety",
            "nursing diagnosis",
            "care planning",
            "pathophysiology",
        ]

        query = random.choice(search_terms)
        params = {
            "q": query,
            "limit": random.randint(10, 50),
            "include_metadata": "true",
        }

        with self.client.get(
            "/api/v1/search", params=params, name="Search Content", catch_response=True
        ) as response:
            if response.status_code == 200:
                results = response.json()
                if results.get("results") and len(results["results"]) > 0:
                    response.success()
                else:
                    response.failure(f"No search results for: {query}")
            else:
                response.failure(f"Search failed: {response.status_code}")


class InstructorUser(HttpUser):
    """Simulated instructor user with administrative tasks."""

    wait_time = between(5, 15)  # Longer think time for complex tasks
    weight = 20  # Secondary user type

    def on_start(self):
        """Initialize instructor session."""
        self.user_type = "instructor"
        self.session_data = {
            "instructor_id": f"instructor_{random.randint(100, 999)}",
            "courses": [
                f"NURS_{random.randint(100, 499)}" for _ in range(random.randint(1, 3))
            ],
            "students": [
                f"student_{random.randint(1000, 9999)}"
                for _ in range(random.randint(10, 50))
            ],
        }

        self.authenticate()

    def authenticate(self):
        """Perform instructor authentication."""
        auth_payload = {
            "username": self.session_data["instructor_id"],
            "password": "instructor_password",
            "role": "instructor",
        }

        with self.client.post(
            "/api/v1/auth/login", json=auth_payload, catch_response=True
        ) as response:
            if response.status_code == 200:
                token_data = response.json()
                self.client.headers.update(
                    {"Authorization": f"Bearer {token_data.get('access_token')}"}
                )
                response.success()
            else:
                response.failure(
                    f"Instructor authentication failed: {response.status_code}"
                )

    @task(35)
    def create_assessment(self):
        """Create assessment for course."""
        course = random.choice(self.session_data["courses"])

        payload = {
            "course_id": course,
            "assessment_type": random.choice(["quiz", "exam", "simulation"]),
            "topics": random.sample(
                [
                    "cardiovascular_assessment",
                    "medication_safety",
                    "infection_control",
                    "critical_thinking",
                    "patient_communication",
                ],
                k=random.randint(2, 4),
            ),
            "difficulty_distribution": {"easy": 30, "medium": 50, "hard": 20},
            "question_count": random.randint(20, 50),
        }

        with self.client.post(
            "/api/v1/assessments/create",
            json=payload,
            name="Create Assessment",
            catch_response=True,
        ) as response:
            if response.status_code == 200 or response.status_code == 201:
                response.success()
            else:
                response.failure(f"Assessment creation failed: {response.status_code}")

    @task(30)
    def view_class_analytics(self):
        """View class performance analytics."""
        course = random.choice(self.session_data["courses"])

        params = {
            "course_id": course,
            "time_period": "month",
            "include_individual_performance": "true",
            "competency_breakdown": "true",
        }

        with self.client.get(
            "/api/v1/analytics/class",
            params=params,
            name="View Class Analytics",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Class analytics failed: {response.status_code}")

    @task(25)
    def bulk_content_generation(self):
        """Generate content for multiple students."""
        student_batch = random.sample(
            self.session_data["students"], k=random.randint(5, 15)
        )

        payload = {
            "student_ids": student_batch,
            "content_type": random.choice(
                ["study_guides", "practice_questions", "remediation"]
            ),
            "competency_focus": random.choice(
                [
                    "AACN_KNOWLEDGE_1",
                    "AACN_PERSON_CENTERED_1",
                    "AACN_POPULATION_HEALTH_1",
                ]
            ),
        }

        with self.client.post(
            "/api/v1/content/bulk-generate",
            json=payload,
            name="Bulk Content Generation",
            catch_response=True,
        ) as response:
            if (
                response.status_code == 200 or response.status_code == 202
            ):  # Accept async processing
                response.success()
            else:
                response.failure(f"Bulk generation failed: {response.status_code}")


class RAGnosticIntegrationUser(HttpUser):
    """Simulated heavy integration user testing RAGnostic pipeline."""

    wait_time = between(1, 3)  # Fast automated processing
    weight = 10  # Background processing simulation

    def on_start(self):
        """Initialize integration session."""
        self.user_type = "integration"
        self.api_key = "test_ragnostic_integration_key"
        self.client.headers.update(
            {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        )

    @task(50)
    def process_medical_content(self):
        """Process medical content through RAGnostic pipeline."""
        content_samples = [
            "Cardiovascular assessment techniques for acute care patients",
            "Medication administration safety protocols in critical care",
            "Infection control measures for immunocompromised patients",
            "Patient education strategies for chronic disease management",
        ]

        payload = {
            "content": random.choice(content_samples),
            "processing_type": "medical_enrichment",
            "umls_integration": True,
            "generate_questions": True,
            "target_education_level": "undergraduate_nursing",
        }

        with self.client.post(
            "/api/v1/pipeline/process",
            json=payload,
            name="Process Medical Content",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                result = response.json()
                if result.get("processed_content") and result.get(
                    "generated_questions"
                ):
                    response.success()
                else:
                    response.failure("Incomplete processing result")
            else:
                response.failure(f"Content processing failed: {response.status_code}")

    @task(30)
    def batch_question_generation(self):
        """Generate questions in batch for educational content."""
        payload = {
            "batch_size": random.randint(10, 30),
            "topics": random.sample(
                [
                    "pathophysiology",
                    "pharmacology",
                    "nursing_assessment",
                    "patient_safety",
                    "clinical_reasoning",
                ],
                k=random.randint(2, 4),
            ),
            "difficulty_levels": ["medium", "hard"],
            "question_types": ["multiple_choice", "select_all_apply", "case_study"],
        }

        with self.client.post(
            "/api/v1/questions/batch-generate",
            json=payload,
            name="Batch Question Generation",
            catch_response=True,
        ) as response:
            if response.status_code == 200 or response.status_code == 202:
                response.success()
            else:
                response.failure(f"Batch generation failed: {response.status_code}")

    @task(20)
    def health_monitoring(self):
        """Monitor system health and performance."""
        with self.client.get(
            "/api/v1/health/detailed", name="Health Monitoring", catch_response=True
        ) as response:
            if response.status_code == 200:
                health = response.json()
                if health.get("status") == "healthy":
                    response.success()
                else:
                    response.failure(f"System unhealthy: {health.get('status')}")
            else:
                response.failure(f"Health check failed: {response.status_code}")


# Event handlers for performance tracking
@events.request.add_listener
def request_handler(
    request_type, name, response_time, response_length, exception, context, **kwargs
):
    """Track request performance metrics."""
    performance_metrics["response_times"].append(
        {
            "timestamp": time.time(),
            "request_type": request_type,
            "name": name,
            "response_time": response_time,
            "success": exception is None,
        }
    )


@events.user_count_changed.add_listener
def user_count_handler(environment, **kwargs):
    """Track concurrent user metrics."""
    performance_metrics["concurrent_users"].append(
        {"timestamp": time.time(), "user_count": environment.runner.user_count}
    )


@events.test_stop.add_listener
def test_stop_handler(environment, **kwargs):
    """Generate performance report at test completion."""
    stats = environment.stats

    # Calculate key metrics
    total_requests = stats.total.num_requests
    total_failures = stats.total.num_failures
    avg_response_time = stats.total.avg_response_time
    max_response_time = stats.total.max_response_time

    # Generate performance summary
    performance_summary = {
        "test_duration_seconds": stats.total.last_request_timestamp
        - stats.total.first_request_timestamp,
        "total_requests": total_requests,
        "total_failures": total_failures,
        "failure_rate": (total_failures / total_requests * 100)
        if total_requests > 0
        else 0,
        "avg_response_time_ms": avg_response_time,
        "max_response_time_ms": max_response_time,
        "requests_per_second": stats.total.current_rps,
        "concurrent_users_peak": max(
            [u["user_count"] for u in performance_metrics["concurrent_users"]],
            default=0,
        ),
    }

    # Save performance report
    report_file = f"/app/reports/performance_report_{int(time.time())}.json"
    try:
        with open(report_file, "w") as f:
            json.dump(
                {
                    "summary": performance_summary,
                    "detailed_metrics": performance_metrics,
                    "endpoint_stats": {
                        name: {
                            "num_requests": stat.num_requests,
                            "num_failures": stat.num_failures,
                            "avg_response_time": stat.avg_response_time,
                            "max_response_time": stat.max_response_time,
                        }
                        for name, stat in stats.entries.items()
                    },
                },
                f,
                indent=2,
            )
        print(f"Performance report saved to: {report_file}")
    except Exception as e:
        print(f"Failed to save performance report: {e}")

    # Print summary to console
    print("\n" + "=" * 50)
    print("PERFORMANCE TEST SUMMARY")
    print("=" * 50)
    print(f"Total Requests: {total_requests:,}")
    print(f"Total Failures: {total_failures:,}")
    print(f"Failure Rate: {performance_summary['failure_rate']:.2f}%")
    print(f"Average Response Time: {avg_response_time:.2f}ms")
    print(f"Max Response Time: {max_response_time:.2f}ms")
    print(f"Peak Concurrent Users: {performance_summary['concurrent_users_peak']}")
    print(f"Requests per Second: {stats.total.current_rps:.2f}")
    print("=" * 50)
