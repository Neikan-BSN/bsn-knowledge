"""Locust Load Testing Scenarios for BSN Knowledge Platform.

Realistic user behavior patterns for comprehensive load testing of:
- BSN Knowledge API endpoints
- RAGnostic integration pipeline
- Concurrent user scenarios
- Mixed workload patterns
"""

import random
from datetime import datetime

from locust import HttpUser, TaskSet, between, events, tag, task
from locust.exception import RescheduleTask


# Test Data Templates
STUDENT_USERNAMES = [
    "student_001",
    "student_002",
    "student_003",
    "student_004",
    "student_005",
    "student_006",
    "student_007",
    "student_008",
    "student_009",
    "student_010",
    "student_011",
    "student_012",
    "student_013",
    "student_014",
    "student_015",
    "student_016",
    "student_017",
    "student_018",
    "student_019",
    "student_020",
]

INSTRUCTOR_USERNAMES = [
    "instructor_001",
    "instructor_002",
    "instructor_003",
    "instructor_004",
    "instructor_005",
]

NCLEX_TOPICS = [
    "nursing_fundamentals",
    "pharmacology",
    "medical_surgical",
    "pediatric",
    "maternal_newborn",
    "mental_health",
    "community_health",
    "leadership",
]

STUDY_GUIDE_TOPICS = [
    "Basic Patient Care",
    "Medication Administration",
    "Infection Control",
    "Cardiovascular Assessment",
    "Respiratory Care",
    "Wound Care",
    "Pain Management",
    "Emergency Procedures",
    "Patient Education",
    "Documentation Standards",
]

COMPETENCIES = [
    "AACN_KNOWLEDGE_1",
    "AACN_KNOWLEDGE_2",
    "AACN_PERSON_CENTERED_1",
    "AACN_POPULATION_HEALTH_1",
    "AACN_SCHOLARSHIP_1",
    "AACN_INFORMATION_TECH_1",
    "AACN_HEALTHCARE_SYSTEMS_1",
    "AACN_INTERPROFESSIONAL_1",
]

CLINICAL_SCENARIOS = [
    "acute_myocardial_infarction",
    "diabetes_management",
    "wound_infection",
    "medication_error_prevention",
    "patient_fall_prevention",
    "sepsis_recognition",
    "respiratory_distress",
    "pain_assessment",
]


class PerformanceTracker:
    """Track performance metrics across test scenarios."""

    def __init__(self):
        self.metrics = {
            "authentication_times": [],
            "content_generation_times": [],
            "search_query_times": [],
            "concurrent_requests": 0,
            "error_responses": [],
            "ragnostic_integration_times": [],
        }

    def record_response_time(
        self, endpoint: str, response_time: float, status_code: int
    ):
        """Record response time for performance analysis."""
        metric_key = f"{endpoint}_times"
        if metric_key not in self.metrics:
            self.metrics[metric_key] = []
        self.metrics[metric_key].append(response_time)

        if status_code >= 400:
            self.metrics["error_responses"].append(
                {
                    "endpoint": endpoint,
                    "status_code": status_code,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat(),
                }
            )


# Global performance tracker
performance_tracker = PerformanceTracker()


@events.request.add_listener
def record_performance_metrics(
    request_type,
    name,
    response_time,
    response_length,
    response,
    context,
    exception,
    start_time,
    url,
    **kwargs,
):
    """Record all performance metrics for analysis."""
    if response:
        performance_tracker.record_response_time(
            name, response_time, response.status_code
        )


class AuthenticatedUser:
    """Mixin for authenticated user behavior."""

    def __init__(self):
        self.auth_token = None
        self.username = None
        self.user_role = None

    def authenticate(self):
        """Authenticate user and store token."""
        if not self.username:
            return False

        response = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": self.username,
                "password": "load_test_password",  # Standardized password for load testing
            },
        )

        if response.status_code == 200:
            data = response.json()
            self.auth_token = data["access_token"]
            return True
        return False

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}


class StudentBehaviorTaskSet(TaskSet):
    """Realistic student behavior patterns."""

    def on_start(self):
        """Initialize student user session."""
        self.username = random.choice(STUDENT_USERNAMES)
        self.user = AuthenticatedUser()
        self.user.username = self.username
        self.user.client = self.client

        # Authenticate on session start
        if not self.user.authenticate():
            raise RescheduleTask("Authentication failed")

    @task(30)
    @tag("study_activities")
    def browse_study_materials(self):
        """Student browses available study materials."""
        headers = self.user.get_auth_headers()

        # Browse topics
        self.client.get(
            "/api/v1/study-guides", headers=headers, name="browse_study_guides"
        )

        # View specific study guide
        topic = random.choice(STUDY_GUIDE_TOPICS)
        self.client.post(
            "/api/v1/study-guide/create",
            json={
                "topic": topic,
                "competencies": random.sample(COMPETENCIES, 2),
                "difficulty_level": random.choice(
                    ["beginner", "intermediate", "advanced"]
                ),
            },
            headers=headers,
            name="create_study_guide",
        )

    @task(25)
    @tag("nclex_practice")
    def practice_nclex_questions(self):
        """Student practices NCLEX questions."""
        headers = self.user.get_auth_headers()

        # Generate NCLEX questions
        topic = random.choice(NCLEX_TOPICS)
        question_count = random.choice([5, 10, 15, 20])
        difficulty = random.choice(["easy", "medium", "hard"])

        self.client.post(
            "/api/v1/nclex/generate",
            json={
                "topic": topic,
                "difficulty": difficulty,
                "question_count": question_count,
                "include_rationale": True,
            },
            headers=headers,
            name="generate_nclex_questions",
        )

    @task(20)
    @tag("quiz_activities")
    def take_practice_quiz(self):
        """Student takes practice quizzes."""
        headers = self.user.get_auth_headers()

        # Create quiz
        quiz_data = {
            "topic": random.choice(STUDY_GUIDE_TOPICS),
            "question_count": random.choice([10, 15, 20]),
            "difficulty": random.choice(["beginner", "intermediate", "advanced"]),
            "time_limit_minutes": random.choice([15, 30, 45]),
        }

        response = self.client.post(
            "/api/v1/quizzes/create",
            json=quiz_data,
            headers=headers,
            name="create_quiz",
        )

        if response.status_code == 200:
            # Simulate taking quiz
            quiz_id = response.json().get("quiz_id")
            if quiz_id:
                # Submit answers
                answers = {
                    "quiz_id": quiz_id,
                    "answers": {
                        f"q_{i}": random.choice(["A", "B", "C", "D"])
                        for i in range(quiz_data["question_count"])
                    },
                }

                self.client.post(
                    f"/api/v1/quizzes/{quiz_id}/submit",
                    json=answers,
                    headers=headers,
                    name="submit_quiz",
                )

    @task(15)
    @tag("clinical_support")
    def access_clinical_support(self):
        """Student accesses clinical decision support."""
        headers = self.user.get_auth_headers()

        scenario = random.choice(CLINICAL_SCENARIOS)

        self.client.post(
            "/api/v1/clinical-support/scenario",
            json={
                "scenario_type": scenario,
                "patient_context": {
                    "age": random.randint(18, 85),
                    "gender": random.choice(["male", "female"]),
                    "primary_diagnosis": scenario,
                },
                "complexity_level": random.choice(
                    ["basic", "intermediate", "advanced"]
                ),
            },
            headers=headers,
            name="clinical_scenario_support",
        )

    @task(10)
    @tag("analytics")
    def view_progress_analytics(self):
        """Student views their learning analytics."""
        headers = self.user.get_auth_headers()

        # View overall progress
        self.client.get(
            f"/api/v1/analytics/student/{self.username}/progress",
            headers=headers,
            name="student_progress",
        )

        # View competency analysis
        self.client.get(
            f"/api/v1/analytics/student/{self.username}/competencies",
            headers=headers,
            name="competency_analysis",
        )

    @task(5)
    @tag("adaptive_learning")
    def adaptive_learning_recommendations(self):
        """Student accesses adaptive learning recommendations."""
        headers = self.user.get_auth_headers()

        self.client.get(
            "/api/v1/adaptive-learning/recommendations",
            headers=headers,
            name="adaptive_recommendations",
        )

        # Request personalized learning path
        self.client.post(
            "/api/v1/adaptive-learning/learning-path",
            json={
                "target_competencies": random.sample(COMPETENCIES, 3),
                "current_performance_level": random.choice(
                    ["novice", "advanced_beginner", "competent"]
                ),
                "learning_preferences": random.sample(
                    ["visual", "auditory", "kinesthetic", "reading"], 2
                ),
            },
            headers=headers,
            name="personalized_learning_path",
        )


class InstructorBehaviorTaskSet(TaskSet):
    """Realistic instructor behavior patterns."""

    def on_start(self):
        """Initialize instructor user session."""
        self.username = random.choice(INSTRUCTOR_USERNAMES)
        self.user = AuthenticatedUser()
        self.user.username = self.username
        self.user.client = self.client
        self.user.user_role = "instructor"

        if not self.user.authenticate():
            raise RescheduleTask("Authentication failed")

    @task(40)
    @tag("assessment")
    def create_and_review_assessments(self):
        """Instructor creates and reviews student assessments."""
        headers = self.user.get_auth_headers()

        # Create competency assessment
        student_id = random.choice(STUDENT_USERNAMES)
        competency_id = random.choice(COMPETENCIES)

        assessment_data = {
            "student_id": student_id,
            "competency_id": competency_id,
            "performance_data": {
                "quiz_scores": [random.randint(70, 95) for _ in range(3)],
                "clinical_evaluation_score": random.randint(75, 95),
                "participation_score": random.randint(80, 100),
            },
            "assessment_type": "comprehensive",
            "notes": f"Assessment for {competency_id} competency",
        }

        self.client.post(
            "/api/v1/assessment/competency/assess",
            json=assessment_data,
            headers=headers,
            name="create_competency_assessment",
        )

        # Review student progress
        self.client.get(
            f"/api/v1/assessment/student/{student_id}/summary",
            headers=headers,
            name="review_student_progress",
        )

    @task(30)
    @tag("analytics")
    def review_class_analytics(self):
        """Instructor reviews class performance analytics."""
        headers = self.user.get_auth_headers()

        # Class overview analytics
        self.client.get(
            "/api/v1/analytics/class/overview", headers=headers, name="class_overview"
        )

        # Competency distribution analysis
        competency = random.choice(COMPETENCIES)
        self.client.get(
            f"/api/v1/analytics/competency/{competency}/distribution",
            headers=headers,
            name="competency_distribution",
        )

        # Performance trends
        self.client.get(
            "/api/v1/analytics/trends/performance",
            params={"time_period": "30_days"},
            headers=headers,
            name="performance_trends",
        )

    @task(20)
    @tag("content_creation")
    def create_educational_content(self):
        """Instructor creates educational content."""
        headers = self.user.get_auth_headers()

        # Create custom quiz
        quiz_data = {
            "title": f"Custom Quiz - {random.choice(STUDY_GUIDE_TOPICS)}",
            "topic": random.choice(STUDY_GUIDE_TOPICS),
            "questions": [
                {
                    "question": f"Question {i + 1} about nursing practice",
                    "options": ["Option A", "Option B", "Option C", "Option D"],
                    "correct_answer": random.choice(["A", "B", "C", "D"]),
                    "rationale": f"Rationale for question {i + 1}",
                }
                for i in range(random.choice([5, 10, 15]))
            ],
            "time_limit_minutes": random.choice([15, 30, 45]),
            "difficulty": random.choice(["beginner", "intermediate", "advanced"]),
        }

        self.client.post(
            "/api/v1/quizzes/create-custom",
            json=quiz_data,
            headers=headers,
            name="create_custom_quiz",
        )

    @task(10)
    @tag("batch_operations")
    def bulk_student_operations(self):
        """Instructor performs bulk operations on student data."""
        headers = self.user.get_auth_headers()

        # Bulk assessment creation
        students = random.sample(STUDENT_USERNAMES, random.choice([5, 10, 15]))
        competency = random.choice(COMPETENCIES)

        bulk_assessments = {
            "assessments": [
                {
                    "student_id": student,
                    "competency_id": competency,
                    "performance_data": {"score": random.randint(70, 95)},
                    "assessment_type": "bulk_assessment",
                }
                for student in students
            ],
            "batch_id": f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        }

        self.client.post(
            "/api/v1/assessment/competency/assess/bulk",
            json=bulk_assessments,
            headers=headers,
            name="bulk_student_assessment",
        )


class BSNKnowledgeStudent(HttpUser, AuthenticatedUser):
    """Student user behavior simulation."""

    tasks = [StudentBehaviorTaskSet]
    wait_time = between(2, 8)  # 2-8 seconds between tasks
    weight = 85  # 85% of users are students

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        AuthenticatedUser.__init__(self)


class BSNKnowledgeInstructor(HttpUser, AuthenticatedUser):
    """Instructor user behavior simulation."""

    tasks = [InstructorBehaviorTaskSet]
    wait_time = between(5, 15)  # 5-15 seconds between tasks (more deliberate)
    weight = 15  # 15% of users are instructors

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        AuthenticatedUser.__init__(self)


class MixedWorkloadUser(HttpUser, AuthenticatedUser):
    """Mixed workload user for stress testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        AuthenticatedUser.__init__(self)

    wait_time = between(1, 5)  # Faster interactions for stress testing
    weight = 100  # Used only in mixed workload scenarios

    @task(40)
    @tag("rapid_requests")
    def rapid_api_calls(self):
        """Rapid succession API calls to test system limits."""
        if not self.auth_token:
            self.username = random.choice(STUDENT_USERNAMES + INSTRUCTOR_USERNAMES)
            if not self.authenticate():
                return

        headers = self.get_auth_headers()

        # Rapid sequence of different endpoints
        endpoints = [
            ("/health", "GET", None),
            ("/api/v1/auth/me", "GET", None),
            ("/api/v1/assessment/domains", "GET", None),
            ("/metrics", "GET", None),
        ]

        for endpoint, method, data in endpoints:
            if method == "GET":
                self.client.get(
                    endpoint,
                    headers=headers,
                    name=f"rapid_{endpoint.replace('/', '_')}",
                )
            else:
                self.client.post(
                    endpoint,
                    json=data,
                    headers=headers,
                    name=f"rapid_{endpoint.replace('/', '_')}",
                )

    @task(30)
    @tag("concurrent_generation")
    def concurrent_content_generation(self):
        """Concurrent content generation to stress RAGnostic integration."""
        if not self.auth_token:
            self.username = random.choice(STUDENT_USERNAMES)
            if not self.authenticate():
                return

        headers = self.get_auth_headers()

        # Multiple concurrent content generation requests
        requests = [
            {
                "endpoint": "/api/v1/nclex/generate",
                "data": {
                    "topic": random.choice(NCLEX_TOPICS),
                    "difficulty": random.choice(["easy", "medium", "hard"]),
                    "question_count": random.choice([5, 10]),
                },
            },
            {
                "endpoint": "/api/v1/study-guide/create",
                "data": {
                    "topic": random.choice(STUDY_GUIDE_TOPICS),
                    "competencies": random.sample(COMPETENCIES, 2),
                    "difficulty_level": random.choice(["beginner", "intermediate"]),
                },
            },
        ]

        for req in requests:
            self.client.post(
                req["endpoint"],
                json=req["data"],
                headers=headers,
                name=f"concurrent_{req['endpoint'].split('/')[-1]}",
            )

    @task(20)
    @tag("database_stress")
    def database_intensive_operations(self):
        """Database-intensive operations for stress testing."""
        if not self.auth_token:
            self.username = random.choice(INSTRUCTOR_USERNAMES)
            if not self.authenticate():
                return

        headers = self.get_auth_headers()

        # Multiple analytics queries that hit the database
        analytics_endpoints = [
            "/api/v1/analytics/class/overview",
            "/api/v1/analytics/trends/performance",
            f"/api/v1/analytics/competency/{random.choice(COMPETENCIES)}/distribution",
        ]

        for endpoint in analytics_endpoints:
            self.client.get(
                endpoint,
                headers=headers,
                name=f"db_intensive_{endpoint.split('/')[-1]}",
            )

    @task(10)
    @tag("error_simulation")
    def simulate_error_conditions(self):
        """Simulate various error conditions for resilience testing."""
        # Invalid authentication
        self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid_token"},
            name="invalid_auth_test",
        )

        # Malformed requests
        self.client.post(
            "/api/v1/nclex/generate",
            json={"invalid": "data"},
            headers=self.get_auth_headers(),
            name="malformed_request_test",
        )

        # Large payload test
        large_data = {
            "topic": "A" * 1000,  # Large topic string
            "description": "B" * 5000,  # Large description
            "competencies": COMPETENCIES * 10,  # Large array
        }

        self.client.post(
            "/api/v1/study-guide/create",
            json=large_data,
            headers=self.get_auth_headers(),
            name="large_payload_test",
        )


# Performance test reporting
@events.test_stop.add_listener
def report_performance_summary(environment, **kwargs):
    """Generate performance summary report at test completion."""
    print("\n" + "=" * 80)
    print("BSN KNOWLEDGE LOAD TEST PERFORMANCE SUMMARY")
    print("=" * 80)

    # Authentication performance
    if performance_tracker.metrics["authentication_times"]:
        auth_times = performance_tracker.metrics["authentication_times"]
        print("Authentication Performance:")
        print(f"  Average: {sum(auth_times) / len(auth_times):.2f}ms")
        print(f"  Min: {min(auth_times):.2f}ms")
        print(f"  Max: {max(auth_times):.2f}ms")

    # Content generation performance
    if performance_tracker.metrics["content_generation_times"]:
        gen_times = performance_tracker.metrics["content_generation_times"]
        print("Content Generation Performance:")
        print(f"  Average: {sum(gen_times) / len(gen_times):.2f}ms")
        print(f"  Min: {min(gen_times):.2f}ms")
        print(f"  Max: {max(gen_times):.2f}ms")

    # Error summary
    if performance_tracker.metrics["error_responses"]:
        errors = performance_tracker.metrics["error_responses"]
        print("Error Summary:")
        print(f"  Total Errors: {len(errors)}")

        # Group by status code
        error_codes = {}
        for error in errors:
            code = error["status_code"]
            error_codes[code] = error_codes.get(code, 0) + 1

        for code, count in error_codes.items():
            print(f"  {code}: {count} errors")

    print("=" * 80 + "\n")
