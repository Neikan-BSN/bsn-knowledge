# Integration Guide

Comprehensive guide for integrating BSN Knowledge with your applications, learning management systems, and enterprise infrastructure.

## Overview

BSN Knowledge provides robust APIs and integration capabilities designed for healthcare education environments. This guide covers authentication, API integration patterns, webhooks, SDKs, and enterprise integration scenarios.

### Integration Architecture

```
Your Application/LMS
       ↓
Authentication Layer (JWT/OAuth2)
       ↓
BSN Knowledge API Gateway
       ↓
┌─────────────┬─────────────┬─────────────┐
│   Content   │ Assessment  │  Analytics  │
│   Service   │   Service   │   Service   │
└─────────────┴─────────────┴─────────────┘
       ↓
RAGnostic AI Pipeline (Medical Content)
```

### Supported Integration Types

- **REST API** - Primary integration method with comprehensive endpoints
- **Webhooks** - Real-time event notifications
- **LMS Integration** - Deep integration with learning management systems
- **SSO/SAML** - Single sign-on for enterprise authentication
- **Bulk Data API** - High-volume data operations
- **Analytics API** - Advanced reporting and insights

## Authentication & Authorization

### JWT Authentication

BSN Knowledge uses JWT (JSON Web Tokens) for API authentication with role-based access control.

#### Authentication Flow

```python
import requests
import jwt
from datetime import datetime, timezone

class BSNKnowledgeAuth:
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url
        self.api_key = api_key
        self.access_token = None
        self.refresh_token = None

    def login(self, username: str, password: str) -> dict:
        """Authenticate user and obtain access tokens."""
        response = requests.post(
            f"{self.base_url}/api/v1/auth/login",
            json={
                "username": username,
                "password": password
            },
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            auth_data = response.json()
            self.access_token = auth_data["access_token"]
            self.refresh_token = auth_data["refresh_token"]
            return auth_data
        else:
            raise Exception(f"Authentication failed: {response.status_code}")

    def get_auth_headers(self) -> dict:
        """Get headers for authenticated requests."""
        if not self.access_token:
            raise Exception("Not authenticated. Call login() first.")

        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    def refresh_tokens(self) -> dict:
        """Refresh access token using refresh token."""
        if not self.refresh_token:
            raise Exception("No refresh token available.")

        response = requests.post(
            f"{self.base_url}/api/v1/auth/refresh",
            json={"refresh_token": self.refresh_token},
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            auth_data = response.json()
            self.access_token = auth_data["access_token"]
            return auth_data
        else:
            raise Exception(f"Token refresh failed: {response.status_code}")

    def is_token_valid(self) -> bool:
        """Check if current token is valid and not expired."""
        if not self.access_token:
            return False

        try:
            # Decode without verification to check expiration
            payload = jwt.decode(
                self.access_token,
                options={"verify_signature": False}
            )
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
                return datetime.now(timezone.utc) < exp_datetime
            return False
        except jwt.InvalidTokenError:
            return False

# Usage example
auth = BSNKnowledgeAuth("https://api.bsn-knowledge.edu")
auth.login("your_username", "your_password")
headers = auth.get_auth_headers()
```

#### Role-Based Access Control

Different user roles have different API access levels:

```python
class UserRole:
    STUDENT = "student"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"
    SYSTEM = "system"

# Role-based endpoint access
ROLE_PERMISSIONS = {
    UserRole.STUDENT: [
        "nclex:generate",
        "study-guide:create",
        "assessment:view-own",
        "analytics:view-own"
    ],
    UserRole.INSTRUCTOR: [
        "nclex:generate",
        "study-guide:create",
        "assessment:manage-students",
        "analytics:view-class",
        "clinical-support:create"
    ],
    UserRole.ADMIN: [
        "*"  # All permissions
    ]
}

def check_permissions(user_role: str, required_permission: str) -> bool:
    """Check if user role has required permission."""
    user_permissions = ROLE_PERMISSIONS.get(user_role, [])
    return "*" in user_permissions or required_permission in user_permissions
```

### API Key Authentication (Server-to-Server)

For server-to-server integrations, use API key authentication:

```python
class BSNKnowledgeAPIClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    def get_headers(self) -> dict:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "BSN-Integration/1.0"
        }

    def make_request(self, method: str, endpoint: str, **kwargs) -> dict:
        """Make authenticated API request."""
        url = f"{self.base_url}{endpoint}"
        headers = self.get_headers()

        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        response = requests.request(method, url, **kwargs)

        if response.status_code >= 400:
            raise Exception(f"API request failed: {response.status_code} - {response.text}")

        return response.json() if response.content else {}

# Usage
client = BSNKnowledgeAPIClient(
    base_url="https://api.bsn-knowledge.edu",
    api_key="your-api-key"
)

# Generate NCLEX questions
questions = client.make_request(
    "POST",
    "/api/v1/nclex/generate",
    json={
        "topic": "Cardiovascular Nursing",
        "question_count": 10,
        "difficulty": "intermediate"
    }
)
```

## Core API Integration Patterns

### Content Generation Integration

#### NCLEX Question Generation

```python
class NCLEXQuestionGenerator:
    def __init__(self, client: BSNKnowledgeAPIClient):
        self.client = client

    def generate_questions(
        self,
        topic: str,
        count: int = 5,
        difficulty: str = "intermediate",
        question_types: list = None,
        custom_settings: dict = None
    ) -> dict:
        """Generate NCLEX-style questions."""

        request_data = {
            "topic": topic,
            "question_count": count,
            "difficulty": difficulty,
            "settings": {
                "include_rationales": True,
                "medical_accuracy_check": True,
                **(custom_settings or {})
            }
        }

        if question_types:
            request_data["question_types"] = question_types

        return self.client.make_request(
            "POST",
            "/api/v1/nclex/generate",
            json=request_data
        )

    def generate_by_competency(
        self,
        competency_ids: list,
        student_level: str = "intermediate"
    ) -> dict:
        """Generate questions aligned to specific competencies."""

        return self.client.make_request(
            "POST",
            "/api/v1/nclex/generate",
            json={
                "competency_alignment": {
                    "aacn_domains": competency_ids,
                    "student_level": student_level
                },
                "question_count": len(competency_ids) * 2,  # 2 per competency
                "settings": {
                    "include_rationales": True,
                    "competency_focused": True
                }
            }
        )

# Usage example
generator = NCLEXQuestionGenerator(client)

# Generate cardiovascular questions
cardio_questions = generator.generate_questions(
    topic="Cardiovascular Nursing",
    count=10,
    difficulty="advanced",
    question_types=["multiple_choice", "select_all"],
    custom_settings={
        "focus_areas": ["pharmacology", "pathophysiology"],
        "clinical_scenarios": True
    }
)

# Generate competency-aligned questions
competency_questions = generator.generate_by_competency(
    competency_ids=["AACN_KNOWLEDGE_1", "AACN_PERSON_CARE_2"],
    student_level="senior"
)
```

#### Study Guide Creation

```python
class StudyGuideGenerator:
    def __init__(self, client: BSNKnowledgeAPIClient):
        self.client = client

    def create_study_guide(
        self,
        topic: str,
        student_level: str = "intermediate",
        guide_type: str = "comprehensive",
        learning_objectives: list = None
    ) -> dict:
        """Create personalized study guide."""

        request_data = {
            "topic": topic,
            "student_level": student_level,
            "guide_type": guide_type,
            "settings": {
                "include_practice_questions": True,
                "include_case_studies": True,
                "visual_learning_aids": True
            }
        }

        if learning_objectives:
            request_data["learning_objectives"] = learning_objectives

        return self.client.make_request(
            "POST",
            "/api/v1/study-guide/create",
            json=request_data
        )

    def create_adaptive_guide(
        self,
        student_id: str,
        knowledge_gaps: list,
        timeline_weeks: int = 4
    ) -> dict:
        """Create study guide based on knowledge gaps."""

        return self.client.make_request(
            "POST",
            "/api/v1/study-guide/create",
            json={
                "personalization": {
                    "student_id": student_id,
                    "knowledge_gaps": knowledge_gaps,
                    "timeline_weeks": timeline_weeks
                },
                "adaptive_content": True,
                "progress_tracking": True
            }
        )

# Usage example
guide_generator = StudyGuideGenerator(client)

# Create comprehensive study guide
study_guide = guide_generator.create_study_guide(
    topic="Mental Health Nursing",
    student_level="junior",
    guide_type="comprehensive",
    learning_objectives=[
        "Understand therapeutic communication",
        "Apply crisis intervention techniques",
        "Demonstrate medication management"
    ]
)

# Create adaptive guide for struggling student
adaptive_guide = guide_generator.create_adaptive_guide(
    student_id="student_123",
    knowledge_gaps=["pharmacology", "pathophysiology"],
    timeline_weeks=6
)
```

### Assessment Integration

#### Competency Assessment

```python
class CompetencyAssessment:
    def __init__(self, client: BSNKnowledgeAPIClient):
        self.client = client

    def assess_student_competency(
        self,
        student_id: str,
        competency_id: str,
        performance_data: dict,
        assessment_type: str = "comprehensive"
    ) -> dict:
        """Assess individual student competency."""

        return self.client.make_request(
            "POST",
            "/api/v1/assessment/competency",
            json={
                "student_id": student_id,
                "competency_id": competency_id,
                "performance_data": performance_data,
                "assessment_type": assessment_type,
                "assessor_id": "system_integration"
            }
        )

    def bulk_assess_competencies(
        self,
        assessments: list,
        batch_id: str = None
    ) -> dict:
        """Perform bulk competency assessments."""

        return self.client.make_request(
            "POST",
            "/api/v1/assessment/competency/assess/bulk",
            json={
                "assessments": assessments,
                "batch_id": batch_id or f"bulk_assessment_{int(time.time())}"
            }
        )

    def get_student_profile(self, student_id: str) -> dict:
        """Get comprehensive student competency profile."""

        return self.client.make_request(
            "GET",
            f"/api/v1/assessment/competency/profile/{student_id}"
        )

    def analyze_knowledge_gaps(
        self,
        student_id: str,
        target_competencies: list,
        severity_filter: str = None
    ) -> dict:
        """Analyze student knowledge gaps."""

        return self.client.make_request(
            "POST",
            "/api/v1/assessment/gaps/analyze",
            json={
                "student_id": student_id,
                "target_competencies": target_competencies,
                "include_prerequisites": True,
                "severity_filter": severity_filter
            }
        )

# Usage examples
assessment = CompetencyAssessment(client)

# Assess single student
competency_result = assessment.assess_student_competency(
    student_id="student_123",
    competency_id="AACN_KNOWLEDGE_1",
    performance_data={
        "quiz_scores": [85, 90, 78],
        "clinical_evaluation": {"patient_care": 4.2, "communication": 4.5},
        "simulation_performance": {"technical_skills": 3.8, "critical_thinking": 4.0}
    }
)

# Bulk assessment for entire class
bulk_assessments = [
    {
        "student_id": "student_123",
        "competency_id": "AACN_KNOWLEDGE_1",
        "performance_data": {"quiz_scores": [85, 90]}
    },
    {
        "student_id": "student_124",
        "competency_id": "AACN_KNOWLEDGE_1",
        "performance_data": {"quiz_scores": [78, 82]}
    }
]

bulk_result = assessment.bulk_assess_competencies(
    assessments=bulk_assessments,
    batch_id="midterm_assessment_2024"
)

# Analyze knowledge gaps
gaps = assessment.analyze_knowledge_gaps(
    student_id="student_123",
    target_competencies=["AACN_KNOWLEDGE_1", "AACN_PERSON_CARE_1"],
    severity_filter="high"
)
```

### Analytics Integration

#### Learning Analytics

```python
class LearningAnalytics:
    def __init__(self, client: BSNKnowledgeAPIClient):
        self.client = client

    def get_student_progress(
        self,
        student_id: str,
        time_period: str = None
    ) -> dict:
        """Get comprehensive student progress metrics."""

        params = {}
        if time_period:
            params["time_period"] = time_period

        return self.client.make_request(
            "GET",
            f"/api/v1/analytics/student/{student_id}/progress",
            params=params
        )

    def get_cohort_analytics(
        self,
        cohort_id: str,
        program: str,
        include_benchmarking: bool = True
    ) -> dict:
        """Get cohort performance analytics."""

        return self.client.make_request(
            "POST",
            "/api/v1/analytics/cohort/analysis",
            json={
                "cohort_id": cohort_id,
                "program": program,
                "analysis_type": "comprehensive",
                "include_benchmarking": include_benchmarking,
                "include_trend_analysis": True
            }
        )

    def generate_institutional_report(
        self,
        institution_id: str,
        report_type: str = "comprehensive",
        time_period: str = "current_semester"
    ) -> dict:
        """Generate institutional effectiveness report."""

        return self.client.make_request(
            "POST",
            "/api/v1/analytics/institutional/report",
            json={
                "institution_id": institution_id,
                "report_type": report_type,
                "time_period": time_period,
                "include_accreditation_metrics": True,
                "include_benchmarking": True
            }
        )

    def predict_performance(
        self,
        student_id: str,
        prediction_type: str = "nclex_readiness"
    ) -> dict:
        """Generate student performance predictions."""

        return self.client.make_request(
            "POST",
            "/api/v1/analytics/predict/performance",
            json={
                "student_id": student_id,
                "prediction_type": prediction_type,
                "include_confidence_intervals": True,
                "include_recommendations": True
            }
        )

# Usage examples
analytics = LearningAnalytics(client)

# Get student progress
progress = analytics.get_student_progress(
    student_id="student_123",
    time_period="current_semester"
)

# Analyze cohort performance
cohort_data = analytics.get_cohort_analytics(
    cohort_id="fall_2024_seniors",
    program="BSN",
    include_benchmarking=True
)

# Generate institutional report
institutional_report = analytics.generate_institutional_report(
    institution_id="university_001",
    report_type="accreditation",
    time_period="academic_year_2024"
)

# Predict NCLEX performance
nclex_prediction = analytics.predict_performance(
    student_id="student_123",
    prediction_type="nclex_readiness"
)
```

## LMS Integration

### Canvas Integration

BSN Knowledge provides deep integration with Canvas LMS through native LTI (Learning Tools Interoperability) support and REST API integration.

#### LTI Integration Setup

```python
class CanvasLTIIntegration:
    def __init__(self, canvas_client_id: str, canvas_client_secret: str):
        self.client_id = canvas_client_id
        self.client_secret = canvas_client_secret

    def create_lti_launch(
        self,
        course_id: str,
        assignment_id: str,
        user_id: str,
        bsn_activity_type: str = "nclex_practice"
    ) -> dict:
        """Create LTI launch for BSN Knowledge activity."""

        lti_params = {
            "lti_message_type": "basic-lti-launch-request",
            "lti_version": "LTI-1p0",
            "resource_link_id": f"canvas_assignment_{assignment_id}",
            "context_id": course_id,
            "user_id": user_id,
            "custom_bsn_activity": bsn_activity_type,
            "custom_canvas_course_id": course_id,
            "lis_outcome_service_url": f"https://canvas.university.edu/api/lti/v1/outcomes/{assignment_id}",
            "ext_outcome_data_values_accepted": "decimal",
        }

        return lti_params

    def handle_grade_passback(
        self,
        assignment_id: str,
        user_id: str,
        score: float,
        max_score: float = 100.0
    ) -> bool:
        """Send grade back to Canvas gradebook."""

        grade_data = {
            "score": score,
            "scoreMaximum": max_score,
            "activityProgress": "Completed",
            "gradingProgress": "FullyGraded"
        }

        # Implementation would use Canvas API or LTI outcome service
        # This is a simplified example
        return self._send_grade_to_canvas(assignment_id, user_id, grade_data)

class CanvasAPIIntegration:
    def __init__(self, canvas_url: str, access_token: str):
        self.canvas_url = canvas_url
        self.access_token = access_token

    def get_courses(self, enrollment_type: str = "teacher") -> list:
        """Get courses for authenticated user."""

        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(
            f"{self.canvas_url}/api/v1/courses",
            headers=headers,
            params={"enrollment_type": enrollment_type}
        )

        return response.json()

    def create_assignment(
        self,
        course_id: str,
        assignment_data: dict
    ) -> dict:
        """Create assignment in Canvas course."""

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            f"{self.canvas_url}/api/v1/courses/{course_id}/assignments",
            headers=headers,
            json={"assignment": assignment_data}
        )

        return response.json()

    def sync_students(self, course_id: str) -> list:
        """Sync student roster from Canvas to BSN Knowledge."""

        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(
            f"{self.canvas_url}/api/v1/courses/{course_id}/enrollments",
            headers=headers,
            params={
                "type": ["StudentEnrollment"],
                "state": ["active"]
            }
        )

        enrollments = response.json()

        # Extract student information
        students = []
        for enrollment in enrollments:
            user = enrollment["user"]
            students.append({
                "canvas_id": user["id"],
                "name": user["name"],
                "email": user["login_id"],
                "sis_user_id": user.get("sis_user_id")
            })

        return students

# Usage example
canvas_api = CanvasAPIIntegration(
    canvas_url="https://canvas.university.edu",
    access_token="your_canvas_token"
)

# Create BSN Knowledge assignment in Canvas
assignment = canvas_api.create_assignment(
    course_id="12345",
    assignment_data={
        "name": "NCLEX Practice - Cardiovascular Nursing",
        "description": "Complete 20 NCLEX-style questions on cardiovascular nursing concepts",
        "points_possible": 100,
        "submission_types": ["external_tool"],
        "external_tool_tag_attributes": {
            "url": "https://api.bsn-knowledge.edu/lti/launch",
            "content_type": "ContextExternalTool"
        }
    }
)

# Sync students to BSN Knowledge
students = canvas_api.sync_students(course_id="12345")
```

### Blackboard Integration

```python
class BlackboardIntegration:
    def __init__(self, bb_url: str, app_key: str, app_secret: str):
        self.bb_url = bb_url
        self.app_key = app_key
        self.app_secret = app_secret
        self.access_token = None

    def authenticate(self) -> str:
        """Authenticate with Blackboard API."""

        auth_url = f"{self.bb_url}/learn/api/public/v1/oauth2/token"

        response = requests.post(
            auth_url,
            data={
                "grant_type": "client_credentials"
            },
            auth=(self.app_key, self.app_secret)
        )

        if response.status_code == 200:
            self.access_token = response.json()["access_token"]
            return self.access_token
        else:
            raise Exception(f"Blackboard authentication failed: {response.status_code}")

    def get_courses(self) -> list:
        """Get courses from Blackboard."""

        if not self.access_token:
            self.authenticate()

        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(
            f"{self.bb_url}/learn/api/public/v1/courses",
            headers=headers
        )

        return response.json()["results"]

    def create_content_item(
        self,
        course_id: str,
        parent_id: str,
        content_data: dict
    ) -> dict:
        """Create content item linking to BSN Knowledge."""

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

        content_item = {
            "title": content_data["title"],
            "body": content_data["description"],
            "contentHandler": {
                "id": "resource/x-bb-externallink"
            },
            "launchInNewWindow": True,
            "url": content_data["bsn_launch_url"]
        }

        response = requests.post(
            f"{self.bb_url}/learn/api/public/v1/courses/{course_id}/contents/{parent_id}/children",
            headers=headers,
            json=content_item
        )

        return response.json()

# Usage
bb_integration = BlackboardIntegration(
    bb_url="https://blackboard.university.edu",
    app_key="your_app_key",
    app_secret="your_app_secret"
)

courses = bb_integration.get_courses()

# Create BSN Knowledge content link
content_item = bb_integration.create_content_item(
    course_id="_123_1",
    parent_id="_456_1",
    content_data={
        "title": "BSN Knowledge - NCLEX Practice",
        "description": "Access personalized NCLEX practice questions",
        "bsn_launch_url": "https://api.bsn-knowledge.edu/lti/launch?activity=nclex"
    }
)
```

## Webhook Integration

### Real-Time Event Notifications

BSN Knowledge provides webhook support for real-time notifications of important events.

#### Webhook Configuration

```python
from flask import Flask, request, jsonify
import hmac
import hashlib
from datetime import datetime

app = Flask(__name__)

class BSNKnowledgeWebhookHandler:
    def __init__(self, webhook_secret: str):
        self.webhook_secret = webhook_secret

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify webhook signature for security."""

        expected_signature = hmac.new(
            self.webhook_secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, f"sha256={expected_signature}")

    def handle_competency_achievement(self, event_data: dict) -> None:
        """Handle student competency achievement event."""

        student_id = event_data["student_id"]
        competency_id = event_data["competency_id"]
        achievement_level = event_data["achievement_level"]

        print(f"Student {student_id} achieved {achievement_level} in {competency_id}")

        # Custom logic: Update LMS gradebook, send notifications, etc.
        self.update_lms_grade(student_id, competency_id, achievement_level)
        self.send_achievement_notification(student_id, competency_id)

    def handle_assessment_completion(self, event_data: dict) -> None:
        """Handle assessment completion event."""

        student_id = event_data["student_id"]
        assessment_id = event_data["assessment_id"]
        score = event_data["score"]

        print(f"Student {student_id} completed assessment {assessment_id} with score {score}")

        # Custom logic: Trigger next steps, update records, etc.
        if score < 70:  # Failing grade
            self.trigger_remediation_plan(student_id, assessment_id)

    def handle_risk_alert(self, event_data: dict) -> None:
        """Handle at-risk student alert."""

        student_id = event_data["student_id"]
        risk_level = event_data["risk_level"]
        risk_factors = event_data["risk_factors"]

        print(f"ALERT: Student {student_id} identified as {risk_level} risk")

        # Custom logic: Alert advisors, trigger interventions
        if risk_level in ["high", "critical"]:
            self.alert_academic_advisor(student_id, risk_factors)
            self.schedule_intervention_meeting(student_id)

webhook_handler = BSNKnowledgeWebhookHandler(webhook_secret="your_webhook_secret")

@app.route('/webhook/bsn-knowledge', methods=['POST'])
def handle_webhook():
    """Handle incoming BSN Knowledge webhooks."""

    # Verify signature
    signature = request.headers.get('X-BSN-Signature')
    if not webhook_handler.verify_signature(request.data, signature):
        return jsonify({"error": "Invalid signature"}), 401

    # Parse event data
    event_data = request.json
    event_type = event_data.get("event_type")

    # Route to appropriate handler
    if event_type == "competency.achieved":
        webhook_handler.handle_competency_achievement(event_data["data"])
    elif event_type == "assessment.completed":
        webhook_handler.handle_assessment_completion(event_data["data"])
    elif event_type == "student.at_risk":
        webhook_handler.handle_risk_alert(event_data["data"])
    else:
        print(f"Unknown event type: {event_type}")

    return jsonify({"status": "processed"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

#### Webhook Event Types

```python
# Available webhook events
WEBHOOK_EVENTS = {
    "competency.achieved": {
        "description": "Student achieves competency level",
        "data_fields": ["student_id", "competency_id", "achievement_level", "timestamp"]
    },
    "competency.declined": {
        "description": "Student competency level decreases",
        "data_fields": ["student_id", "competency_id", "previous_level", "current_level"]
    },
    "assessment.completed": {
        "description": "Student completes assessment",
        "data_fields": ["student_id", "assessment_id", "score", "completion_time"]
    },
    "assessment.failed": {
        "description": "Student fails assessment",
        "data_fields": ["student_id", "assessment_id", "score", "failure_count"]
    },
    "student.at_risk": {
        "description": "Student identified as at-risk",
        "data_fields": ["student_id", "risk_level", "risk_factors", "intervention_recommended"]
    },
    "nclex.readiness_changed": {
        "description": "NCLEX readiness score significant change",
        "data_fields": ["student_id", "previous_score", "current_score", "trend"]
    },
    "content.generated": {
        "description": "New content generated for student",
        "data_fields": ["student_id", "content_type", "topic", "difficulty"]
    }
}

# Example webhook payload
EXAMPLE_WEBHOOK_PAYLOAD = {
    "event_type": "competency.achieved",
    "event_id": "evt_123456789",
    "timestamp": "2024-08-24T14:30:00Z",
    "data": {
        "student_id": "student_123",
        "competency_id": "AACN_KNOWLEDGE_1",
        "achievement_level": "proficient",
        "previous_level": "competent",
        "assessment_id": "assess_456",
        "confidence_score": 0.92
    },
    "metadata": {
        "institution_id": "university_001",
        "program": "BSN",
        "semester": "fall_2024"
    }
}
```

## Enterprise Integration Patterns

### Bulk Data Operations

For high-volume operations, use batch processing endpoints:

```python
class BulkDataProcessor:
    def __init__(self, client: BSNKnowledgeAPIClient):
        self.client = client

    def bulk_student_import(self, students_data: list) -> dict:
        """Import multiple students in bulk."""

        # Process in batches to avoid timeout
        batch_size = 100
        results = []

        for i in range(0, len(students_data), batch_size):
            batch = students_data[i:i + batch_size]

            result = self.client.make_request(
                "POST",
                "/api/v1/admin/students/bulk-import",
                json={
                    "students": batch,
                    "batch_id": f"import_batch_{i // batch_size + 1}",
                    "validate_only": False,
                    "send_welcome_emails": True
                }
            )

            results.append(result)

        return results

    def bulk_competency_assessment(
        self,
        assessments: list,
        parallel_processing: bool = True
    ) -> dict:
        """Process multiple competency assessments."""

        return self.client.make_request(
            "POST",
            "/api/v1/assessment/competency/bulk-assess",
            json={
                "assessments": assessments,
                "parallel_processing": parallel_processing,
                "batch_id": f"bulk_assess_{int(time.time())}",
                "include_analytics": True
            }
        )

    def export_analytics_data(
        self,
        export_type: str,
        filters: dict = None,
        format: str = "json"
    ) -> dict:
        """Export analytics data for external processing."""

        return self.client.make_request(
            "POST",
            "/api/v1/analytics/export",
            json={
                "export_type": export_type,
                "filters": filters or {},
                "format": format,
                "include_metadata": True,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

# Usage
bulk_processor = BulkDataProcessor(client)

# Import students from SIS
students_data = [
    {
        "student_id": "SIS001",
        "name": "John Doe",
        "email": "jdoe@university.edu",
        "program": "BSN",
        "year_level": "junior"
    },
    # ... more students
]

import_results = bulk_processor.bulk_student_import(students_data)

# Bulk assess end-of-semester competencies
assessments = [
    {
        "student_id": "student_123",
        "competency_id": "AACN_KNOWLEDGE_1",
        "performance_data": {"final_exam": 87, "clinical_eval": 4.2}
    },
    # ... more assessments
]

assessment_results = bulk_processor.bulk_competency_assessment(assessments)
```

### Error Handling and Resilience

Implement robust error handling for production integrations:

```python
import time
import random
from typing import Optional
from functools import wraps

class BSNKnowledgeError(Exception):
    """Base exception for BSN Knowledge API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[dict] = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(message)

class RateLimitError(BSNKnowledgeError):
    """Raised when rate limit is exceeded."""
    pass

class AuthenticationError(BSNKnowledgeError):
    """Raised when authentication fails."""
    pass

class ValidationError(BSNKnowledgeError):
    """Raised when request validation fails."""
    pass

def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0):
    """Decorator for retrying failed requests with exponential backoff."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except RateLimitError as e:
                    if attempt == max_retries:
                        raise

                    # Extract rate limit reset time from headers
                    reset_time = getattr(e, 'reset_time', None)
                    if reset_time:
                        sleep_time = reset_time - time.time() + 1
                    else:
                        # Exponential backoff with jitter
                        sleep_time = base_delay * (2 ** attempt) + random.uniform(0, 1)

                    print(f"Rate limited. Waiting {sleep_time:.2f} seconds before retry {attempt + 1}")
                    time.sleep(sleep_time)

                except (ConnectionError, TimeoutError) as e:
                    if attempt == max_retries:
                        raise BSNKnowledgeError(f"Connection failed after {max_retries} retries: {e}")

                    sleep_time = base_delay * (2 ** attempt)
                    print(f"Connection error. Retrying in {sleep_time:.2f} seconds")
                    time.sleep(sleep_time)

                except AuthenticationError:
                    # Don't retry authentication errors
                    raise

                except BSNKnowledgeError as e:
                    if e.status_code and 500 <= e.status_code < 600 and attempt < max_retries:
                        # Retry server errors
                        sleep_time = base_delay * (2 ** attempt)
                        print(f"Server error {e.status_code}. Retrying in {sleep_time:.2f} seconds")
                        time.sleep(sleep_time)
                    else:
                        raise

            return None

        return wrapper
    return decorator

class ResilientBSNClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    def _handle_response(self, response: requests.Response) -> dict:
        """Handle API response and raise appropriate exceptions."""

        if response.status_code == 401:
            raise AuthenticationError("Authentication failed", response.status_code)
        elif response.status_code == 422:
            raise ValidationError("Request validation failed", response.status_code, response.json())
        elif response.status_code == 429:
            reset_time = response.headers.get('X-RateLimit-Reset')
            error = RateLimitError("Rate limit exceeded", response.status_code)
            if reset_time:
                error.reset_time = int(reset_time)
            raise error
        elif response.status_code >= 400:
            raise BSNKnowledgeError(
                f"API request failed: {response.status_code}",
                response.status_code,
                response.json() if response.content else None
            )

        return response.json() if response.content else {}

    @retry_with_backoff(max_retries=3)
    def make_request(
        self,
        method: str,
        endpoint: str,
        timeout: int = 30,
        **kwargs
    ) -> dict:
        """Make resilient API request with retries."""

        url = f"{self.base_url}{endpoint}"
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
            return self._handle_response(response)

        except requests.RequestException as e:
            raise BSNKnowledgeError(f"Request failed: {e}")

# Usage with error handling
resilient_client = ResilientBSNClient(
    base_url="https://api.bsn-knowledge.edu",
    api_key="your-api-key"
)

try:
    questions = resilient_client.make_request(
        "POST",
        "/api/v1/nclex/generate",
        json={"topic": "Cardiovascular Nursing", "question_count": 10}
    )
    print(f"Generated {len(questions['questions'])} questions")

except ValidationError as e:
    print(f"Request validation failed: {e.response_data}")

except RateLimitError as e:
    print(f"Rate limit exceeded. Try again later.")

except AuthenticationError as e:
    print(f"Authentication failed. Check API key.")

except BSNKnowledgeError as e:
    print(f"API error: {e.message}")
```

## Security Best Practices

### Secure API Integration

```python
import os
from cryptography.fernet import Fernet
import keyring

class SecureBSNConfiguration:
    def __init__(self):
        self.encryption_key = self._get_or_create_key()
        self.cipher = Fernet(self.encryption_key)

    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key for local storage."""

        key = keyring.get_password("BSN_Knowledge", "encryption_key")
        if not key:
            key = Fernet.generate_key().decode()
            keyring.set_password("BSN_Knowledge", "encryption_key", key)

        return key.encode()

    def store_api_credentials(self, api_key: str, refresh_token: str = None):
        """Securely store API credentials."""

        encrypted_key = self.cipher.encrypt(api_key.encode())
        keyring.set_password("BSN_Knowledge", "api_key", encrypted_key.decode())

        if refresh_token:
            encrypted_token = self.cipher.encrypt(refresh_token.encode())
            keyring.set_password("BSN_Knowledge", "refresh_token", encrypted_token.decode())

    def get_api_credentials(self) -> tuple[str, str]:
        """Retrieve stored API credentials."""

        encrypted_key = keyring.get_password("BSN_Knowledge", "api_key")
        encrypted_token = keyring.get_password("BSN_Knowledge", "refresh_token")

        if not encrypted_key:
            raise ValueError("No API credentials stored")

        api_key = self.cipher.decrypt(encrypted_key.encode()).decode()
        refresh_token = None

        if encrypted_token:
            refresh_token = self.cipher.decrypt(encrypted_token.encode()).decode()

        return api_key, refresh_token

    def validate_ssl_certificates(self) -> bool:
        """Always validate SSL certificates in production."""
        return os.getenv("BSN_DISABLE_SSL_VERIFY", "false").lower() != "true"

# Usage
config = SecureBSNConfiguration()
config.store_api_credentials("your-api-key", "your-refresh-token")

api_key, refresh_token = config.get_api_credentials()
```

### Input Validation and Sanitization

```python
import re
from typing import Any, Dict, List
from pydantic import BaseModel, Field, validator

class SecureNCLEXRequest(BaseModel):
    """Secure request model for NCLEX generation."""

    topic: str = Field(..., min_length=1, max_length=200)
    question_count: int = Field(default=5, ge=1, le=50)
    difficulty: str = Field(default="intermediate", regex="^(beginner|intermediate|advanced)$")
    focus_areas: List[str] = Field(default=[], max_items=10)

    @validator('topic')
    def validate_topic(cls, v):
        """Validate topic contains only safe characters."""
        if not re.match(r'^[a-zA-Z0-9\s\-_.,()]+$', v):
            raise ValueError('Topic contains invalid characters')
        return v.strip()

    @validator('focus_areas')
    def validate_focus_areas(cls, v):
        """Validate focus areas."""
        safe_areas = []
        for area in v:
            if re.match(r'^[a-zA-Z0-9\s\-_]+$', area) and len(area) <= 100:
                safe_areas.append(area.strip())
            else:
                raise ValueError(f'Invalid focus area: {area}')
        return safe_areas

class SecureAPIRequest:
    """Secure API request handler with input validation."""

    @staticmethod
    def sanitize_student_id(student_id: str) -> str:
        """Sanitize student ID to prevent injection attacks."""

        # Remove any non-alphanumeric characters except hyphens and underscores
        sanitized = re.sub(r'[^a-zA-Z0-9\-_]', '', student_id)

        # Limit length
        if len(sanitized) > 50:
            raise ValueError("Student ID too long")

        if len(sanitized) < 1:
            raise ValueError("Invalid student ID")

        return sanitized

    @staticmethod
    def validate_competency_data(performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize performance data."""

        allowed_keys = {
            'quiz_scores', 'clinical_evaluation', 'simulation_performance',
            'assignment_grades', 'participation_score'
        }

        sanitized = {}
        for key, value in performance_data.items():
            if key not in allowed_keys:
                continue  # Skip unknown keys

            if key == 'quiz_scores' and isinstance(value, list):
                # Validate quiz scores
                scores = [float(s) for s in value if isinstance(s, (int, float)) and 0 <= s <= 100]
                sanitized[key] = scores[:20]  # Limit to 20 scores

            elif key in ['clinical_evaluation', 'simulation_performance'] and isinstance(value, dict):
                # Validate nested evaluation data
                eval_data = {}
                for eval_key, eval_value in value.items():
                    if re.match(r'^[a-zA-Z_]+$', eval_key) and isinstance(eval_value, (int, float)):
                        if 0 <= eval_value <= 5:  # Assuming 5-point scale
                            eval_data[eval_key] = float(eval_value)
                sanitized[key] = eval_data

        return sanitized

# Usage in API calls
def secure_generate_questions(client: BSNKnowledgeAPIClient, request_data: dict) -> dict:
    """Securely generate NCLEX questions with validation."""

    # Validate request data
    validated_request = SecureNCLEXRequest(**request_data)

    # Make API call with validated data
    return client.make_request(
        "POST",
        "/api/v1/nclex/generate",
        json=validated_request.dict()
    )

def secure_assess_competency(
    client: BSNKnowledgeAPIClient,
    student_id: str,
    competency_id: str,
    performance_data: dict
) -> dict:
    """Securely assess student competency with input validation."""

    # Sanitize inputs
    safe_student_id = SecureAPIRequest.sanitize_student_id(student_id)
    safe_performance_data = SecureAPIRequest.validate_competency_data(performance_data)

    # Validate competency ID format
    if not re.match(r'^[A-Z_0-9]+$', competency_id):
        raise ValueError("Invalid competency ID format")

    return client.make_request(
        "POST",
        "/api/v1/assessment/competency",
        json={
            "student_id": safe_student_id,
            "competency_id": competency_id,
            "performance_data": safe_performance_data,
            "assessment_type": "comprehensive"
        }
    )
```

---

## Testing Your Integration

### Integration Testing Framework

```python
import unittest
from unittest.mock import Mock, patch
import responses

class BSNKnowledgeIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.base_url = "https://api.bsn-knowledge.edu"
        self.api_key = "test_api_key"
        self.client = BSNKnowledgeAPIClient(self.base_url, self.api_key)

    @responses.activate
    def test_nclex_question_generation(self):
        """Test NCLEX question generation integration."""

        # Mock API response
        mock_response = {
            "questions": [
                {
                    "id": "q_001",
                    "question_text": "Test question",
                    "correct_answer": ["A"],
                    "rationale": {"correct": "Test rationale"}
                }
            ],
            "generation_metadata": {
                "total_questions": 1,
                "medical_validation_passed": True
            }
        }

        responses.add(
            responses.POST,
            f"{self.base_url}/api/v1/nclex/generate",
            json=mock_response,
            status=200
        )

        # Test request
        result = self.client.make_request(
            "POST",
            "/api/v1/nclex/generate",
            json={
                "topic": "Cardiovascular Nursing",
                "question_count": 1
            }
        )

        # Assertions
        self.assertEqual(len(result["questions"]), 1)
        self.assertTrue(result["generation_metadata"]["medical_validation_passed"])

    @responses.activate
    def test_rate_limiting_handling(self):
        """Test proper handling of rate limiting."""

        # Mock rate limit response
        responses.add(
            responses.POST,
            f"{self.base_url}/api/v1/nclex/generate",
            json={"error": "Rate limit exceeded"},
            status=429,
            headers={"X-RateLimit-Reset": str(int(time.time()) + 60)}
        )

        # Test that rate limit exception is raised
        with self.assertRaises(RateLimitError):
            self.client.make_request(
                "POST",
                "/api/v1/nclex/generate",
                json={"topic": "Test", "question_count": 1}
            )

    def test_input_validation(self):
        """Test input validation and sanitization."""

        # Test invalid student ID
        with self.assertRaises(ValueError):
            SecureAPIRequest.sanitize_student_id("student'; DROP TABLE students; --")

        # Test valid student ID
        valid_id = SecureAPIRequest.sanitize_student_id("student_123")
        self.assertEqual(valid_id, "student_123")

if __name__ == '__main__':
    unittest.main()
```

---

This integration guide provides comprehensive examples for integrating BSN Knowledge into your educational technology infrastructure. For additional support or custom integration requirements, contact our integration team at integrations@bsn-knowledge.edu.
