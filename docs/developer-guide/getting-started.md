# Getting Started Guide

Welcome to the BSN Knowledge API! This guide will help you get up and running quickly with authentication, your first API calls, and common integration patterns.

## Prerequisites

Before you begin, ensure you have:

- **API Access**: Contact BSN Knowledge support for API credentials
- **Development Environment**: Choose your preferred programming language
- **HTTPS Support**: All API calls must use HTTPS
- **JSON Support**: API uses JSON for request/response format

## Quick Start Checklist

- [ ] Obtain API credentials (username/password)
- [ ] Set up development environment
- [ ] Test authentication
- [ ] Make your first API call
- [ ] Explore interactive documentation
- [ ] Implement error handling
- [ ] Set up rate limiting

## Step 1: Authentication Setup

### Get Your Access Tokens

Start by authenticating to get your JWT tokens:

```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Save Your Tokens Securely

**Important**: Store tokens securely and never expose them in client-side code.

```python
# Python example - secure token storage
import os
from pathlib import Path

# Store in environment variables or secure config
os.environ['BSN_ACCESS_TOKEN'] = access_token
os.environ['BSN_REFRESH_TOKEN'] = refresh_token

# Or use a secure config file
config_file = Path.home() / '.bsn_knowledge' / 'credentials'
config_file.parent.mkdir(exist_ok=True)
with open(config_file, 'w') as f:
    f.write(f"access_token={access_token}\nrefresh_token={refresh_token}")
```

## Step 2: Your First API Call

### Test Authentication

Verify your token works by getting your user information:

```bash
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "id": 1,
  "username": "student1",
  "email": "student1@nursing.edu",
  "role": "student",
  "is_active": true,
  "created_at": "2024-08-24T10:00:00Z"
}
```

### Generate Your First NCLEX Questions

Try the core functionality - generating nursing practice questions:

```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/nclex/generate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "Cardiovascular Nursing",
    "difficulty": "intermediate",
    "question_count": 3,
    "settings": {
      "include_rationales": true
    }
  }'
```

## Step 3: SDK Setup (Recommended)

### Install Official SDK

Instead of making raw HTTP requests, use our official SDKs:

#### Python
```bash
pip install bsn-knowledge-sdk
```

```python
from bsn_knowledge_sdk import BSNKnowledgeClient

# Initialize client
client = BSNKnowledgeClient(
    base_url="https://api.bsn-knowledge.edu",
    timeout=30
)

# Login
client.login('your-username', 'your-password')

# Generate questions
questions = client.nclex.generate(
    topic="Pediatric Nursing",
    difficulty="intermediate",
    question_count=5,
    settings={"include_rationales": True}
)

print(f"Generated {len(questions.questions)} questions")
for q in questions.questions:
    print(f"Q: {q.question_text}")
    print(f"A: {q.correct_answer}")
    print("---")
```

#### JavaScript/Node.js
```bash
npm install bsn-knowledge-sdk
```

```javascript
const BSNKnowledgeClient = require('bsn-knowledge-sdk');

// Initialize client
const client = new BSNKnowledgeClient({
  baseURL: 'https://api.bsn-knowledge.edu',
  timeout: 30000
});

async function main() {
  try {
    // Login
    await client.login('your-username', 'your-password');

    // Generate study guide
    const studyGuide = await client.studyGuides.create({
      topic: 'Mental Health Nursing',
      student_level: 'intermediate',
      focus_areas: ['anxiety_disorders', 'mood_disorders'],
      length: 'detailed'
    });

    console.log(`Study guide created: ${studyGuide.title}`);
    console.log(`Sections: ${studyGuide.sections.length}`);

  } catch (error) {
    console.error('API Error:', error.message);
  }
}

main();
```

## Step 4: Environment Setup

### Development Environment

Create a development configuration:

```python
# config/development.py
class DevelopmentConfig:
    BSN_API_BASE_URL = "https://dev-api.bsn-knowledge.edu"
    BSN_API_TIMEOUT = 30
    BSN_API_RETRIES = 3

    # Rate limiting - be conservative in development
    REQUEST_DELAY = 0.5  # seconds between requests

    # Logging
    LOG_LEVEL = "DEBUG"
    LOG_API_REQUESTS = True
```

```javascript
// config/development.js
module.exports = {
  bsnApi: {
    baseURL: 'https://dev-api.bsn-knowledge.edu',
    timeout: 30000,
    retries: 3
  },

  // Rate limiting
  requestDelay: 500, // ms between requests

  // Logging
  logLevel: 'debug',
  logApiRequests: true
};
```

### Production Environment

```python
# config/production.py
class ProductionConfig:
    BSN_API_BASE_URL = "https://api.bsn-knowledge.edu"
    BSN_API_TIMEOUT = 15
    BSN_API_RETRIES = 2

    # Security
    VERIFY_SSL = True
    USE_CONNECTION_POOLING = True

    # Performance
    CACHE_RESPONSES = True
    CACHE_TTL = 300  # 5 minutes

    # Logging
    LOG_LEVEL = "INFO"
    LOG_API_REQUESTS = False
```

## Step 5: Error Handling

### Basic Error Handling

Always implement proper error handling:

```python
import logging
from bsn_knowledge_sdk import BSNKnowledgeClient, BSNKnowledgeError

logger = logging.getLogger(__name__)

def safe_api_call():
    client = BSNKnowledgeClient()

    try:
        client.login('username', 'password')

        # API call with error handling
        result = client.nclex.generate(
            topic="Medical-Surgical Nursing",
            question_count=5
        )

        return result

    except BSNKnowledgeError as e:
        # Handle API-specific errors
        if e.status_code == 401:
            logger.error("Authentication failed - check credentials")
            # Trigger re-authentication
        elif e.status_code == 429:
            logger.warning("Rate limit exceeded - backing off")
            # Implement exponential backoff
        elif e.status_code >= 500:
            logger.error(f"Server error: {e.message}")
            # Retry with exponential backoff
        else:
            logger.error(f"API error: {e.message}")

        raise

    except Exception as e:
        logger.exception("Unexpected error in API call")
        raise
```

### Retry Logic with Exponential Backoff

```python
import time
import random
from functools import wraps

def retry_with_backoff(max_retries=3, base_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except BSNKnowledgeError as e:
                    if e.status_code == 429 and attempt < max_retries:
                        # Rate limited - exponential backoff with jitter
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        logger.info(f"Rate limited, retrying in {delay:.2f}s")
                        time.sleep(delay)
                        continue
                    elif e.status_code >= 500 and attempt < max_retries:
                        # Server error - retry
                        delay = base_delay * (2 ** attempt)
                        logger.info(f"Server error, retrying in {delay:.2f}s")
                        time.sleep(delay)
                        continue
                    else:
                        # Don't retry other errors or max retries reached
                        raise
                except Exception:
                    # Don't retry unexpected errors
                    raise

        return wrapper
    return decorator

# Usage
@retry_with_backoff(max_retries=3)
def generate_questions_with_retry(client, topic):
    return client.nclex.generate(topic=topic, question_count=5)
```

## Step 6: Rate Limiting Best Practices

### Respect Rate Limits

Monitor your rate limit usage:

```python
class RateLimitAwareClient:
    def __init__(self, client):
        self.client = client
        self.rate_limits = {}

    def make_request(self, endpoint_func, *args, **kwargs):
        # Check if we're approaching rate limits
        if self._should_throttle():
            time.sleep(1)

        response = endpoint_func(*args, **kwargs)

        # Update rate limit tracking from response headers
        self._update_rate_limits(response.headers)

        return response

    def _should_throttle(self):
        # Implement throttling logic based on remaining requests
        for endpoint_type, limits in self.rate_limits.items():
            remaining = limits.get('remaining', float('inf'))
            if remaining < 10:  # Conservative threshold
                return True
        return False

    def _update_rate_limits(self, headers):
        # Parse rate limit headers
        limit = headers.get('X-RateLimit-Limit')
        remaining = headers.get('X-RateLimit-Remaining')
        reset = headers.get('X-RateLimit-Reset')

        # Store for future reference
        # Implementation details...
```

### Batch Operations

Use batch operations when available:

```python
# Instead of multiple individual requests
for student_id in student_ids:
    assessment = client.assessment.assess_competency(
        student_id=student_id,
        competency_id="aacn_domain_1_comp_1",
        performance_data=data[student_id]
    )

# Use bulk assessment
assessments = [
    {
        "student_id": student_id,
        "competency_id": "aacn_domain_1_comp_1",
        "performance_data": data[student_id]
    }
    for student_id in student_ids
]

bulk_result = client.assessment.assess_bulk({
    "assessments": assessments,
    "batch_id": "semester_final_2024"
})
```

## Step 7: Testing Your Integration

### Unit Tests

Write tests for your API integration:

```python
import pytest
from unittest.mock import Mock, patch
from your_app import BSNKnowledgeService

class TestBSNKnowledgeIntegration:

    @patch('your_app.BSNKnowledgeClient')
    def test_generate_questions_success(self, mock_client):
        # Setup mock
        mock_instance = Mock()
        mock_client.return_value = mock_instance
        mock_instance.nclex.generate.return_value = Mock(
            questions=[Mock(question_text="Test question", correct_answer=["A"])]
        )

        # Test
        service = BSNKnowledgeService()
        result = service.generate_study_questions("Cardiology", 5)

        # Assert
        assert len(result.questions) == 1
        mock_instance.nclex.generate.assert_called_once_with(
            topic="Cardiology",
            question_count=5
        )

    @patch('your_app.BSNKnowledgeClient')
    def test_authentication_failure(self, mock_client):
        # Setup mock to raise authentication error
        mock_instance = Mock()
        mock_client.return_value = mock_instance
        mock_instance.login.side_effect = BSNKnowledgeError("Authentication failed", 401)

        # Test
        service = BSNKnowledgeService()

        with pytest.raises(BSNKnowledgeError) as exc_info:
            service.authenticate("invalid", "credentials")

        assert exc_info.value.status_code == 401
```

### Integration Tests

Test against the development API:

```python
import pytest
from bsn_knowledge_sdk import BSNKnowledgeClient

@pytest.mark.integration
class TestAPIIntegration:

    @pytest.fixture
    def client(self):
        client = BSNKnowledgeClient(
            base_url="https://dev-api.bsn-knowledge.edu"
        )
        client.login('test_student', 'test_password')
        return client

    def test_nclex_generation_flow(self, client):
        # Test complete NCLEX generation workflow
        result = client.nclex.generate(
            topic="Fundamentals of Nursing",
            difficulty="beginner",
            question_count=2,
            settings={"include_rationales": True}
        )

        assert len(result.questions) == 2
        assert all(q.rationale for q in result.questions)
        assert result.generation_metadata.medical_validation_passed

    def test_assessment_workflow(self, client):
        # Test competency assessment workflow
        assessment_result = client.assessment.assess_competency(
            student_id="test_student_001",
            competency_id="aacn_domain_1_comp_1",
            performance_data={
                "quiz_scores": [85, 90, 88],
                "clinical_evaluation": {"patient_care": 4.0}
            }
        )

        assert assessment_result.current_level in [
            "novice", "advanced_beginner", "competent", "proficient", "expert"
        ]
        assert 0 <= assessment_result.proficiency_score <= 100
```

## Step 8: Monitoring and Logging

### Request Logging

Log API requests for debugging:

```python
import logging
import json
from datetime import datetime

class APILogger:
    def __init__(self):
        self.logger = logging.getLogger('bsn_api')

        # Configure file handler
        handler = logging.FileHandler('bsn_api.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_request(self, method, url, data=None, response=None, error=None):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'method': method,
            'url': url,
            'request_data': data,
            'response_status': getattr(response, 'status_code', None),
            'response_data': getattr(response, 'json', lambda: None)(),
            'error': str(error) if error else None
        }

        if error:
            self.logger.error(f"API Error: {json.dumps(log_entry)}")
        else:
            self.logger.info(f"API Request: {json.dumps(log_entry)}")

# Usage in your API client wrapper
api_logger = APILogger()

def logged_api_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            response = func(*args, **kwargs)
            api_logger.log_request(
                method=func.__name__,
                url=kwargs.get('url', 'unknown'),
                data=kwargs.get('data'),
                response=response
            )
            return response
        except Exception as e:
            api_logger.log_request(
                method=func.__name__,
                url=kwargs.get('url', 'unknown'),
                data=kwargs.get('data'),
                error=e
            )
            raise
    return wrapper
```

### Health Monitoring

Monitor API health in your application:

```python
import asyncio
from datetime import datetime, timedelta

class APIHealthMonitor:
    def __init__(self, client):
        self.client = client
        self.health_status = "unknown"
        self.last_check = None
        self.check_interval = timedelta(minutes=5)

    async def check_health(self):
        try:
            health_response = await self.client.health_check()
            self.health_status = health_response.get('status', 'unknown')
            self.last_check = datetime.utcnow()

            if self.health_status != 'healthy':
                # Alert your monitoring system
                await self._send_alert(f"API health check failed: {self.health_status}")

        except Exception as e:
            self.health_status = "error"
            await self._send_alert(f"API health check error: {str(e)}")

    async def _send_alert(self, message):
        # Implement alerting (email, Slack, etc.)
        print(f"ALERT: {message}")

    async def start_monitoring(self):
        while True:
            await self.check_health()
            await asyncio.sleep(self.check_interval.total_seconds())
```

## Step 9: Interactive Documentation

### Explore the API

Use the interactive Swagger documentation:

1. **Visit**: [https://api.bsn-knowledge.edu/docs](https://api.bsn-knowledge.edu/docs)
2. **Authenticate**: Click "Authorize" and enter `Bearer YOUR_TOKEN`
3. **Test Endpoints**: Try different endpoints directly in the browser
4. **Export Collection**: Download Postman collection for offline testing

### Alternative Documentation

- **ReDoc**: [https://api.bsn-knowledge.edu/redoc](https://api.bsn-knowledge.edu/redoc)
- **OpenAPI Spec**: [https://api.bsn-knowledge.edu/openapi.json](https://api.bsn-knowledge.edu/openapi.json)

## Next Steps

Now that you have the basics working:

1. **Read the Complete Documentation**:
   - [Authentication Guide](../api-reference/authentication.md)
   - [NCLEX Generation](../api-reference/endpoints/nclex.md)
   - [Assessment API](../api-reference/endpoints/assessment.md)
   - [Analytics API](../api-reference/endpoints/analytics.md)

2. **Implement Advanced Features**:
   - [Study Guide Generation](../api-reference/endpoints/study-guides.md)
   - [Clinical Decision Support](../api-reference/endpoints/clinical-support.md)
   - [Adaptive Learning Paths](../api-reference/endpoints/adaptive-learning.md)

3. **Review Best Practices**:
   - [Integration Patterns](integration-guide.md)
   - [Performance Optimization](best-practices.md)
   - [Security Guidelines](../compliance/security-best-practices.md)

4. **Production Deployment**:
   - [Deployment Guide](../technical/deployment.md)
   - [Monitoring Setup](../technical/performance.md)
   - [Security Configuration](../technical/security.md)

## Common Issues and Troubleshooting

### Authentication Issues

```bash
# Test token validity
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/verify-token \
  -H "Authorization: Bearer YOUR_TOKEN"

# If invalid, refresh or re-authenticate
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

### Rate Limiting Issues

```python
# Check rate limit headers in response
def check_rate_limits(response):
    headers = response.headers
    print(f"Rate Limit: {headers.get('X-RateLimit-Limit')}")
    print(f"Remaining: {headers.get('X-RateLimit-Remaining')}")
    print(f"Reset Time: {headers.get('X-RateLimit-Reset')}")
```

### Connection Issues

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure robust HTTP session
session = requests.Session()

# Retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)
session.mount("http://", adapter)

# Use session for API calls
response = session.post(
    "https://api.bsn-knowledge.edu/api/v1/auth/login",
    json={"username": "user", "password": "pass"},
    timeout=30
)
```

---

**Support Resources:**
- **Technical Support**: support@bsn-knowledge.edu
- **Documentation**: [https://docs.bsn-knowledge.edu](https://docs.bsn-knowledge.edu)
- **Status Page**: [https://status.bsn-knowledge.edu](https://status.bsn-knowledge.edu)
- **Community Forum**: [https://community.bsn-knowledge.edu](https://community.bsn-knowledge.edu)
