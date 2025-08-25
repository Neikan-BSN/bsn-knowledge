# Error Handling Guide

BSN Knowledge API provides comprehensive error handling with standardized error codes, detailed error messages, and actionable resolution guidance.

## Error Response Format

All API errors follow a consistent JSON format for reliable error handling:

```json
{
  "error": true,
  "error_code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123",
  "path": "/api/v1/assessment/competency",
  "details": {
    "validation_errors": [
      {
        "field": "student_id",
        "message": "Student ID is required",
        "type": "missing"
      }
    ]
  }
}
```

### Error Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `error` | boolean | Always `true` for error responses |
| `error_code` | string | Standardized error code for programmatic handling |
| `message` | string | Human-readable error description |
| `timestamp` | string | ISO 8601 timestamp when error occurred |
| `request_id` | string | Unique identifier for request tracking |
| `path` | string | API endpoint where error occurred |
| `details` | object | Additional error-specific information |

## HTTP Status Codes

### 4xx Client Errors

#### 400 Bad Request
**When**: Invalid request syntax or malformed request body

```json
{
  "error": true,
  "error_code": "BAD_REQUEST",
  "message": "Invalid JSON in request body",
  "details": {
    "json_error": "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"
  }
}
```

**Common Causes**:
- Malformed JSON in request body
- Invalid request parameters
- Missing Content-Type header

**Resolution**:
- Validate JSON syntax
- Check request parameter formats
- Include `Content-Type: application/json` header

#### 401 Unauthorized
**When**: Authentication required or authentication failed

```json
{
  "error": true,
  "error_code": "AUTHENTICATION_ERROR",
  "message": "Could not validate credentials",
  "details": {
    "auth_method": "jwt_bearer",
    "token_status": "expired"
  }
}
```

**Common Causes**:
- Missing Authorization header
- Expired or invalid JWT token
- Malformed Bearer token format

**Resolution**:
- Include `Authorization: Bearer <token>` header
- Refresh expired tokens using `/api/v1/auth/refresh`
- Re-authenticate if refresh token is expired

#### 403 Forbidden
**When**: Valid authentication but insufficient permissions

```json
{
  "error": true,
  "error_code": "AUTHORIZATION_ERROR",
  "message": "Insufficient permissions. Required role: instructor",
  "details": {
    "user_role": "student",
    "required_role": "instructor",
    "endpoint_access_level": "instructor_only"
  }
}
```

**Common Causes**:
- User role lacks required permissions
- Attempting to access administrative functions
- Cross-user data access without proper authorization

**Resolution**:
- Contact administrator for role assignment
- Use appropriate user account for the operation
- Request access through proper channels

#### 404 Not Found
**When**: Requested resource does not exist

```json
{
  "error": true,
  "error_code": "RESOURCE_NOT_FOUND",
  "message": "Student with ID 'student_99999' not found",
  "details": {
    "resource_type": "student",
    "resource_id": "student_99999"
  }
}
```

**Common Causes**:
- Invalid resource ID
- Resource has been deleted
- User lacks access to resource

**Resolution**:
- Verify resource ID format and existence
- Check user permissions for resource access
- Use appropriate search endpoints to find valid resources

#### 422 Unprocessable Entity
**When**: Valid request syntax but semantic errors

```json
{
  "error": true,
  "error_code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "details": {
    "validation_errors": [
      {
        "field": "question_count",
        "message": "Question count must be between 1 and 50",
        "type": "value_error",
        "input": 100
      },
      {
        "field": "difficulty",
        "message": "Difficulty must be one of: beginner, intermediate, advanced",
        "type": "value_error",
        "input": "expert"
      }
    ]
  }
}
```

**Common Causes**:
- Field values outside acceptable ranges
- Invalid enum values
- Failed business logic validation
- Missing required fields

**Resolution**:
- Check field validation requirements in documentation
- Ensure all required fields are provided
- Use valid enum values as specified

#### 429 Too Many Requests
**When**: Rate limit exceeded

```json
{
  "error": true,
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded for content_generation. Please try again later.",
  "details": {
    "endpoint_type": "content_generation",
    "retry_after_seconds": 1800,
    "current_limit": 50,
    "requests_remaining": 0,
    "window_seconds": 3600
  }
}
```

**Headers**:
```http
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1692873600
Retry-After: 1800
```

**Resolution**:
- Wait for the time specified in `retry_after_seconds`
- Implement exponential backoff for retries
- Consider request batching or caching strategies
- Monitor rate limit headers in responses

### 5xx Server Errors

#### 500 Internal Server Error
**When**: Unexpected server-side error

```json
{
  "error": true,
  "error_code": "INTERNAL_ERROR",
  "message": "An unexpected error occurred. Please try again later.",
  "request_id": "req_abc123"
}
```

**Resolution**:
- Retry the request after a short delay
- Contact support if error persists
- Include request_id when reporting issues

#### 503 Service Unavailable
**When**: External service dependency failure

```json
{
  "error": true,
  "error_code": "EXTERNAL_SERVICE_ERROR",
  "message": "RAGnostic AI service temporarily unavailable",
  "details": {
    "service": "ragnostic_ai",
    "estimated_recovery": "2024-08-24T10:30:00Z"
  }
}
```

**Resolution**:
- Retry after estimated recovery time
- Use cached responses if available
- Consider alternative workflows if applicable

## Standardized Error Codes

### Authentication & Authorization

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `AUTHENTICATION_ERROR` | 401 | Invalid or missing authentication | Provide valid JWT token |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions | Check user role requirements |
| `TOKEN_EXPIRED` | 401 | JWT token has expired | Refresh token or re-authenticate |
| `INVALID_TOKEN_FORMAT` | 401 | Malformed Authorization header | Use `Bearer <token>` format |

### Request Validation

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `VALIDATION_ERROR` | 422 | Request validation failed | Check field requirements |
| `BAD_REQUEST` | 400 | Invalid request format | Verify JSON syntax and structure |
| `MISSING_REQUIRED_FIELD` | 422 | Required field not provided | Include all required fields |
| `INVALID_FIELD_VALUE` | 422 | Field value outside valid range | Use valid field values |

### Resource Management

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `RESOURCE_NOT_FOUND` | 404 | Requested resource not found | Verify resource ID and permissions |
| `DUPLICATE_RESOURCE` | 409 | Resource already exists | Use different identifier or update existing |
| `RESOURCE_CONFLICT` | 409 | Resource state conflict | Resolve conflicts and retry |

### Business Logic

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `BUSINESS_LOGIC_ERROR` | 422 | Business rule violation | Check business logic requirements |
| `CONTENT_GENERATION_ERROR` | 422 | AI content generation failed | Try different parameters or retry |
| `ASSESSMENT_ERROR` | 422 | Assessment processing failed | Provide more performance data |
| `INSUFFICIENT_DATA` | 422 | Not enough data for operation | Provide additional required data |

### System & External Services

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `RATE_LIMIT_EXCEEDED` | 429 | Request rate limit exceeded | Wait and retry with backoff |
| `EXTERNAL_SERVICE_ERROR` | 503 | External dependency failure | Retry after service recovery |
| `INTERNAL_ERROR` | 500 | Unexpected system error | Contact support with request_id |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable | Retry after delay |

## Error Handling Best Practices

### 1. Implement Comprehensive Error Handling

```python
from bsn_knowledge_sdk import BSNKnowledgeClient, BSNKnowledgeError
import logging

logger = logging.getLogger(__name__)

async def robust_api_call():
    client = BSNKnowledgeClient()

    try:
        # API operation
        result = await client.nclex.generate(
            topic="Cardiovascular Nursing",
            question_count=5
        )
        return result

    except BSNKnowledgeError as e:
        # Handle specific API errors
        if e.error_code == "RATE_LIMIT_EXCEEDED":
            retry_after = e.details.get("retry_after_seconds", 60)
            logger.info(f"Rate limited. Retrying after {retry_after} seconds")
            await asyncio.sleep(retry_after)
            # Implement retry logic here

        elif e.error_code == "AUTHENTICATION_ERROR":
            logger.error("Authentication failed - check credentials")
            # Implement re-authentication logic

        elif e.error_code == "VALIDATION_ERROR":
            validation_errors = e.details.get("validation_errors", [])
            for error in validation_errors:
                logger.error(f"Validation error: {error['field']} - {error['message']}")
            # Handle validation errors appropriately

        else:
            logger.error(f"API error: {e.error_code} - {e.message}")

        # Re-raise or handle as appropriate
        raise

    except Exception as e:
        logger.exception("Unexpected error in API call")
        raise
```

### 2. Exponential Backoff for Retries

```python
import asyncio
import random
from typing import Callable, Any

class ExponentialBackoff:
    def __init__(self, max_retries=3, base_delay=1, max_delay=60):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with exponential backoff retry"""

        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)

            except BSNKnowledgeError as e:
                if e.error_code == "RATE_LIMIT_EXCEEDED":
                    # Use server-specified retry time if available
                    retry_after = e.details.get("retry_after_seconds")
                    if retry_after:
                        await asyncio.sleep(retry_after)
                        continue

                if attempt == self.max_retries:
                    raise  # Final attempt failed

                # Calculate backoff delay with jitter
                delay = min(
                    self.base_delay * (2 ** attempt) + random.uniform(0, 1),
                    self.max_delay
                )

                logger.info(f"Retrying after {delay:.2f}s (attempt {attempt + 1}/{self.max_retries})")
                await asyncio.sleep(delay)

            except Exception as e:
                # Don't retry unexpected errors
                logger.error(f"Non-retryable error: {e}")
                raise

# Usage
backoff = ExponentialBackoff(max_retries=3)
result = await backoff.execute(
    client.assessment.assess_competency,
    student_id="student_123",
    competency_id="aacn_domain_1_comp_1",
    performance_data=data
)
```

### 3. Graceful Degradation

```python
class GracefulClient:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    async def get_with_fallback(self, primary_func, fallback_func, cache_key=None):
        """Attempt primary function with fallback on failure"""

        try:
            result = await primary_func()

            # Cache successful result
            if cache_key:
                self.cache[cache_key] = result

            return result

        except BSNKnowledgeError as e:
            logger.warning(f"Primary function failed: {e.message}")

            # Try cached result first
            if cache_key and cache_key in self.cache:
                logger.info("Using cached result")
                return self.cache[cache_key]

            # Try fallback function
            if fallback_func:
                logger.info("Using fallback function")
                return await fallback_func()

            # No fallback available
            raise

# Usage
graceful_client = GracefulClient(client)

# Primary: Generate new questions, Fallback: Use cached/predefined questions
questions = await graceful_client.get_with_fallback(
    primary_func=lambda: client.nclex.generate(topic="Cardiology"),
    fallback_func=lambda: get_predefined_questions("Cardiology"),
    cache_key="cardiology_questions"
)
```

### 4. Error Context and Logging

```python
import structlog
from contextlib import contextmanager

logger = structlog.get_logger()

@contextmanager
def error_context(**context):
    """Add context to error logging"""
    try:
        yield
    except BSNKnowledgeError as e:
        logger.error(
            "API error occurred",
            error_code=e.error_code,
            status_code=e.status_code,
            message=e.message,
            request_id=getattr(e, 'request_id', None),
            **context
        )
        raise
    except Exception as e:
        logger.exception(
            "Unexpected error occurred",
            error_type=type(e).__name__,
            **context
        )
        raise

# Usage
async def generate_study_session(student_id, topics):
    with error_context(
        operation="study_session_generation",
        student_id=student_id,
        topic_count=len(topics)
    ):
        questions = []
        for topic in topics:
            topic_questions = await client.nclex.generate(
                topic=topic,
                question_count=5
            )
            questions.extend(topic_questions.questions)

        return questions
```

### 5. User-Friendly Error Messages

```python
class ErrorMessageTranslator:
    """Convert technical error messages to user-friendly messages"""

    USER_MESSAGES = {
        "AUTHENTICATION_ERROR": "Please log in again to continue.",
        "AUTHORIZATION_ERROR": "You don't have permission to perform this action.",
        "RATE_LIMIT_EXCEEDED": "Too many requests. Please wait a moment and try again.",
        "VALIDATION_ERROR": "Please check your input and try again.",
        "EXTERNAL_SERVICE_ERROR": "Our AI service is temporarily unavailable. Please try again in a few minutes.",
        "RESOURCE_NOT_FOUND": "The requested item could not be found.",
        "CONTENT_GENERATION_ERROR": "Unable to generate content with the current settings. Please try different options."
    }

    def translate_error(self, error: BSNKnowledgeError) -> dict:
        """Translate technical error to user-friendly message"""
        user_message = self.USER_MESSAGES.get(
            error.error_code,
            "An unexpected error occurred. Please try again."
        )

        return {
            "user_message": user_message,
            "technical_details": {
                "error_code": error.error_code,
                "message": error.message,
                "request_id": getattr(error, 'request_id', None)
            },
            "suggested_actions": self._get_suggested_actions(error.error_code)
        }

    def _get_suggested_actions(self, error_code: str) -> list:
        actions = {
            "AUTHENTICATION_ERROR": ["Log in again", "Check your internet connection"],
            "AUTHORIZATION_ERROR": ["Contact your instructor for access", "Verify your account permissions"],
            "RATE_LIMIT_EXCEEDED": ["Wait a few minutes", "Reduce the number of requests"],
            "VALIDATION_ERROR": ["Check required fields", "Verify input formats"],
            "EXTERNAL_SERVICE_ERROR": ["Try again in a few minutes", "Contact support if issue persists"]
        }
        return actions.get(error_code, ["Try again", "Contact support if issue persists"])

# Usage in web application
translator = ErrorMessageTranslator()

try:
    result = await api_operation()
except BSNKnowledgeError as e:
    error_info = translator.translate_error(e)
    return render_error_page(error_info)
```

## Debugging and Troubleshooting

### 1. Enable Debug Logging

```python
import logging

# Enable debug logging for BSN Knowledge SDK
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('bsn_knowledge_sdk')
logger.setLevel(logging.DEBUG)

# This will log all API requests and responses
client = BSNKnowledgeClient(debug=True)
```

### 2. Request ID Tracking

Always log and track request IDs for debugging:

```python
async def make_tracked_request(client, operation_name, **kwargs):
    """Make API request with request ID tracking"""
    try:
        result = await client.some_operation(**kwargs)
        logger.info(f"{operation_name} succeeded")
        return result

    except BSNKnowledgeError as e:
        request_id = getattr(e, 'request_id', 'unknown')
        logger.error(f"{operation_name} failed - Request ID: {request_id}")

        # Store request ID for support tickets
        error_tracker.record_error(
            operation=operation_name,
            request_id=request_id,
            error_code=e.error_code,
            timestamp=datetime.utcnow()
        )
        raise
```

### 3. Common Troubleshooting Steps

**Authentication Issues:**
```python
# Verify token format and expiration
def debug_jwt_token(token):
    try:
        # Decode without verification for debugging
        header, payload, signature = token.split('.')

        import base64
        import json

        # Decode payload (add padding if needed)
        payload += '=' * (4 - len(payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload)
        token_data = json.loads(decoded_payload)

        print(f"Token expires at: {token_data.get('exp')}")
        print(f"Current time: {time.time()}")
        print(f"User: {token_data.get('sub')}")
        print(f"Role: {token_data.get('role')}")

    except Exception as e:
        print(f"Failed to decode token: {e}")

# Usage
debug_jwt_token(your_access_token)
```

**Rate Limiting Issues:**
```python
# Check rate limit status
def check_rate_limit_status(response_headers):
    print(f"Rate Limit: {response_headers.get('X-RateLimit-Limit')}")
    print(f"Remaining: {response_headers.get('X-RateLimit-Remaining')}")
    print(f"Reset Time: {response_headers.get('X-RateLimit-Reset')}")

    reset_time = int(response_headers.get('X-RateLimit-Reset', 0))
    current_time = time.time()

    if reset_time > current_time:
        wait_time = reset_time - current_time
        print(f"Wait time: {wait_time} seconds")
```

**Validation Errors:**
```python
# Debug validation errors
def debug_validation_errors(validation_error):
    print("Validation errors found:")

    for error in validation_error.details.get('validation_errors', []):
        print(f"  Field: {error['field']}")
        print(f"  Message: {error['message']}")
        print(f"  Type: {error['type']}")
        if 'input' in error:
            print(f"  Invalid Input: {error['input']}")
        print()
```

---

**Related Documentation:**
- [Authentication Guide](authentication.md) - Authentication and authorization errors
- [Rate Limiting Guide](rate-limiting.md) - Rate limiting and throttling
- [API Reference](overview.md) - Complete API documentation
- [Best Practices](../developer-guide/best-practices.md) - Client implementation guidelines
