# Rate Limiting Guide

BSN Knowledge implements intelligent rate limiting to ensure fair resource allocation, prevent abuse, and maintain optimal performance for all users.

## Rate Limiting Overview

### Rate Limiting Strategy

The API uses a **tiered rate limiting system** based on endpoint functionality and computational requirements:

1. **User-Based Limits**: Rates are applied per authenticated user account
2. **Endpoint-Type Classification**: Different limits for different endpoint categories
3. **Time Window**: Sliding window approach with hourly reset cycles
4. **Graceful Degradation**: Clear error messages with retry guidance

### Rate Limit Headers

Every API response includes rate limiting information:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1692873600
X-RateLimit-Window: 3600
```

## Rate Limit Tiers

### Tier 1: General API Operations
**Limit**: 1,000 requests per hour
**Window**: 3600 seconds
**Applies to**: Standard CRUD operations, user management, basic queries

**Included Endpoints**:
- `/api/v1/auth/me` - Current user information
- `/api/v1/auth/verify-token` - Token verification
- `/api/v1/assessment/competencies/available` - Available competencies
- `/api/v1/assessment/domains` - AACN domains
- `/api/v1/assessment/proficiency-levels` - Proficiency levels
- `/api/v1/analytics/dashboard/summary` - Dashboard data
- All health check and system status endpoints

### Tier 2: Content Generation
**Limit**: 50 requests per hour
**Window**: 3600 seconds
**Applies to**: AI-powered content generation requiring RAGnostic integration

**Included Endpoints**:
- `/api/v1/nclex/generate` - NCLEX question generation
- `/api/v1/study-guide/create` - Study guide creation
- `/api/v1/clinical-support/generate` - Clinical scenarios
- Any endpoint using AI content generation

**Rationale**: AI content generation requires significant computational resources and external API calls.

### Tier 3: Assessment Operations
**Limit**: 200 requests per hour
**Window**: 3600 seconds
**Applies to**: Competency assessments, evaluations, and complex analytics

**Included Endpoints**:
- `/api/v1/assessment/competency` - Single competency assessment
- `/api/v1/assessment/competency/assess/bulk` - Bulk assessments
- `/api/v1/assessment/gaps/analyze` - Gap analysis
- `/api/v1/assessment/learning-path/generate` - Learning path generation
- Complex assessment-related operations

### Tier 4: Analytics & Reporting
**Limit**: 500 requests per hour
**Window**: 3600 seconds
**Applies to**: Learning analytics, progress tracking, and reporting

**Included Endpoints**:
- `/api/v1/analytics/student/{student_id}/progress` - Student progress
- `/api/v1/analytics/student/{student_id}/insights` - Learning insights
- `/api/v1/analytics/cohort/analyze` - Cohort analytics
- `/api/v1/analytics/institutional/report` - Institutional reports
- Advanced analytics and reporting endpoints

## Rate Limiting Implementation

### Algorithm: Sliding Window

The API uses a sliding window approach for accurate rate limiting:

```python
class SlidingWindowRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.window_size = 3600  # 1 hour in seconds

    async def is_allowed(self, user_id: int, endpoint_type: str) -> tuple[bool, dict]:
        current_time = time.time()
        window_start = current_time - self.window_size

        # Redis key for user's requests
        key = f"rate_limit:{user_id}:{endpoint_type}"

        # Remove old requests outside the window
        await self.redis.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        current_count = await self.redis.zcard(key)

        # Get rate limit for endpoint type
        limit = self.get_limit_for_endpoint(endpoint_type)

        if current_count < limit:
            # Add current request timestamp
            await self.redis.zadd(key, {str(current_time): current_time})
            await self.redis.expire(key, self.window_size)

            remaining = limit - current_count - 1
            return True, {
                "limit": limit,
                "remaining": remaining,
                "reset": int(current_time + self.window_size),
                "window": self.window_size
            }
        else:
            return False, {
                "limit": limit,
                "remaining": 0,
                "reset": int(current_time + self.window_size),
                "window": self.window_size,
                "retry_after": self.calculate_retry_after(key, window_start)
            }
```

### Endpoint Classification

Endpoints are automatically classified based on URL patterns:

```python
def classify_endpoint(request_path: str) -> str:
    """Classify endpoint for rate limiting"""

    # Content generation endpoints
    content_generation_patterns = [
        r'/nclex/generate',
        r'/study-guide/create',
        r'/clinical-support/generate'
    ]

    # Assessment endpoints
    assessment_patterns = [
        r'/assessment/competency',
        r'/assessment/gaps/analyze',
        r'/assessment/learning-path/generate'
    ]

    # Analytics endpoints
    analytics_patterns = [
        r'/analytics/student/.*/progress',
        r'/analytics/student/.*/insights',
        r'/analytics/cohort/analyze',
        r'/analytics/institutional/report'
    ]

    for pattern in content_generation_patterns:
        if re.search(pattern, request_path):
            return "content_generation"

    for pattern in assessment_patterns:
        if re.search(pattern, request_path):
            return "assessment"

    for pattern in analytics_patterns:
        if re.search(pattern, request_path):
            return "analytics"

    return "default"  # General API tier
```

## Rate Limit Response Format

### Successful Request

When within rate limits, responses include informational headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1692873600
X-Process-Time: 0.125

{
  "data": {
    // API response data
  }
}
```

### Rate Limit Exceeded

When rate limits are exceeded, a `429 Too Many Requests` response is returned:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1692873600
Retry-After: 1800

{
  "error": true,
  "error_code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded for content_generation. Please try again later.",
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123",
  "details": {
    "endpoint_type": "content_generation",
    "retry_after_seconds": 1800,
    "current_limit": 50,
    "window_seconds": 3600
  }
}
```

## Best Practices

### 1. Monitor Rate Limit Headers

Always check rate limit headers in your client applications:

```python
import time
from bsn_knowledge_sdk import BSNKnowledgeClient

class RateLimitAwareClient:
    def __init__(self):
        self.client = BSNKnowledgeClient()
        self.rate_limits = {}

    async def make_request(self, endpoint_func, *args, **kwargs):
        # Check if we should throttle based on previous responses
        if self._should_wait():
            await asyncio.sleep(self._calculate_wait_time())

        try:
            response = await endpoint_func(*args, **kwargs)
            self._update_rate_limit_info(response.headers)
            return response

        except RateLimitExceededError as e:
            retry_after = e.retry_after_seconds
            await asyncio.sleep(retry_after)
            return await endpoint_func(*args, **kwargs)  # Retry once

    def _update_rate_limit_info(self, headers):
        self.rate_limits = {
            'limit': int(headers.get('X-RateLimit-Limit', 0)),
            'remaining': int(headers.get('X-RateLimit-Remaining', 0)),
            'reset': int(headers.get('X-RateLimit-Reset', 0)),
            'last_updated': time.time()
        }

    def _should_wait(self):
        if not self.rate_limits:
            return False

        remaining = self.rate_limits.get('remaining', float('inf'))
        return remaining < 5  # Conservative threshold
```

### 2. Implement Exponential Backoff

For robust error handling, implement exponential backoff with jitter:

```python
import random
import asyncio

async def exponential_backoff_retry(func, max_retries=3, base_delay=1):
    """Retry function with exponential backoff"""

    for attempt in range(max_retries + 1):
        try:
            return await func()

        except RateLimitExceededError as e:
            if attempt == max_retries:
                raise  # Final attempt failed

            # Calculate backoff delay with jitter
            delay = min(
                e.retry_after_seconds,  # Respect server's retry-after
                base_delay * (2 ** attempt) + random.uniform(0, 1)
            )

            await asyncio.sleep(delay)

        except Exception:
            # Don't retry non-rate-limit errors
            raise

# Usage
result = await exponential_backoff_retry(
    lambda: client.nclex.generate(topic="Cardiology", question_count=5)
)
```

### 3. Batch Operations

Use batch operations to maximize efficiency within rate limits:

```python
# Instead of multiple individual requests (inefficient)
questions = []
for topic in topics:
    response = await client.nclex.generate(topic=topic, question_count=5)
    questions.extend(response.questions)

# Use efficient batching (recommended)
batch_request = {
    "batch_requests": [
        {"topic": topic, "question_count": 5}
        for topic in topics
    ]
}
batch_response = await client.nclex.generate_batch(batch_request)
```

### 4. Cache Responses

Implement client-side caching to reduce API calls:

```python
from functools import wraps
import hashlib
import json

def cache_response(ttl_seconds=300):
    """Cache decorator with TTL"""
    cache = {}

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Create cache key from function args
            cache_key = hashlib.md5(
                json.dumps([args, kwargs], sort_keys=True).encode()
            ).hexdigest()

            # Check cache
            if cache_key in cache:
                cached_result, timestamp = cache[cache_key]
                if time.time() - timestamp < ttl_seconds:
                    return cached_result

            # Make API call and cache result
            result = await func(*args, **kwargs)
            cache[cache_key] = (result, time.time())

            return result
        return wrapper
    return decorator

# Usage
@cache_response(ttl_seconds=300)  # 5-minute cache
async def get_competencies():
    return await client.assessment.get_available_competencies()
```

### 5. Prioritize Requests

Design your application to prioritize high-value requests:

```python
class PriorityRequestManager:
    def __init__(self, client):
        self.client = client
        self.priority_queue = asyncio.PriorityQueue()

    async def schedule_request(self, priority, request_func, *args, **kwargs):
        """Schedule request with priority (lower number = higher priority)"""
        await self.priority_queue.put((priority, request_func, args, kwargs))

    async def process_requests(self):
        """Process requests in priority order"""
        while not self.priority_queue.empty():
            priority, request_func, args, kwargs = await self.priority_queue.get()

            try:
                result = await self.make_rate_limited_request(request_func, *args, **kwargs)
                # Handle successful result

            except RateLimitExceededError:
                # Re-queue with same priority
                await self.priority_queue.put((priority, request_func, args, kwargs))
                await asyncio.sleep(60)  # Wait before retrying

# Usage
manager = PriorityRequestManager(client)

# High priority: Student assessment due today
await manager.schedule_request(1, client.assessment.assess_competency, student_id="urgent_001")

# Medium priority: Generate study materials
await manager.schedule_request(5, client.study_guides.create, topic="Cardiology")

# Low priority: Analytics reports
await manager.schedule_request(10, client.analytics.generate_report, type="monthly")
```

## Rate Limit Monitoring

### Dashboard Metrics

The API provides rate limiting metrics through the metrics endpoint:

```http
GET /metrics
```

**Response includes**:
```json
{
  "rate_limiting": {
    "total_requests_blocked": 1247,
    "blocked_by_tier": {
      "content_generation": 892,
      "assessment": 201,
      "analytics": 154
    },
    "average_retry_after_seconds": 1342,
    "most_limited_users": [
      {"user_id": 12345, "blocks_last_24h": 23},
      {"user_id": 67890, "blocks_last_24h": 18}
    ]
  }
}
```

### Alerting Thresholds

Monitor these metrics for rate limiting issues:

- **Block Rate**: >5% of requests blocked indicates potential issues
- **Retry Success Rate**: <80% retry success suggests inadequate backoff
- **User Concentration**: Few users consuming most rate limit quota
- **Endpoint Hotspots**: Specific endpoints with high block rates

## Rate Limit Exceptions

### Exempt Endpoints

Some endpoints are exempt from rate limiting:

- `/health` - Health checks
- `/metrics` - System metrics
- `/docs` and `/redoc` - API documentation
- `/openapi.json` - OpenAPI specification
- Authentication endpoints during emergency access

### Administrative Override

System administrators can temporarily adjust rate limits:

```python
# Emergency rate limit adjustment (admin only)
PUT /api/v1/admin/rate-limits/{user_id}
{
  "tier_overrides": {
    "content_generation": 100,  # Temporary increase
    "assessment": 400,
    "analytics": 1000
  },
  "expires_at": "2024-08-24T18:00:00Z",
  "reason": "Emergency assessment deadline"
}
```

## Troubleshooting Rate Limits

### Common Issues

**1. Unexpected Rate Limiting**
```bash
# Check your current rate limit status
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -v  # Verbose output shows rate limit headers
```

**2. Calculate Time to Reset**
```python
import time

def time_until_reset(reset_timestamp):
    """Calculate seconds until rate limit resets"""
    current_time = time.time()
    if reset_timestamp > current_time:
        return int(reset_timestamp - current_time)
    return 0

# Usage
reset_time = 1692873600  # From X-RateLimit-Reset header
wait_seconds = time_until_reset(reset_time)
print(f"Rate limit resets in {wait_seconds} seconds")
```

**3. Optimize Request Patterns**
```python
# Inefficient: Multiple small requests
for student_id in student_ids:
    progress = await client.analytics.get_student_progress(student_id)

# Efficient: Use batch endpoints when available
progress_data = await client.analytics.get_batch_student_progress(student_ids)
```

### Debug Rate Limiting

Enable detailed rate limiting logs in development:

```python
import logging

# Configure rate limiting debug logs
logging.getLogger('bsn_knowledge_sdk.rate_limiting').setLevel(logging.DEBUG)

# This will show detailed rate limiting decisions
client = BSNKnowledgeClient(debug_rate_limiting=True)
```

---

**Related Documentation:**
- [Authentication Guide](authentication.md) - User authentication for rate limiting
- [Error Handling](error-handling.md) - Handling rate limit errors
- [Best Practices](../developer-guide/best-practices.md) - Client implementation patterns
