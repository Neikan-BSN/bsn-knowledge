# API Overview

Welcome to the BSN Knowledge API, a comprehensive platform designed specifically for nursing education. This RESTful API provides access to advanced educational tools including AI-powered content generation, competency assessment, and learning analytics.

## Base URL

```
https://api.bsn-knowledge.edu
```

**Development Environment:**
```
https://dev-api.bsn-knowledge.edu
```

## API Versioning

The API uses URL path versioning. The current version is `v1`, and all endpoints are prefixed with `/api/v1`.

```http
GET /api/v1/auth/me
```

### Version Support Policy

- **Current Version**: v1 (fully supported)
- **Deprecation Notice**: 6 months before version sunset
- **Breaking Changes**: Only introduced in new major versions

## Core Concepts

### 🎓 Educational Framework
The BSN Knowledge API is built around the **AACN Essentials Framework**, providing structured competency assessment and learning path optimization.

**Eight AACN Domains:**
1. Knowledge for Nursing Practice
2. Person-Centered Care
3. Population Health
4. Scholarship for Nursing Discipline
5. Information Technology
6. Healthcare Systems
7. Interprofessional Partnerships
8. Personal Professional Development

### 🔐 Role-Based Access Control

The API supports three primary user roles:

| Role | Description | Access Level |
|------|-------------|--------------|
| **Student** | Nursing students and learners | Course content, assessments, progress tracking |
| **Instructor** | Faculty and teaching staff | Course management, student analytics, content creation |
| **Admin** | System administrators | Full system access, user management, institutional reporting |

### 🎯 Content Generation

The API integrates with **RAGnostic AI** for intelligent content generation:

- **NCLEX-style questions** with evidence-based rationales
- **Personalized study guides** aligned with competency gaps
- **Clinical scenarios** for hands-on learning
- **Assessment tools** with automatic grading and feedback

## API Architecture

### RESTful Design Principles

The API follows REST architectural constraints:

- **Stateless**: Each request contains all necessary information
- **Resource-based URLs**: Endpoints represent resources, not actions
- **HTTP Methods**: Proper use of GET, POST, PUT, DELETE
- **Standard Status Codes**: Meaningful HTTP response codes

### Response Format

All API responses use JSON format with consistent structure:

```json
{
  "data": {
    "id": "12345",
    "type": "resource_type",
    "attributes": {
      // Resource-specific data
    }
  },
  "meta": {
    "timestamp": "2024-08-24T10:00:00Z",
    "request_id": "req_abc123"
  }
}
```

### Error Response Format

Errors follow a standardized format for consistent handling:

```json
{
  "error": true,
  "error_code": "VALIDATION_ERROR",
  "message": "Request validation failed",
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123",
  "path": "/api/v1/endpoint",
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

## Request/Response Headers

### Standard Headers

**Request Headers:**
```http
Content-Type: application/json
Authorization: Bearer <jwt_token>
Accept: application/json
User-Agent: YourApp/1.0.0
```

**Response Headers:**
```http
Content-Type: application/json
X-Process-Time: 0.145
X-Request-ID: req_abc123
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1692873600
```

### Performance Headers

Monitor API performance with included headers:

- `X-Process-Time`: Request processing time in seconds
- `X-Request-ID`: Unique identifier for request tracking
- `X-Cache-Status`: Cache hit/miss information

## Data Types

### Common Data Formats

| Type | Format | Example |
|------|--------|---------|
| **Date/Time** | ISO 8601 UTC | `2024-08-24T10:00:00Z` |
| **UUID** | UUID v4 | `550e8400-e29b-41d4-a716-446655440000` |
| **Student ID** | String | `student_12345` |
| **Competency ID** | String | `aacn_domain_1_comp_3` |

### Proficiency Levels

Competency assessments use standardized proficiency levels:

```json
{
  "proficiency_levels": [
    "novice",
    "advanced_beginner",
    "competent",
    "proficient",
    "expert"
  ]
}
```

## Pagination

List endpoints support cursor-based pagination for efficient data retrieval:

### Request Parameters

```http
GET /api/v1/students?limit=20&skip=0
```

- `limit`: Number of records to return (default: 100, max: 1000)
- `skip`: Number of records to skip (default: 0)

### Response Format

```json
{
  "data": [
    // Array of resources
  ],
  "pagination": {
    "total": 2500,
    "limit": 20,
    "skip": 0,
    "has_more": true
  }
}
```

## Filtering and Sorting

### Query Parameters

Most list endpoints support filtering and sorting:

```http
GET /api/v1/assessments?competency_domain=person_centered_care&sort=created_at&order=desc
```

**Common Parameters:**
- `sort`: Field to sort by
- `order`: `asc` or `desc`
- `created_after`: Filter by creation date
- `updated_since`: Filter by modification date

### Complex Filtering

For advanced queries, use JSON-encoded filter parameters:

```http
GET /api/v1/analytics/students?filters={"program":"BSN","semester":{"gte":3}}
```

## Content Types

### Supported MIME Types

The API supports the following content types:

**Request:**
- `application/json` (default)
- `application/x-www-form-urlencoded` (OAuth2 endpoints)
- `multipart/form-data` (file uploads)

**Response:**
- `application/json` (default)
- `text/csv` (data exports)
- `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` (Excel exports)

## Compression

The API supports Gzip compression for responses larger than 1KB. Include the `Accept-Encoding` header:

```http
Accept-Encoding: gzip, deflate
```

## CORS Support

Cross-Origin Resource Sharing (CORS) is enabled for web applications:

**Allowed Origins:** Configurable (production environments use specific domains)
**Allowed Methods:** GET, POST, PUT, DELETE, OPTIONS
**Allowed Headers:** Authorization, Content-Type, Accept

## Health and Status

### Health Check Endpoint

Monitor API health and status:

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": 1692873600.123,
  "version": "1.0.0",
  "performance_metrics": {
    "total_requests": 125000,
    "average_response_time": 0.145,
    "error_rate_percentage": 0.02
  },
  "features_status": {
    "authentication": "operational",
    "rate_limiting": "active",
    "ragnostic_integration": "operational"
  }
}
```

### Metrics Endpoint

Get detailed performance metrics:

```http
GET /metrics
```

## Getting Started

### 1. Authentication

Obtain access tokens through the authentication endpoint:

```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

### 2. Test API Access

Verify your authentication:

```bash
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 3. Explore Endpoints

Use the interactive documentation:

- **Swagger UI**: [https://api.bsn-knowledge.edu/docs](https://api.bsn-knowledge.edu/docs)
- **ReDoc**: [https://api.bsn-knowledge.edu/redoc](https://api.bsn-knowledge.edu/redoc)

## SDK and Libraries

### Official SDKs

We provide official SDKs for popular programming languages:

- **Python**: `pip install bsn-knowledge-sdk`
- **JavaScript/Node.js**: `npm install bsn-knowledge-sdk`
- **Java**: Available via Maven Central
- **C#/.NET**: Available via NuGet

### Community Libraries

Third-party libraries maintained by the community:

- **Ruby**: `gem install bsn-knowledge-ruby`
- **PHP**: Available via Composer
- **Go**: Available via Go modules

## API Limits and Quotas

### Rate Limiting

Rate limits are enforced per user account:

| Endpoint Type | Limit | Window |
|---------------|-------|---------|
| Authentication | No limit | - |
| General API | 1,000 requests | 1 hour |
| Content Generation | 50 requests | 1 hour |
| Assessment | 200 requests | 1 hour |
| Analytics | 500 requests | 1 hour |

### Data Limits

- **Request Size**: Maximum 10MB
- **Response Size**: Maximum 50MB
- **File Upload**: Maximum 100MB per file
- **Batch Operations**: Maximum 1,000 items per request

## Support and Resources

### Technical Support

- **Email**: api-support@bsn-knowledge.edu
- **Response Time**: 24 hours for standard inquiries
- **Priority Support**: Available for enterprise customers

### Additional Resources

- [Authentication Guide](authentication.md)
- [Rate Limiting Guide](rate-limiting.md)
- [Error Handling Guide](error-handling.md)
- [Developer Best Practices](../developer-guide/best-practices.md)

---

**Next Steps:**
- [Set up authentication](authentication.md)
- [Explore API endpoints](endpoints/)
- [Review rate limiting policies](rate-limiting.md)
