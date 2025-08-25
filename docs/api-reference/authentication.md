# Authentication Guide

The BSN Knowledge API uses **JWT (JSON Web Token)** authentication with role-based access control. This guide covers authentication flows, token management, and security best practices.

## Authentication Overview

### Token-Based Authentication

The API uses stateless JWT tokens for authentication:

- **Access Tokens**: Short-lived tokens (30 minutes) for API requests
- **Refresh Tokens**: Long-lived tokens (7 days) for obtaining new access tokens
- **Bearer Token Format**: Include in the `Authorization` header

### User Roles

Three primary roles with hierarchical permissions:

| Role | Description | Typical Use Cases |
|------|-------------|-------------------|
| **Student** | Nursing students and learners | Access course content, take assessments, view progress |
| **Instructor** | Faculty and teaching staff | Manage courses, view student analytics, create content |
| **Admin** | System administrators | User management, institutional reports, system configuration |

## Authentication Endpoints

### Login

Authenticate with username and password to receive JWT tokens.

```http
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "username": "student1",
  "password": "password123"
}
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

**cURL Example:**
```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "student1",
    "password": "password123"
  }'
```

### OAuth2 Compatible Login

OAuth2 password flow compatible endpoint for automatic API documentation.

```http
POST /api/v1/auth/login/oauth2
```

**Request (Form Data):**
```http
Content-Type: application/x-www-form-urlencoded

username=student1&password=password123&scope=
```

**Response:** Same as standard login endpoint

### Token Refresh

Exchange a valid refresh token for new access and refresh tokens.

```http
POST /api/v1/auth/refresh
```

**Request Body:**
```json
{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Response:** Same format as login response

**cURL Example:**
```bash
curl -X POST https://api.bsn-knowledge.edu/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

### User Information

Get current authenticated user details.

```http
GET /api/v1/auth/me
```

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
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

### Logout

Invalidate current session (client-side token removal).

```http
POST /api/v1/auth/logout
```

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "User student1 logged out successfully",
  "username": "student1"
}
```

### Token Verification

Verify if a token is valid and get token information.

```http
GET /api/v1/auth/verify-token
```

**Headers:**
```http
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "valid": true,
  "user": {
    "id": 1,
    "username": "student1",
    "role": "student"
  },
  "message": "Token is valid"
}
```

## Authentication Flows

### Standard Login Flow

1. **Login Request**: Client sends credentials to `/api/v1/auth/login`
2. **Token Response**: Server returns access and refresh tokens
3. **API Requests**: Client includes access token in Authorization header
4. **Token Refresh**: Client uses refresh token to get new access token before expiration

```mermaid
sequenceDiagram
    participant Client
    participant API

    Client->>API: POST /auth/login (credentials)
    API->>Client: Access & Refresh tokens

    loop API Requests
        Client->>API: Request with Authorization header
        API->>Client: Protected resource response
    end

    Client->>API: POST /auth/refresh (refresh token)
    API->>Client: New access & refresh tokens
```

### Token Refresh Flow

```javascript
// Automatic token refresh example
class BSNKnowledgeClient {
  async makeRequest(endpoint, options = {}) {
    // Add auth header
    options.headers = {
      ...options.headers,
      'Authorization': `Bearer ${this.accessToken}`
    };

    let response = await fetch(endpoint, options);

    // If token expired, refresh and retry
    if (response.status === 401) {
      await this.refreshToken();
      options.headers['Authorization'] = `Bearer ${this.accessToken}`;
      response = await fetch(endpoint, options);
    }

    return response;
  }

  async refreshToken() {
    const response = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
  }
}
```

## Token Structure

### JWT Token Claims

BSN Knowledge JWT tokens contain the following claims:

```json
{
  "sub": "student1",           // Username (subject)
  "user_id": 1,               // Numeric user ID
  "role": "student",          // User role
  "scopes": [],               // Permission scopes (future use)
  "iat": 1692873600,          // Issued at timestamp
  "exp": 1692875400,          // Expiration timestamp
  "type": "access"            // Token type (access/refresh)
}
```

### Token Validation

Tokens are validated using:
- **Signature Verification**: HMAC SHA-256 with secret key
- **Expiration Check**: Tokens expire after designated time
- **Type Verification**: Access vs. refresh token validation
- **User Status**: Active user account validation

## Using Authentication

### Including Bearer Tokens

Add the Authorization header to all authenticated requests:

```http
GET /api/v1/students/12345/progress
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### SDK Authentication Examples

#### Python
```python
import requests
from bsn_knowledge_sdk import BSNKnowledgeClient

# Manual authentication
response = requests.post('https://api.bsn-knowledge.edu/api/v1/auth/login',
    json={'username': 'student1', 'password': 'password123'})
tokens = response.json()

# Using SDK (recommended)
client = BSNKnowledgeClient()
client.login('student1', 'password123')
user_info = client.get_user_info()
```

#### JavaScript/Node.js
```javascript
const axios = require('axios');

// Login and get tokens
const loginResponse = await axios.post('https://api.bsn-knowledge.edu/api/v1/auth/login', {
  username: 'student1',
  password: 'password123'
});

const { access_token } = loginResponse.data;

// Make authenticated requests
const userResponse = await axios.get('https://api.bsn-knowledge.edu/api/v1/auth/me', {
  headers: { Authorization: `Bearer ${access_token}` }
});
```

#### cURL
```bash
# Login
LOGIN_RESPONSE=$(curl -s -X POST https://api.bsn-knowledge.edu/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "student1", "password": "password123"}')

# Extract token
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')

# Make authenticated request
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Role-Based Access Control

### Permission Hierarchy

Roles have hierarchical permissions where higher roles inherit lower role permissions:

```
Admin (Full Access)
  ↑
Instructor (Course Management + Student Access)
  ↑
Student (Basic Learning Features)
```

### Endpoint Access Levels

| Endpoint Pattern | Student | Instructor | Admin |
|------------------|---------|------------|-------|
| `/auth/*` | ✅ | ✅ | ✅ |
| `/nclex/generate` | ✅ | ✅ | ✅ |
| `/assessment/competency` | ✅ | ✅ | ✅ |
| `/study-guide/create` | ✅ | ✅ | ✅ |
| `/analytics/student/{own_id}` | ✅ | - | - |
| `/analytics/student/{any_id}` | - | ✅ | ✅ |
| `/analytics/institutional/*` | - | - | ✅ |
| `/auth/users` | - | - | ✅ |

### Role Validation

The API automatically validates user roles for protected endpoints:

```python
# Endpoint requiring instructor access
@router.get("/analytics/cohort/{cohort_id}")
async def get_cohort_analytics(
    cohort_id: str,
    current_user: User = Depends(get_current_instructor)  # Role validation
):
    # Only instructors and admins can access
    pass
```

## Security Best Practices

### Token Security

1. **Secure Storage**: Store tokens securely (never in localStorage for web apps)
2. **HTTPS Only**: Always use HTTPS for authentication requests
3. **Token Expiration**: Respect token expiration times
4. **Refresh Strategy**: Implement automatic token refresh

### Client Implementation

```javascript
// Secure token storage example
class SecureTokenStorage {
  // Web: Use secure cookies or sessionStorage
  storeTokens(tokens) {
    // Option 1: Secure HTTP-only cookie (preferred)
    document.cookie = `access_token=${tokens.access_token}; Secure; HttpOnly; SameSite=Strict`;

    // Option 2: SessionStorage (less secure but workable)
    sessionStorage.setItem('refresh_token', tokens.refresh_token);
  }

  // Mobile: Use secure keychain/keystore
  // Node.js: Use environment variables or secure storage
}
```

### Rate Limiting and Authentication

Authentication endpoints have specific rate limiting:

- **Login attempts**: 5 attempts per 15 minutes per IP
- **Token refresh**: 10 attempts per minute per user
- **General auth endpoints**: No specific limit (uses general API limit)

## Error Handling

### Authentication Errors

| Status Code | Error Code | Description | Resolution |
|-------------|------------|-------------|------------|
| `401` | `AUTHENTICATION_ERROR` | Invalid or missing token | Login again or refresh token |
| `401` | `TOKEN_EXPIRED` | Access token expired | Refresh token |
| `403` | `AUTHORIZATION_ERROR` | Insufficient permissions | Contact administrator |
| `429` | `RATE_LIMIT_EXCEEDED` | Too many login attempts | Wait and retry |

### Error Response Examples

```json
{
  "error": true,
  "error_code": "AUTHENTICATION_ERROR",
  "message": "Could not validate credentials",
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123"
}
```

```json
{
  "error": true,
  "error_code": "AUTHORIZATION_ERROR",
  "message": "Insufficient permissions. Required role: instructor",
  "timestamp": "2024-08-24T10:00:00Z",
  "request_id": "req_abc123"
}
```

## Testing Authentication

### Using Swagger UI

1. Navigate to [https://api.bsn-knowledge.edu/docs](https://api.bsn-knowledge.edu/docs)
2. Click the "Authorize" button
3. Enter your token in the format: `Bearer <your_jwt_token>`
4. Click "Authorize" to apply to all endpoints

### Test Accounts

Development environment provides test accounts:

```json
{
  "student_account": {
    "username": "student1",
    "password": "password123",
    "role": "student"
  },
  "instructor_account": {
    "username": "instructor1",
    "password": "password123",
    "role": "instructor"
  },
  "admin_account": {
    "username": "admin1",
    "password": "password123",
    "role": "admin"
  }
}
```

## Troubleshooting

### Common Issues

**Invalid Token Error:**
```bash
# Verify token is not expired
jwt-cli decode <your_token>

# Check token format
echo "Bearer <your_token>" | wc -c  # Should be reasonable length
```

**Permission Denied:**
```bash
# Check your user role
curl -X GET https://api.bsn-knowledge.edu/api/v1/auth/me \
  -H "Authorization: Bearer <your_token>"
```

**Token Refresh Failed:**
```bash
# Verify refresh token is still valid
# Refresh tokens expire after 7 days
# If expired, perform full login again
```

### Debug Authentication

Enable authentication debugging in your client:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('bsn_knowledge_sdk')

# Authentication debug info will be logged
client = BSNKnowledgeClient(debug=True)
client.login('student1', 'password123')
```

---

**Next Steps:**
- [Explore API endpoints](endpoints/)
- [Review rate limiting policies](rate-limiting.md)
- [Learn about error handling](error-handling.md)
