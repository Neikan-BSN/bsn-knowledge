"""
Authentication and authorization middleware for BSN Knowledge API.
Implements JWT-based authentication with role-based access control.
"""

import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from functools import wraps

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
security = HTTPBearer(auto_error=False)


class UserRole:
    """Available user roles for BSN Knowledge system"""

    STUDENT = "student"
    INSTRUCTOR = "instructor"
    ADMIN = "admin"


class TokenData(BaseModel):
    """JWT Token payload data"""

    username: str | None = None
    user_id: int | None = None
    role: str | None = None
    scopes: list[str] = Field(default_factory=list)


class User(BaseModel):
    """User model for authentication"""

    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UserInDB(User):
    """User model with hashed password for database storage"""

    hashed_password: str


class Token(BaseModel):
    """Token response model"""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginRequest(BaseModel):
    """Login request model"""

    username: str
    password: str


# Mock user database - In production, replace with actual database
fake_users_db = {
    "student1": UserInDB(
        id=1,
        username="student1",
        email="student1@nursing.edu",
        role=UserRole.STUDENT,
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password123"  # noqa: S106
        is_active=True,
    ),
    "instructor1": UserInDB(
        id=2,
        username="instructor1",
        email="instructor1@nursing.edu",
        role=UserRole.INSTRUCTOR,
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password123"  # noqa: S106
        is_active=True,
    ),
    "admin1": UserInDB(
        id=3,
        username="admin1",
        email="admin1@nursing.edu",
        role=UserRole.ADMIN,
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "password123"  # noqa: S106
        is_active=True,
    ),
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def get_user(username: str) -> UserInDB | None:
    """Get user from database"""
    return fake_users_db.get(username)


def authenticate_user(username: str, password: str) -> UserInDB | None:
    """Authenticate user credentials"""
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": datetime.now(UTC), "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "iat": datetime.now(UTC), "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> TokenData:
    """Verify and decode JWT token"""
    try:
        from .api.error_handlers import AuthenticationError

        credentials_exception = AuthenticationError("Could not validate credentials")
    except ImportError:
        # Fallback for cases where error handlers aren't available
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        role: str = payload.get("role")
        scopes: list = payload.get("scopes", [])
        token_type_payload: str = payload.get("type")

        if username is None or token_type_payload != token_type:
            raise credentials_exception

        token_data = TokenData(
            username=username, user_id=user_id, role=role, scopes=scopes
        )
        return token_data
    except jwt.PyJWTError as e:
        raise credentials_exception from e


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> User:
    """Get current authenticated user"""
    if not credentials:
        try:
            from .api.error_handlers import AuthenticationError

            raise AuthenticationError("Authentication required")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    token_data = verify_token(credentials.credentials)
    user = get_user(username=token_data.username)
    if user is None:
        try:
            from .api.error_handlers import AuthenticationError

            raise AuthenticationError("User not found")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    if not user.is_active:
        try:
            from .api.error_handlers import AuthenticationError

            raise AuthenticationError("User account is inactive")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
            ) from e

    # Convert UserInDB to User (remove hashed_password)
    return User(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )


def require_role(required_role: str):
    """Decorator to require specific user role"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependency injection
            request = kwargs.get("request")
            if request:
                user = await get_current_user(
                    credentials=security(request)
                    if hasattr(request, "headers")
                    else None
                )
                if user.role != required_role and user.role != UserRole.ADMIN:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions. Required role: {required_role}",
                    )
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_any_role(required_roles: list[str]):
    """Decorator to require any of the specified roles"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request")
            if request:
                user = await get_current_user(
                    credentials=security(request)
                    if hasattr(request, "headers")
                    else None
                )
                if user.role not in required_roles and user.role != UserRole.ADMIN:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Insufficient permissions. Required roles: {', '.join(required_roles)}",
                    )
            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Dependency aliases for common role requirements
async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_current_student(current_user: User = Depends(get_current_user)) -> User:
    """Get current user with student role or higher"""
    if current_user.role not in [UserRole.STUDENT, UserRole.INSTRUCTOR, UserRole.ADMIN]:
        try:
            from .api.error_handlers import AuthorizationError

            raise AuthorizationError("Student access required")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Student access required"
            ) from e
    return current_user


async def get_current_instructor(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current user with instructor role or higher"""
    if current_user.role not in [UserRole.INSTRUCTOR, UserRole.ADMIN]:
        try:
            from .api.error_handlers import AuthorizationError

            raise AuthorizationError("Instructor access required")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Instructor access required",
            ) from e
    return current_user


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Get current user with admin role"""
    if current_user.role != UserRole.ADMIN:
        try:
            from .api.error_handlers import AuthorizationError

            raise AuthorizationError("Administrator access required")
        except ImportError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator access required",
            ) from e
    return current_user


class RateLimiter:
    """Simple in-memory rate limiter"""

    def __init__(self):
        self.requests = {}  # {user_id: [(timestamp, endpoint), ...]}
        self.limits = {
            "default": (1000, 3600),  # 1000 requests per hour
            "content_generation": (50, 3600),  # 50 AI generations per hour
            "assessment": (200, 3600),  # 200 assessments per hour
            "analytics": (500, 3600),  # 500 analytics requests per hour
        }

    def _clean_old_requests(self, user_id: int, window: int):
        """Remove requests older than the time window"""
        if user_id not in self.requests:
            self.requests[user_id] = []

        current_time = time.time()
        self.requests[user_id] = [
            (timestamp, endpoint)
            for timestamp, endpoint in self.requests[user_id]
            if current_time - timestamp < window
        ]

    def is_allowed(
        self, user_id: int, endpoint_type: str = "default"
    ) -> tuple[bool, dict]:
        """Check if request is allowed and return rate limit info"""
        limit, window = self.limits.get(endpoint_type, self.limits["default"])

        self._clean_old_requests(user_id, window)

        current_requests = len(
            [
                req
                for req in self.requests[user_id]
                if req[1] == endpoint_type or endpoint_type == "default"
            ]
        )

        allowed = current_requests < limit

        if allowed:
            self.requests[user_id].append((time.time(), endpoint_type))

        rate_limit_info = {
            "limit": limit,
            "remaining": max(0, limit - current_requests - (1 if allowed else 0)),
            "reset": int(time.time() + window),
            "window": window,
        }

        return allowed, rate_limit_info


# Global rate limiter instance
rate_limiter = RateLimiter()


def get_endpoint_type(path: str) -> str:
    """Determine endpoint type for rate limiting"""
    if "/nclex/" in path or "/study-guide/" in path or "/clinical-support/" in path:
        return "content_generation"
    elif "/assessment/" in path:
        return "assessment"
    elif "/analytics/" in path:
        return "analytics"
    else:
        return "default"


async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    # Skip rate limiting for authentication endpoints
    if request.url.path in [
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/health",
        "/docs",
        "/openapi.json",
    ]:
        response = await call_next(request)
        return response

    # Get current user for rate limiting (if authenticated)
    user_id = None
    try:
        credentials = await security(request)
        if credentials:
            token_data = verify_token(credentials.credentials)
            user_id = token_data.user_id or hash(token_data.username)
    except:
        # If not authenticated, use IP-based rate limiting
        user_id = hash(request.client.host) if request.client else 0

    endpoint_type = get_endpoint_type(request.url.path)
    allowed, rate_info = rate_limiter.is_allowed(user_id, endpoint_type)

    if not allowed:
        from .api.error_handlers import RateLimitExceededError

        raise RateLimitExceededError(
            retry_after=rate_info["window"], endpoint_type=endpoint_type
        )

    response = await call_next(request)

    # Add rate limit headers to response
    response.headers["X-RateLimit-Limit"] = str(rate_info["limit"])
    response.headers["X-RateLimit-Remaining"] = str(rate_info["remaining"])
    response.headers["X-RateLimit-Reset"] = str(rate_info["reset"])

    return response


def create_auth_tokens(user: UserInDB) -> Token:
    """Create access and refresh tokens for user"""
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "scopes": [],  # Can be extended for fine-grained permissions
    }

    access_token = create_access_token(
        data=token_data, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(
        data=token_data, expires_delta=refresh_token_expires
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
