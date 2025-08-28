"""
Input validation utilities and middleware for BSN Knowledge API
"""

import re
from functools import wraps
from typing import Any

from fastapi import Request, status
from pydantic import BaseModel, Field, validator

from .error_handlers import APIError, ValidationError


class StudentIDValidation(BaseModel):
    """Student ID validation model"""

    student_id: str = Field(..., min_length=3, max_length=50, regex=r"^[a-zA-Z0-9_-]+$")

    @validator("student_id")
    def validate_student_id_format(cls, v):
        if not v or not v.strip():
            raise ValueError("Student ID cannot be empty") from e
        return v.strip()


class CompetencyIDValidation(BaseModel):
    """Competency ID validation model"""

    competency_id: str = Field(
        ..., min_length=2, max_length=100, regex=r"^[a-zA-Z0-9_.-]+$"
    )

    @validator("competency_id")
    def validate_competency_id_format(cls, v):
        if not v or not v.strip():
            raise ValueError("Competency ID cannot be empty") from e
        return v.strip()


class PaginationValidation(BaseModel):
    """Pagination parameters validation"""

    skip: int = Field(0, ge=0, le=10000)
    limit: int = Field(100, ge=1, le=1000)


class TimeRangeValidation(BaseModel):
    """Time range validation"""

    start_date: str | None = Field(None, regex=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str | None = Field(None, regex=r"^\d{4}-\d{2}-\d{2}$")

    @validator("end_date")
    def validate_date_range(cls, v, values):
        if v and "start_date" in values and values["start_date"]:
            if v < values["start_date"]:
                raise ValueError("End date must be after start date") from e
        return v


class TopicValidation(BaseModel):
    """Topic validation model"""

    topic: str = Field(..., min_length=3, max_length=200)

    @validator("topic")
    def validate_topic_content(cls, v):
        if not v or not v.strip():
            raise ValueError("Topic cannot be empty") from e

        # Check for potentially harmful content
        forbidden_patterns = [
            r"<script",
            r"javascript:",
            r"vbscript:",
            r"onload=",
            r"onerror=",
        ]

        for pattern in forbidden_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Topic contains invalid content") from e

        return v.strip()


class DifficultyValidation(BaseModel):
    """Difficulty level validation"""

    difficulty: str = Field(..., regex=r"^(beginner|intermediate|advanced)$")


class AssessmentDataValidation(BaseModel):
    """Assessment performance data validation"""

    performance_data: dict[str, Any] = Field(..., min_items=1)

    @validator("performance_data")
    def validate_performance_data_structure(cls, v):
        if not isinstance(v, dict):
            raise ValueError("Performance data must be a dictionary") from e

        # Validate basic structure
        required_keys = ["scores", "completion_time"]
        for key in required_keys:
            if key not in v:
                raise ValueError(f"Missing required key: {key}") from e

        # Validate scores
        if not isinstance(v["scores"], dict | list):
            raise ValueError("Scores must be a dictionary or list") from e

        # Validate completion time
        if (
            not isinstance(v["completion_time"], int | float)
            or v["completion_time"] < 0
        ):
            raise ValueError("Completion time must be a non-negative number") from e

        return v


class QuestionCountValidation(BaseModel):
    """Question count validation"""

    question_count: int = Field(..., ge=1, le=100)


class ContentValidation(BaseModel):
    """General content validation"""

    content: str = Field(..., min_length=10, max_length=50000)

    @validator("content")
    def validate_content_safety(cls, v):
        if not v or not v.strip():
            raise ValueError("Content cannot be empty") from e

        # Basic XSS protection
        dangerous_tags = [
            "<script",
            "</script>",
            "<iframe",
            "</iframe>",
            "<object",
            "</object>",
            "<embed",
            "</embed>",
            "javascript:",
            "vbscript:",
            "onload=",
            "onerror=",
            "onclick=",
        ]

        content_lower = v.lower()
        for tag in dangerous_tags:
            if tag in content_lower:
                raise ValueError(
                    f"Content contains potentially unsafe element: {tag}"
                ) from e

        return v.strip()


def validate_request_size(max_size_mb: float = 50):
    """Middleware to validate request size"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if request:
                content_length = request.headers.get("content-length")
                if content_length:
                    size_mb = int(content_length) / (1024 * 1024)
                    if size_mb > max_size_mb:
                        raise ValidationError(
                            f"Request size ({size_mb:.1f}MB) exceeds maximum allowed size ({max_size_mb}MB)"
                        )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_content_type(allowed_types: list[str]):
    """Middleware to validate content type"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if request and request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "").split(";")[0]
                if content_type not in allowed_types:
                    raise ValidationError(
                        f"Unsupported content type: {content_type}. Allowed types: {', '.join(allowed_types)}"
                    )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def sanitize_string_input(value: str, max_length: int = 1000) -> str:
    """Sanitize string input for safety"""
    if not value:
        return ""

    # Remove null bytes
    value = value.replace("\x00", "")

    # Limit length
    if len(value) > max_length:
        value = value[:max_length]

    # Basic HTML entity encoding for common dangerous characters
    dangerous_chars = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;",
    }

    for char, entity in dangerous_chars.items():
        value = value.replace(char, entity)

    return value.strip()


def validate_medical_terminology(text: str) -> bool:
    """Basic validation for medical terminology appropriateness"""
    # This is a simplified validation - in production, this would use
    # UMLS or other medical terminology validation services

    if not text:
        return False

    # Check for obviously inappropriate content
    inappropriate_terms = [
        "fake",
        "bogus",
        "nonsense",
        "garbage",
        "xxx",
        "adult",
        "inappropriate",
    ]

    text_lower = text.lower()
    for term in inappropriate_terms:
        if term in text_lower:
            return False

    # Basic length and character validation
    if len(text) < 3 or len(text) > 10000:
        return False

    # Check for reasonable medical/nursing content patterns
    medical_indicators = [
        "patient",
        "nursing",
        "medical",
        "treatment",
        "diagnosis",
        "care",
        "health",
        "clinical",
        "therapy",
        "medication",
        "assessment",
        "intervention",
        "outcome",
        "symptom",
    ]

    # At least one medical term should be present for medical content
    has_medical_context = any(
        indicator in text_lower for indicator in medical_indicators
    )

    return has_medical_context


class RequestValidationMiddleware:
    """Comprehensive request validation middleware"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, request: Request, call_next):
        try:
            # Validate request headers
            self._validate_headers(request)

            # Validate request size
            self._validate_request_size(request)

            # Process request
            response = await call_next(request)

            return response

        except ValidationError:
            raise
        except Exception:
            raise APIError(
                message="Request validation failed",
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
            )

    def _validate_headers(self, request: Request):
        """Validate request headers"""
        # Check for required headers on certain endpoints
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if not content_type:
                raise ValidationError(
                    "Content-Type header is required for data endpoints"
                )

    def _validate_request_size(self, request: Request, max_size_mb: float = 50):
        """Validate request size"""
        content_length = request.headers.get("content-length")
        if content_length:
            size_mb = int(content_length) / (1024 * 1024)
            if size_mb > max_size_mb:
                raise ValidationError(
                    f"Request size ({size_mb:.1f}MB) exceeds maximum allowed ({max_size_mb}MB)"
                )
