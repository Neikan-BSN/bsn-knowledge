"""
Comprehensive error handling and validation utilities for BSN Knowledge API
"""

import logging
from datetime import datetime
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception for API errors"""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code: str = "INTERNAL_ERROR",
        details: dict[str, Any] | None = None,
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)


class ValidationError(APIError):
    """Validation error exception"""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="VALIDATION_ERROR",
            details=details,
        )


class AuthenticationError(APIError):
    """Authentication error exception"""

    def __init__(self, message: str = "Authentication required"):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="AUTHENTICATION_ERROR",
        )


class AuthorizationError(APIError):
    """Authorization error exception"""

    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AUTHORIZATION_ERROR",
        )


class ResourceNotFoundError(APIError):
    """Resource not found error exception"""

    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            message=f"{resource_type} with ID '{resource_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND",
            details={"resource_type": resource_type, "resource_id": resource_id},
        )


class BusinessLogicError(APIError):
    """Business logic error exception"""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="BUSINESS_LOGIC_ERROR",
            details=details,
        )


class ExternalServiceError(APIError):
    """External service error exception"""

    def __init__(
        self, service_name: str, message: str = "External service unavailable"
    ):
        super().__init__(
            message=f"{service_name}: {message}",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code="EXTERNAL_SERVICE_ERROR",
            details={"service": service_name},
        )


def create_error_response(
    error: APIError, request: Request, include_traceback: bool = False
) -> JSONResponse:
    """Create standardized error response"""

    # Generate request ID for tracking
    request_id = str(id(request))

    # Base error response
    error_response = {
        "error": True,
        "error_code": error.error_code,
        "message": error.message,
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id,
        "path": str(request.url.path),
    }

    # Add details if available
    if error.details:
        error_response["details"] = error.details

    # Log the error
    log_error(error, request, request_id)

    return JSONResponse(
        status_code=error.status_code,
        content=error_response,
        headers={"X-Request-ID": request_id},
    )


def log_error(error: APIError, request: Request, request_id: str):
    """Log error with appropriate level"""

    error_context = {
        "request_id": request_id,
        "path": request.url.path,
        "method": request.method,
        "error_code": error.error_code,
        "status_code": error.status_code,
    }

    if error.status_code >= 500:
        logger.error(f"Server error: {error.message}", extra=error_context)
    elif error.status_code >= 400:
        logger.warning(f"Client error: {error.message}", extra=error_context)
    else:
        logger.info(f"Error: {error.message}", extra=error_context)


def validation_error_handler(
    request: Request, exc: PydanticValidationError
) -> JSONResponse:
    """Handle Pydantic validation errors"""

    validation_details = []
    for error in exc.errors():
        validation_details.append(
            {
                "field": " -> ".join(str(x) for x in error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            }
        )

    api_error = ValidationError(
        message="Request validation failed",
        details={"validation_errors": validation_details},
    )

    return create_error_response(api_error, request)


def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle FastAPI HTTP exceptions"""

    # Map HTTPException to APIError
    error_code_map = {
        400: "BAD_REQUEST",
        401: "AUTHENTICATION_ERROR",
        403: "AUTHORIZATION_ERROR",
        404: "RESOURCE_NOT_FOUND",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }

    error_code = error_code_map.get(exc.status_code, "HTTP_ERROR")

    api_error = APIError(
        message=exc.detail, status_code=exc.status_code, error_code=error_code
    )

    return create_error_response(api_error, request)


def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions"""

    # Log the full exception
    logger.exception(f"Unexpected error in {request.method} {request.url.path}")

    api_error = APIError(
        message="An unexpected error occurred. Please try again later.",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_code="INTERNAL_ERROR",
    )

    return create_error_response(api_error, request)


# Input validation utilities
def validate_student_id(student_id: str) -> str:
    """Validate student ID format"""
    if not student_id or not isinstance(student_id, str):
        raise ValidationError("Student ID is required and must be a string")

    if len(student_id.strip()) < 3:
        raise ValidationError("Student ID must be at least 3 characters long")

    return student_id.strip()


def validate_competency_id(competency_id: str) -> str:
    """Validate competency ID format"""
    if not competency_id or not isinstance(competency_id, str):
        raise ValidationError("Competency ID is required and must be a string")

    if len(competency_id.strip()) < 2:
        raise ValidationError("Competency ID must be at least 2 characters long")

    return competency_id.strip()


def validate_pagination_params(skip: int = 0, limit: int = 100) -> tuple[int, int]:
    """Validate pagination parameters"""
    if skip < 0:
        raise ValidationError("Skip parameter must be non-negative")

    if limit <= 0 or limit > 1000:
        raise ValidationError("Limit parameter must be between 1 and 1000")

    return skip, limit


def validate_json_data(
    data: dict[str, Any], required_fields: list[str]
) -> dict[str, Any]:
    """Validate JSON data has required fields"""
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")

    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing_fields)}",
            details={"missing_fields": missing_fields},
        )

    return data


# Rate limiting error handling
class RateLimitExceededError(APIError):
    """Rate limit exceeded error exception"""

    def __init__(self, retry_after: int, endpoint_type: str = "default"):
        super().__init__(
            message=f"Rate limit exceeded for {endpoint_type}. Please try again later.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_EXCEEDED",
            details={
                "endpoint_type": endpoint_type,
                "retry_after_seconds": retry_after,
            },
        )


# Content generation error handling
class ContentGenerationError(APIError):
    """Content generation error exception"""

    def __init__(self, content_type: str, reason: str):
        super().__init__(
            message=f"Failed to generate {content_type}: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="CONTENT_GENERATION_ERROR",
            details={"content_type": content_type, "reason": reason},
        )


# Assessment error handling
class AssessmentError(APIError):
    """Assessment error exception"""

    def __init__(self, assessment_type: str, reason: str):
        super().__init__(
            message=f"Assessment failed for {assessment_type}: {reason}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="ASSESSMENT_ERROR",
            details={"assessment_type": assessment_type, "reason": reason},
        )
