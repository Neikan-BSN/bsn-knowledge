#!/usr/bin/env python3
"""
Medical Input Validation Framework for BSN Knowledge Platform

Provides comprehensive input validation for medical education platform
with HIPAA compliance, security validation, and educational content protection.

Security Features:
- Medical data format validation
- HIPAA-compliant input sanitization
- SQL injection prevention
- XSS protection for educational content
- Medical calculation input validation
- Student data protection
"""

import html
import re
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any

from .medical_audit_logger import get_medical_audit_logger, log_security_violation


class ValidationSeverity(Enum):
    """Validation error severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationError(Exception):
    """Custom validation error for medical platform."""

    def __init__(
        self,
        message: str,
        field: str = None,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ):
        self.message = message
        self.field = field
        self.severity = severity
        super().__init__(message)


class MedicalInputValidator:
    """Comprehensive input validator for medical education platform."""

    # Regex patterns for medical data validation
    PATTERNS = {
        "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
        "student_id": re.compile(r"^[A-Z0-9]{6,12}$"),
        "medical_record_number": re.compile(r"^[A-Z0-9\-]{8,15}$"),
        "phone": re.compile(r"^\+?1?[0-9]{10,15}$"),
        "zipcode": re.compile(r"^\d{5}(-\d{4})?$"),
        "ssn_last_four": re.compile(r"^\d{4}$"),
        "date_iso": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
        "time_iso": re.compile(r"^\d{2}:\d{2}(:\d{2})?$"),
        "url": re.compile(r"^https?://[^\s/$.?#].[^\s]*$"),
        "uuid": re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
        "alphanumeric": re.compile(r"^[a-zA-Z0-9\s\-_]+$"),
        "medical_terminology": re.compile(r"^[a-zA-Z0-9\s\-_.,()\/]+$"),
    }

    # Dangerous patterns for security
    DANGEROUS_PATTERNS = {
        "sql_injection": re.compile(
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b|[\'";])',
            re.IGNORECASE,
        ),
        "xss": re.compile(
            r"<\s*script[^>]*>|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed",
            re.IGNORECASE,
        ),
        "path_traversal": re.compile(
            r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c", re.IGNORECASE
        ),
        "command_injection": re.compile(r"[;&|`$(){}[\]<>]", re.IGNORECASE),
        "ldap_injection": re.compile(r"[()&|=!><~*]", re.IGNORECASE),
    }

    def __init__(self, strict_mode: bool = True, log_violations: bool = True):
        """
        Initialize medical input validator.

        Args:
            strict_mode: Enable strict validation for medical data
            log_violations: Log security violations for audit trail
        """
        self.strict_mode = strict_mode
        self.log_violations = log_violations
        self.logger = get_medical_audit_logger() if log_violations else None

    def validate_student_data(
        self, student_data: dict[str, Any], required_fields: list[str] | None = None
    ) -> tuple[bool, list[str]]:
        """
        Validate student data input for HIPAA compliance.

        Args:
            student_data: Student data dictionary to validate
            required_fields: List of required field names

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not isinstance(student_data, dict):
            errors.append("Student data must be a dictionary")
            return False, errors

        # Check required fields
        if required_fields:
            for field in required_fields:
                if field not in student_data or student_data[field] is None:
                    errors.append(f"Required field '{field}' is missing or null")

        # Validate individual fields
        field_validators = {
            "student_id": self._validate_student_id,
            "email": self._validate_email,
            "first_name": lambda x: self._validate_name(x, "first_name"),
            "last_name": lambda x: self._validate_name(x, "last_name"),
            "phone": self._validate_phone,
            "date_of_birth": self._validate_date,
            "enrollment_date": self._validate_date,
            "program": lambda x: self._validate_text_field(
                x, "program", max_length=100
            ),
            "year_level": lambda x: self._validate_integer_range(x, "year_level", 1, 4),
            "gpa": lambda x: self._validate_decimal_range(
                x, "gpa", Decimal("0.0"), Decimal("4.0")
            ),
        }

        for field, value in student_data.items():
            if field in field_validators:
                try:
                    field_validators[field](value)
                except ValidationError as e:
                    errors.append(f"{field}: {e.message}")

        # Check for security threats
        security_errors = self._check_security_threats(student_data, "student_data")
        errors.extend(security_errors)

        return len(errors) == 0, errors

    def validate_medical_content(
        self, content_data: dict[str, Any]
    ) -> tuple[bool, list[str]]:
        """
        Validate medical educational content input.

        Args:
            content_data: Medical content data to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not isinstance(content_data, dict):
            errors.append("Content data must be a dictionary")
            return False, errors

        # Validate content structure
        required_fields = ["title", "content", "subject_area", "difficulty_level"]
        for field in required_fields:
            if field not in content_data:
                errors.append(f"Required field '{field}' is missing")

        # Validate specific fields
        try:
            if "title" in content_data:
                self._validate_medical_title(content_data["title"])

            if "content" in content_data:
                self._validate_medical_content_text(content_data["content"])

            if "subject_area" in content_data:
                self._validate_subject_area(content_data["subject_area"])

            if "difficulty_level" in content_data:
                self._validate_difficulty_level(content_data["difficulty_level"])

            if "medical_terminology" in content_data:
                self._validate_medical_terminology(content_data["medical_terminology"])

        except ValidationError as e:
            errors.append(e.message)

        # Security checks
        security_errors = self._check_security_threats(content_data, "medical_content")
        errors.extend(security_errors)

        return len(errors) == 0, errors

    def validate_assessment_data(
        self, assessment_data: dict[str, Any]
    ) -> tuple[bool, list[str]]:
        """
        Validate assessment data for medical education platform.

        Args:
            assessment_data: Assessment data to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not isinstance(assessment_data, dict):
            errors.append("Assessment data must be a dictionary")
            return False, errors

        # Validate assessment structure
        try:
            if "questions" in assessment_data:
                self._validate_assessment_questions(assessment_data["questions"])

            if "time_limit" in assessment_data:
                self._validate_time_limit(assessment_data["time_limit"])

            if "passing_score" in assessment_data:
                self._validate_passing_score(assessment_data["passing_score"])

        except ValidationError as e:
            errors.append(e.message)

        return len(errors) == 0, errors

    def sanitize_input(self, input_data: Any, context: str = "general") -> Any:
        """
        Sanitize input data for safe processing.

        Args:
            input_data: Data to sanitize
            context: Context of the data (general, medical, student, etc.)

        Returns:
            Sanitized data
        """
        if isinstance(input_data, str):
            return self._sanitize_string(input_data, context)
        elif isinstance(input_data, dict):
            return {
                key: self.sanitize_input(value, context)
                for key, value in input_data.items()
            }
        elif isinstance(input_data, list):
            return [self.sanitize_input(item, context) for item in input_data]
        else:
            return input_data

    def _validate_student_id(self, student_id: str) -> None:
        """Validate student ID format."""
        if not isinstance(student_id, str):
            raise ValidationError("Student ID must be a string", "student_id")

        if not self.PATTERNS["student_id"].match(student_id):
            raise ValidationError(
                "Student ID format invalid (must be 6-12 alphanumeric characters)",
                "student_id",
            )

    def _validate_email(self, email: str) -> None:
        """Validate email address format."""
        if not isinstance(email, str):
            raise ValidationError("Email must be a string", "email")

        if not self.PATTERNS["email"].match(email):
            raise ValidationError("Invalid email format", "email")

        # Check for length limits
        if len(email) > 254:
            raise ValidationError(
                "Email address too long (max 254 characters)", "email"
            )

    def _validate_name(self, name: str, field_name: str) -> None:
        """Validate name fields."""
        if not isinstance(name, str):
            raise ValidationError(f"{field_name} must be a string", field_name)

        if len(name) < 1:
            raise ValidationError(f"{field_name} cannot be empty", field_name)

        if len(name) > 50:
            raise ValidationError(
                f"{field_name} too long (max 50 characters)", field_name
            )

        # Check for dangerous characters
        if not self.PATTERNS["alphanumeric"].match(
            name.replace("'", "").replace("-", "")
        ):
            raise ValidationError(
                f"{field_name} contains invalid characters", field_name
            )

    def _validate_phone(self, phone: str) -> None:
        """Validate phone number format."""
        if not isinstance(phone, str):
            raise ValidationError("Phone must be a string", "phone")

        # Remove formatting characters
        cleaned_phone = re.sub(r"[^0-9+]", "", phone)

        if not self.PATTERNS["phone"].match(cleaned_phone):
            raise ValidationError("Invalid phone number format", "phone")

    def _validate_date(self, date_value: str | date | datetime) -> None:
        """Validate date format and range."""
        if isinstance(date_value, str):
            if not self.PATTERNS["date_iso"].match(date_value):
                raise ValidationError("Date must be in ISO format (YYYY-MM-DD)", "date")

            try:
                parsed_date = datetime.strptime(date_value, "%Y-%m-%d").date()
            except ValueError as e:
                raise ValidationError("Invalid date value", "date") from e
        elif isinstance(date_value, date | datetime):
            parsed_date = (
                date_value.date() if isinstance(date_value, datetime) else date_value
            )
        else:
            raise ValidationError("Date must be string, date, or datetime", "date")

        # Check reasonable date range for medical education
        if parsed_date.year < 1900 or parsed_date.year > 2050:
            raise ValidationError("Date out of reasonable range (1900-2050)", "date")

    def _validate_text_field(
        self, text: str, field_name: str, max_length: int = 1000
    ) -> None:
        """Validate general text field."""
        if not isinstance(text, str):
            raise ValidationError(f"{field_name} must be a string", field_name)

        if len(text) > max_length:
            raise ValidationError(
                f"{field_name} too long (max {max_length} characters)", field_name
            )

        # Check for dangerous content
        if self._contains_dangerous_patterns(text):
            raise ValidationError(
                f"{field_name} contains potentially dangerous content", field_name
            )

    def _validate_integer_range(
        self, value: int | str, field_name: str, min_val: int, max_val: int
    ) -> None:
        """Validate integer within range."""
        try:
            int_value = int(value)
        except (ValueError, TypeError) as e:
            raise ValidationError(f"{field_name} must be an integer", field_name) from e

        if int_value < min_val or int_value > max_val:
            raise ValidationError(
                f"{field_name} must be between {min_val} and {max_val}", field_name
            )

    def _validate_decimal_range(
        self,
        value: Decimal | float | str,
        field_name: str,
        min_val: Decimal,
        max_val: Decimal,
    ) -> None:
        """Validate decimal within range."""
        try:
            decimal_value = Decimal(str(value))
        except (InvalidOperation, TypeError) as e:
            raise ValidationError(f"{field_name} must be a valid decimal", field_name) from e

        if decimal_value < min_val or decimal_value > max_val:
            raise ValidationError(
                f"{field_name} must be between {min_val} and {max_val}", field_name
            )

    def _validate_medical_title(self, title: str) -> None:
        """Validate medical content title."""
        if not isinstance(title, str):
            raise ValidationError("Title must be a string", "title")

        if len(title) < 5:
            raise ValidationError("Title too short (minimum 5 characters)", "title")

        if len(title) > 200:
            raise ValidationError("Title too long (maximum 200 characters)", "title")

        if not self.PATTERNS["medical_terminology"].match(title):
            raise ValidationError(
                "Title contains invalid characters for medical content", "title"
            )

    def _validate_medical_content_text(self, content: str) -> None:
        """Validate medical educational content text."""
        if not isinstance(content, str):
            raise ValidationError("Content must be a string", "content")

        if len(content) < 100:
            raise ValidationError(
                "Content too short for educational material (minimum 100 characters)",
                "content",
            )

        if len(content) > 50000:
            raise ValidationError(
                "Content too long (maximum 50,000 characters)", "content"
            )

        # Check for XSS and other security threats
        if self._contains_dangerous_patterns(content):
            raise ValidationError(
                "Content contains potentially dangerous patterns", "content"
            )

    def _validate_subject_area(self, subject_area: str) -> None:
        """Validate medical subject area."""
        valid_subjects = {
            "medical_surgical",
            "pediatrics",
            "maternity",
            "psychiatric",
            "community_health",
            "critical_care",
            "emergency",
            "oncology",
            "cardiology",
            "respiratory",
            "endocrine",
            "neurology",
        }

        if subject_area not in valid_subjects:
            raise ValidationError(
                f"Invalid subject area. Must be one of: {', '.join(valid_subjects)}",
                "subject_area",
            )

    def _validate_difficulty_level(self, difficulty: int | str) -> None:
        """Validate difficulty level for medical content."""
        try:
            level = int(difficulty)
        except (ValueError, TypeError) as e:
            raise ValidationError(
                "Difficulty level must be an integer", "difficulty_level"
            ) from e

        if level < 1 or level > 5:
            raise ValidationError(
                "Difficulty level must be between 1 and 5", "difficulty_level"
            )

    def _validate_medical_terminology(self, terms: list[str]) -> None:
        """Validate medical terminology list."""
        if not isinstance(terms, list):
            raise ValidationError(
                "Medical terminology must be a list", "medical_terminology"
            )

        for term in terms:
            if not isinstance(term, str):
                raise ValidationError(
                    "All medical terms must be strings", "medical_terminology"
                )

            if not self.PATTERNS["medical_terminology"].match(term):
                raise ValidationError(
                    f"Invalid medical term format: {term}", "medical_terminology"
                )

    def _validate_assessment_questions(self, questions: list[dict]) -> None:
        """Validate assessment questions structure."""
        if not isinstance(questions, list):
            raise ValidationError("Questions must be a list", "questions")

        if len(questions) < 1:
            raise ValidationError(
                "Assessment must have at least one question", "questions"
            )

        if len(questions) > 100:
            raise ValidationError(
                "Assessment cannot have more than 100 questions", "questions"
            )

        for i, question in enumerate(questions):
            if not isinstance(question, dict):
                raise ValidationError(
                    f"Question {i + 1} must be a dictionary", "questions"
                )

            if "question_text" not in question:
                raise ValidationError(
                    f"Question {i + 1} missing question_text", "questions"
                )

            if "options" not in question:
                raise ValidationError(f"Question {i + 1} missing options", "questions")

            self._validate_text_field(
                question["question_text"], f"question_{i + 1}_text", 1000
            )

    def _validate_time_limit(self, time_limit: int | str) -> None:
        """Validate assessment time limit."""
        try:
            minutes = int(time_limit)
        except (ValueError, TypeError) as e:
            raise ValidationError(
                "Time limit must be an integer (minutes)", "time_limit"
            ) from e

        if minutes < 5:
            raise ValidationError(
                "Time limit too short (minimum 5 minutes)", "time_limit"
            )

        if minutes > 480:  # 8 hours
            raise ValidationError("Time limit too long (maximum 8 hours)", "time_limit")

    def _validate_passing_score(self, passing_score: int | float | str) -> None:
        """Validate assessment passing score."""
        try:
            score = float(passing_score)
        except (ValueError, TypeError) as e:
            raise ValidationError("Passing score must be a number", "passing_score") from e

        if score < 0 or score > 100:
            raise ValidationError(
                "Passing score must be between 0 and 100", "passing_score"
            )

    def _check_security_threats(self, data: dict[str, Any], context: str) -> list[str]:
        """Check for security threats in input data."""
        errors = []

        for field, value in data.items():
            if isinstance(value, str):
                threats = self._detect_threats(value)
                if threats:
                    for threat in threats:
                        error_msg = f"Security threat detected in {field}: {threat}"
                        errors.append(error_msg)

                        if self.log_violations:
                            log_security_violation(
                                violation_type=threat,
                                details=f"Field: {field}, Context: {context}",
                                threat_level="HIGH",
                            )

        return errors

    def _contains_dangerous_patterns(self, text: str) -> bool:
        """Check if text contains dangerous patterns."""
        for _pattern_name, pattern in self.DANGEROUS_PATTERNS.items():
            if pattern.search(text):
                return True
        return False

    def _detect_threats(self, text: str) -> list[str]:
        """Detect specific security threats in text."""
        threats = []

        for threat_name, pattern in self.DANGEROUS_PATTERNS.items():
            if pattern.search(text):
                threats.append(threat_name)

        return threats

    def _sanitize_string(self, text: str, context: str) -> str:
        """Sanitize string input for safe processing."""
        if not isinstance(text, str):
            return text

        # HTML escape for XSS prevention
        sanitized = html.escape(text)

        # Remove null bytes
        sanitized = sanitized.replace("\x00", "")

        # For medical context, be more strict
        if context == "medical":
            # Remove potentially dangerous characters while preserving medical terminology
            sanitized = re.sub(r'[<>"\']', "", sanitized)

        return sanitized.strip()


# Global validator instance
_medical_validator: MedicalInputValidator | None = None


def get_medical_validator() -> MedicalInputValidator:
    """Get global medical input validator instance."""
    global _medical_validator

    if _medical_validator is None:
        _medical_validator = MedicalInputValidator(
            strict_mode=True, log_violations=True
        )

    return _medical_validator


def validate_medical_input(
    input_data: dict[str, Any], data_type: str = "general"
) -> tuple[bool, list[str]]:
    """
    Convenience function for medical input validation.

    Args:
        input_data: Data to validate
        data_type: Type of data (student, medical_content, assessment, general)

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    validator = get_medical_validator()

    if data_type == "student":
        return validator.validate_student_data(input_data)
    elif data_type == "medical_content":
        return validator.validate_medical_content(input_data)
    elif data_type == "assessment":
        return validator.validate_assessment_data(input_data)
    else:
        # General validation
        errors = []
        try:
            validator.sanitize_input(input_data, "general")  # Sanitize for security
            security_errors = validator._check_security_threats(input_data, "general")
            errors.extend(security_errors)

            return len(errors) == 0, errors
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors
