#!/usr/bin/env python3
"""
Medical Audit Logging Framework for BSN Knowledge Platform

Provides HIPAA-compliant structured logging for medical education platform
with proper audit trails, security event tracking, and compliance reporting.

Security Features:
- Structured logging with medical context
- HIPAA-compliant audit trails
- Security event tracking
- Sanitized logging (no PII/PHI exposure)
- Configurable log levels for different environments
"""

import json
import logging
import sys
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any


class MedicalAuditEventType(Enum):
    """Medical audit event types for HIPAA compliance tracking."""

    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SYSTEM_ERROR = "system_error"

    # Authentication Events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    AUTHENTICATION_FAILURE = "auth_failure"
    SESSION_EXPIRED = "session_expired"

    # Data Access Events
    STUDENT_DATA_ACCESS = "student_data_access"
    MEDICAL_CONTENT_ACCESS = "medical_content_access"
    ASSESSMENT_DATA_ACCESS = "assessment_data_access"
    ANALYTICS_DATA_ACCESS = "analytics_data_access"

    # Data Modification Events
    STUDENT_RECORD_UPDATE = "student_record_update"
    MEDICAL_CONTENT_UPDATE = "medical_content_update"
    ASSESSMENT_CREATION = "assessment_creation"
    ASSESSMENT_SUBMISSION = "assessment_submission"

    # Security Events
    SECURITY_VIOLATION = "security_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    FAILED_ACCESS_ATTEMPT = "failed_access_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Medical Platform Events
    MEDICAL_CALCULATION = "medical_calculation"
    CLINICAL_DECISION_SUPPORT = "clinical_decision_support"
    LEARNING_ANALYTICS = "learning_analytics"
    KNOWLEDGE_ASSESSMENT = "knowledge_assessment"


class MedicalAuditLogger:
    """HIPAA-compliant medical audit logger for BSN Knowledge platform."""

    def __init__(
        self,
        logger_name: str = "bsn_medical_audit",
        log_file: Path | None = None,
        console_output: bool = True,
        log_level: str = "INFO",
    ):
        """
        Initialize medical audit logger.

        Args:
            logger_name: Name for the logger instance
            log_file: Path to log file (None for no file logging)
            console_output: Whether to output to console
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # Clear any existing handlers
        self.logger.handlers.clear()

        # Setup structured formatter
        self.formatter = self._create_structured_formatter()

        # Setup console handler if requested
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(self.formatter)
            self.logger.addHandler(console_handler)

        # Setup file handler if log file specified
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(self.formatter)
            self.logger.addHandler(file_handler)

    def _create_structured_formatter(self) -> logging.Formatter:
        """Create structured JSON formatter for medical audit compliance."""

        class MedicalAuditFormatter(logging.Formatter):
            def format(self, record):
                # Base structured log entry
                log_entry = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno,
                }

                # Add medical audit context if present
                if hasattr(record, "audit_context"):
                    log_entry["audit_context"] = record.audit_context

                # Add user context if present (sanitized)
                if hasattr(record, "user_context"):
                    user_context = record.user_context.copy()
                    # Remove any potential PII/PHI
                    sanitized_user = self._sanitize_user_context(user_context)
                    log_entry["user_context"] = sanitized_user

                # Add request context if present
                if hasattr(record, "request_context"):
                    log_entry["request_context"] = record.request_context

                return json.dumps(log_entry)

            def _sanitize_user_context(
                self, user_context: dict[str, Any]
            ) -> dict[str, Any]:
                """Sanitize user context to remove PII/PHI for HIPAA compliance."""
                sanitized = {}

                # Allow only safe fields
                safe_fields = {
                    "user_id",
                    "role",
                    "institution_id",
                    "session_id",
                    "permissions",
                    "authentication_method",
                    "user_type",
                }

                for key, value in user_context.items():
                    if key in safe_fields:
                        sanitized[key] = value
                    else:
                        sanitized[key] = "[REDACTED_FOR_PRIVACY]"

                return sanitized

        return MedicalAuditFormatter()

    def log_audit_event(
        self,
        event_type: MedicalAuditEventType,
        message: str,
        user_id: str | None = None,
        student_id: str | None = None,
        resource_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
        severity: str = "INFO",
    ):
        """
        Log a medical audit event with proper context.

        Args:
            event_type: Type of audit event
            message: Human-readable event message
            user_id: ID of user performing action (hashed/anonymized)
            student_id: ID of student affected (hashed/anonymized)
            resource_id: ID of resource accessed/modified
            additional_context: Additional context information
            severity: Log severity level
        """

        # Build audit context
        audit_context = {
            "event_type": event_type.value,
            "event_id": self._generate_event_id(),
            "platform": "bsn_knowledge",
            "compliance_framework": "hipaa_ferpa",
        }

        if user_id:
            audit_context["user_id"] = self._hash_identifier(user_id)

        if student_id:
            audit_context["student_id"] = self._hash_identifier(student_id)

        if resource_id:
            audit_context["resource_id"] = resource_id

        if additional_context:
            # Sanitize additional context
            sanitized_context = self._sanitize_context(additional_context)
            audit_context.update(sanitized_context)

        # Create log record with audit context
        log_level = getattr(logging, severity.upper())
        record = self.logger.makeRecord(
            self.logger.name, log_level, "", 0, message, (), None
        )
        record.audit_context = audit_context

        self.logger.handle(record)

    def log_security_event(
        self,
        event_type: MedicalAuditEventType,
        message: str,
        threat_level: str = "MEDIUM",
        user_context: dict[str, Any] | None = None,
        request_context: dict[str, Any] | None = None,
    ):
        """
        Log security-related events for medical platform protection.

        Args:
            event_type: Type of security event
            message: Security event description
            threat_level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
            user_context: User context information
            request_context: Request context information
        """

        audit_context = {
            "event_type": event_type.value,
            "event_category": "security",
            "threat_level": threat_level,
            "event_id": self._generate_event_id(),
            "platform": "bsn_knowledge",
            "requires_investigation": threat_level in ["HIGH", "CRITICAL"],
        }

        # Determine log level based on threat level
        log_level_map = {
            "LOW": "INFO",
            "MEDIUM": "WARNING",
            "HIGH": "ERROR",
            "CRITICAL": "CRITICAL",
        }
        severity = log_level_map.get(threat_level, "WARNING")

        log_level = getattr(logging, severity)
        record = self.logger.makeRecord(
            self.logger.name, log_level, "", 0, message, (), None
        )
        record.audit_context = audit_context

        if user_context:
            record.user_context = user_context

        if request_context:
            record.request_context = self._sanitize_request_context(request_context)

        self.logger.handle(record)

    def log_medical_calculation(
        self,
        calculation_type: str,
        input_data: dict[str, Any],
        result: Any,
        user_id: str | None = None,
        confidence_score: float | None = None,
    ):
        """
        Log medical calculations for audit trail compliance.

        Args:
            calculation_type: Type of medical calculation performed
            input_data: Input data used (sanitized)
            result: Calculation result
            user_id: User who requested calculation
            confidence_score: Confidence score of calculation
        """

        # S110 fix: Proper structured logging instead of silent exception handling
        sanitized_input = self._sanitize_medical_data(input_data)

        audit_context = {
            "event_type": MedicalAuditEventType.MEDICAL_CALCULATION.value,
            "calculation_type": calculation_type,
            "event_id": self._generate_event_id(),
            "input_data_hash": self._hash_data(str(sanitized_input)),
            "result_type": type(result).__name__,
            "confidence_score": confidence_score,
            "platform": "bsn_knowledge",
        }

        if user_id:
            audit_context["user_id"] = self._hash_identifier(user_id)

        message = f"Medical calculation performed: {calculation_type}"
        if confidence_score:
            message += f" (confidence: {confidence_score:.3f})"

        record = self.logger.makeRecord(
            self.logger.name, logging.INFO, "", 0, message, (), None
        )
        record.audit_context = audit_context

        self.logger.handle(record)

    def _generate_event_id(self) -> str:
        """Generate unique event ID for audit trail."""
        import uuid

        return str(uuid.uuid4())

    def _hash_identifier(self, identifier: str) -> str:
        """Hash user/student identifiers for privacy protection."""
        import hashlib

        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def _hash_data(self, data: str) -> str:
        """Hash data for integrity verification."""
        import hashlib

        return hashlib.sha256(data.encode()).hexdigest()

    def _sanitize_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """Sanitize context data to prevent PII/PHI exposure."""
        sanitized = {}

        # Fields that are safe to log
        safe_fields = {
            "action",
            "resource_type",
            "operation",
            "status",
            "duration",
            "success",
            "error_code",
            "retry_count",
            "api_version",
            "client_version",
            "feature_flags",
        }

        for key, value in context.items():
            if key in safe_fields:
                sanitized[key] = value
            elif "id" in key.lower():
                # Hash any ID fields
                sanitized[key] = self._hash_identifier(str(value))
            else:
                sanitized[f"{key}_sanitized"] = "[REDACTED_FOR_PRIVACY]"

        return sanitized

    def _sanitize_request_context(
        self, request_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Sanitize request context for security logging."""
        sanitized = {}

        safe_fields = {
            "method",
            "endpoint",
            "status_code",
            "response_time",
            "user_agent_type",
            "ip_hash",
            "request_id",
        }

        for key, value in request_context.items():
            if key in safe_fields:
                sanitized[key] = value
            elif key == "ip_address":
                # Hash IP addresses for privacy
                sanitized["ip_hash"] = self._hash_identifier(str(value))
            else:
                sanitized[f"{key}_redacted"] = True

        return sanitized

    def _sanitize_medical_data(self, medical_data: dict[str, Any]) -> dict[str, Any]:
        """Sanitize medical data for calculation logging."""
        sanitized = {}

        # Only log structure and types, not actual values
        for key, value in medical_data.items():
            sanitized[key] = {
                "type": type(value).__name__,
                "length": len(str(value)) if value else 0,
                "present": value is not None,
            }

        return sanitized


# Global medical audit logger instance
_medical_audit_logger: MedicalAuditLogger | None = None


def get_medical_audit_logger() -> MedicalAuditLogger:
    """Get global medical audit logger instance."""
    global _medical_audit_logger

    if _medical_audit_logger is None:
        log_file = Path(__file__).parent.parent.parent / "logs" / "medical_audit.log"
        _medical_audit_logger = MedicalAuditLogger(
            logger_name="bsn_medical_audit",
            log_file=log_file,
            console_output=True,
            log_level="INFO",
        )

    return _medical_audit_logger


def log_medical_access(
    resource_type: str, resource_id: str, user_id: str, action: str = "access"
) -> None:
    """Convenience function for logging medical resource access."""
    logger = get_medical_audit_logger()
    logger.log_audit_event(
        event_type=MedicalAuditEventType.MEDICAL_CONTENT_ACCESS,
        message=f"Medical {resource_type} {action}: {resource_id}",
        user_id=user_id,
        resource_id=resource_id,
        additional_context={"action": action, "resource_type": resource_type},
    )


def log_security_violation(
    violation_type: str,
    details: str,
    user_context: dict[str, Any] | None = None,
    threat_level: str = "MEDIUM",
) -> None:
    """Convenience function for logging security violations."""
    logger = get_medical_audit_logger()
    logger.log_security_event(
        event_type=MedicalAuditEventType.SECURITY_VIOLATION,
        message=f"Security violation detected: {violation_type} - {details}",
        threat_level=threat_level,
        user_context=user_context,
    )
