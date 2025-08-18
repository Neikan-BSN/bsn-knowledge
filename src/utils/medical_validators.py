import re
from typing import Any

from pydantic import BaseModel


class ValidationResult(BaseModel):
    is_valid: bool
    errors: list[str] = []
    warnings: list[str] = []
    suggestions: list[str] = []


class MedicalTermValidator:
    def __init__(self):
        self.approved_terms = set()
        self.deprecated_terms = {}
        self.drug_name_patterns = [
            r"^[A-Za-z][a-zA-Z0-9\-]*$",
        ]

    def validate_medication_name(self, medication: str) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        if not medication or not medication.strip():
            result.is_valid = False
            result.errors.append("Medication name cannot be empty")
            return result

        medication = medication.strip()

        if len(medication) < 2:
            result.is_valid = False
            result.errors.append("Medication name too short")

        if not any(
            re.match(pattern, medication) for pattern in self.drug_name_patterns
        ):
            result.warnings.append("Medication name format may be non-standard")

        return result

    def validate_dosage(self, dosage: str) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        dosage_patterns = [
            r"^\d+(\.\d+)?\s*(mg|g|mcg|μg|IU|mL|L)$",
            r"^\d+(\.\d+)?\s*(mg|g|mcg|μg|IU|mL|L)\s*/\s*(kg|day|dose)$",
        ]

        if not any(
            re.match(pattern, dosage, re.IGNORECASE) for pattern in dosage_patterns
        ):
            result.is_valid = False
            result.errors.append("Invalid dosage format")

        return result

    def validate_medical_terminology(self, text: str) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        if not text or not text.strip():
            result.is_valid = False
            result.errors.append("Medical text cannot be empty")
            return result

        dangerous_terms = [
            "always fatal",
            "never recovers",
            "100% mortality",
            "guaranteed cure",
            "miracle treatment",
        ]

        text_lower = text.lower()
        for term in dangerous_terms:
            if term in text_lower:
                result.warnings.append(f"Potentially misleading term: {term}")

        return result


class NCLEXValidator:
    def __init__(self):
        self.nclex_categories = {
            "Safe and Effective Care Environment": [
                "Management of Care",
                "Safety and Infection Control",
            ],
            "Health Promotion and Maintenance": [],
            "Psychosocial Integrity": [],
            "Physiological Integrity": [
                "Basic Care and Comfort",
                "Pharmacological and Parenteral Therapies",
                "Reduction of Risk Potential",
                "Physiological Adaptation",
            ],
        }

    def validate_nclex_question(
        self, question_data: dict[str, Any]
    ) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        required_fields = ["question", "options", "correct_answer", "rationale"]
        for field in required_fields:
            if field not in question_data or not question_data[field]:
                result.is_valid = False
                result.errors.append(f"Missing required field: {field}")

        if "options" in question_data:
            options = question_data["options"]
            if not isinstance(options, list) or len(options) < 4:
                result.is_valid = False
                result.errors.append("NCLEX questions must have at least 4 options")

        if "correct_answer" in question_data:
            correct = question_data["correct_answer"]
            if not isinstance(correct, int) or correct < 0:
                result.is_valid = False
                result.errors.append("Invalid correct answer index")

        return result

    def validate_nclex_category(self, category: str) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        if category not in self.nclex_categories:
            result.is_valid = False
            result.errors.append(f"Invalid NCLEX category: {category}")

        return result


class ContentSafetyValidator:
    def __init__(self):
        self.prohibited_content = [
            "personal medical advice",
            "diagnosis recommendations",
            "treatment prescriptions",
        ]

    def validate_educational_content(self, content: str) -> ValidationResult:
        result = ValidationResult(is_valid=True)

        content_lower = content.lower()

        for prohibited in self.prohibited_content:
            if prohibited in content_lower:
                result.warnings.append(
                    f"Content may contain prohibited medical advice: {prohibited}"
                )

        if "should take" in content_lower or "must take" in content_lower:
            result.warnings.append(
                "Content appears to give specific medical instructions"
            )

        return result
