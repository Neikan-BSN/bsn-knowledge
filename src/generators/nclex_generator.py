from typing import Any

from pydantic import BaseModel


class NCLEXQuestion(BaseModel):
    question: str
    options: list[str]
    correct_answer: int
    rationale: str
    category: str
    difficulty: str
    nclex_standard: str


class NCLEXGenerator:
    def __init__(self):
        pass

    async def generate_questions(
        self,
        topic: str,
        count: int = 10,
        difficulty: str = "medium",
        category: str = None,
    ) -> list[NCLEXQuestion]:
        raise NotImplementedError("NCLEX question generation not implemented")

    async def validate_question(self, question: NCLEXQuestion) -> dict[str, Any]:
        raise NotImplementedError("NCLEX question validation not implemented")

    async def get_available_categories(self) -> list[str]:
        return [
            "Safe and Effective Care Environment",
            "Health Promotion and Maintenance",
            "Psychosocial Integrity",
            "Physiological Integrity",
        ]
