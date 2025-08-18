from typing import Any

from pydantic import BaseModel


class QuizQuestion(BaseModel):
    question: str
    options: list[str]
    correct_answer: int
    explanation: str
    difficulty: str
    topic: str
    tags: list[str]


class Quiz(BaseModel):
    title: str
    topic: str
    questions: list[QuizQuestion]
    time_limit: int | None
    passing_score: float
    metadata: dict[str, Any]


class QuizGenerator:
    def __init__(self):
        pass

    async def generate_quiz(
        self,
        topic: str,
        question_count: int = 10,
        difficulty: str = "medium",
        question_types: list[str] = None,
    ) -> Quiz:
        raise NotImplementedError("Quiz generation not implemented")

    async def adapt_difficulty(
        self, student_performance: dict[str, Any], base_quiz: Quiz
    ) -> Quiz:
        raise NotImplementedError("Adaptive difficulty not implemented")

    async def validate_quiz(self, quiz: Quiz) -> dict[str, Any]:
        raise NotImplementedError("Quiz validation not implemented")

    def get_supported_question_types(self) -> list[str]:
        return [
            "multiple_choice",
            "true_false",
            "select_all_that_apply",
            "fill_in_the_blank",
            "matching",
            "ordering",
        ]
