from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class AssessmentType(str, Enum):
    FORMATIVE = "formative"
    SUMMATIVE = "summative"
    DIAGNOSTIC = "diagnostic"
    SELF_ASSESSMENT = "self_assessment"


class QuestionType(str, Enum):
    MULTIPLE_CHOICE = "multiple_choice"
    TRUE_FALSE = "true_false"
    SELECT_ALL = "select_all_that_apply"
    FILL_BLANK = "fill_in_the_blank"
    MATCHING = "matching"
    ORDERING = "ordering"
    SHORT_ANSWER = "short_answer"


class AssessmentQuestion(BaseModel):
    id: str
    question_text: str
    question_type: QuestionType
    options: list[str] = []
    correct_answers: list[int] = []
    explanation: str
    topic: str
    difficulty: str
    points: int = 1
    tags: list[str] = []


class StudentAnswer(BaseModel):
    question_id: str
    selected_answers: list[int] = []
    text_answer: str | None = None
    time_spent: int = 0
    is_correct: bool = False
    points_earned: float = 0.0


class AssessmentSession(BaseModel):
    id: str
    student_id: str
    assessment_id: str
    started_at: datetime
    completed_at: datetime | None = None
    answers: list[StudentAnswer] = []
    total_score: float = 0.0
    percentage_score: float = 0.0
    time_taken: int = 0
    is_completed: bool = False


class Assessment(BaseModel):
    id: str
    title: str
    description: str
    assessment_type: AssessmentType
    topic: str
    questions: list[AssessmentQuestion]
    time_limit: int | None = None
    passing_score: float = 70.0
    max_attempts: int = 3
    randomize_questions: bool = False
    show_results_immediately: bool = True
    created_by: str
    created_date: datetime
    is_active: bool = True


class CompetencyMeasurement(BaseModel):
    competency_id: str
    assessment_id: str
    questions_mapped: list[str]
    weight: float = 1.0
    passing_threshold: float = 70.0


class AssessmentAnalytics(BaseModel):
    assessment_id: str
    total_attempts: int = 0
    average_score: float = 0.0
    pass_rate: float = 0.0
    average_time: int = 0
    difficulty_analysis: dict[str, Any] = {}
    question_analytics: dict[str, dict[str, Any]] = {}
    last_calculated: datetime
