from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, EmailStr


class StudentYear(str, Enum):
    FIRST_YEAR = "first_year"
    SECOND_YEAR = "second_year"
    THIRD_YEAR = "third_year"
    FOURTH_YEAR = "fourth_year"
    GRADUATE = "graduate"


class LearningStyle(str, Enum):
    VISUAL = "visual"
    AUDITORY = "auditory"
    KINESTHETIC = "kinesthetic"
    READING_WRITING = "reading_writing"


class StudentPreferences(BaseModel):
    learning_style: LearningStyle
    preferred_study_time: list[str] = []
    difficulty_preference: str = "adaptive"
    content_types: list[str] = []
    notification_settings: dict[str, bool] = {}


class AcademicRecord(BaseModel):
    gpa: float | None = None
    courses_completed: list[str] = []
    current_courses: list[str] = []
    specialization: str | None = None
    clinical_hours: int = 0


class LearningGoal(BaseModel):
    id: str
    title: str
    description: str
    target_date: datetime
    priority: str
    progress: float = 0.0
    is_active: bool = True


class StudentProfile(BaseModel):
    id: str
    user_id: str
    email: EmailStr
    first_name: str
    last_name: str
    student_year: StudentYear
    program: str
    school: str | None = None
    preferences: StudentPreferences
    academic_record: AcademicRecord
    learning_goals: list[LearningGoal] = []
    created_date: datetime
    last_active: datetime
    is_active: bool = True


class StudentProgress(BaseModel):
    student_id: str
    topic: str
    competency_level: str
    assessment_scores: list[float] = []
    time_spent_studying: int = 0
    resources_completed: list[str] = []
    last_assessment_date: datetime | None = None
    trend_data: dict[str, Any] = {}


class StudentEngagement(BaseModel):
    student_id: str
    daily_logins: int = 0
    weekly_study_hours: float = 0.0
    quiz_completion_rate: float = 0.0
    content_interaction_score: float = 0.0
    peer_collaboration_score: float = 0.0
    last_calculated: datetime
