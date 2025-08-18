from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ContentType(str, Enum):
    STUDY_GUIDE = "study_guide"
    QUIZ = "quiz"
    VIDEO = "video"
    ARTICLE = "article"
    CASE_STUDY = "case_study"
    SIMULATION = "simulation"


class DifficultyLevel(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"


class ContentMetadata(BaseModel):
    author: str
    created_date: datetime
    last_updated: datetime
    version: str
    tags: list[str]
    source: str | None = None


class EducationalContent(BaseModel):
    id: str
    title: str
    content_type: ContentType
    difficulty: DifficultyLevel
    topic: str
    description: str
    content: str
    objectives: list[str]
    prerequisites: list[str] = []
    estimated_duration: int
    metadata: ContentMetadata
    is_active: bool = True


class ContentRating(BaseModel):
    content_id: str
    student_id: str
    rating: int = Field(ge=1, le=5)
    feedback: str | None = None
    helpful_votes: int = 0
    created_date: datetime


class ContentUsage(BaseModel):
    content_id: str
    student_id: str
    access_count: int = 0
    total_time_spent: int = 0
    completion_status: str
    last_accessed: datetime
    progress_data: dict[str, Any] = {}


class ContentCollection(BaseModel):
    id: str
    name: str
    description: str
    content_ids: list[str]
    category: str
    curator: str
    is_public: bool = True
    created_date: datetime
