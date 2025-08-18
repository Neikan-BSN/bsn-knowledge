from typing import Any

from pydantic import BaseModel


class StudyGuideSection(BaseModel):
    title: str
    content: str
    key_points: list[str]
    resources: list[str]


class StudyGuide(BaseModel):
    title: str
    topic: str
    level: str
    sections: list[StudyGuideSection]
    summary: str
    next_steps: list[str]


class StudyGuideGenerator:
    def __init__(self):
        pass

    async def generate_guide(
        self, topic: str, level: str = "beginner", format: str = "comprehensive"
    ) -> StudyGuide:
        raise NotImplementedError("Study guide generation not implemented")

    async def customize_guide(
        self, base_guide: StudyGuide, student_profile: dict[str, Any]
    ) -> StudyGuide:
        raise NotImplementedError("Study guide customization not implemented")

    async def get_available_topics(self) -> list[str]:
        return [
            "Fundamentals of Nursing",
            "Anatomy and Physiology",
            "Pharmacology",
            "Medical-Surgical Nursing",
            "Psychiatric Nursing",
            "Pediatric Nursing",
            "Maternal Health Nursing",
            "Community Health Nursing",
        ]
