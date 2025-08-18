
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/study-guides", tags=["study-guides"])


class StudyGuideRequest(BaseModel):
    topic: str
    level: str = "beginner"
    format: str = "text"


class StudyGuideResponse(BaseModel):
    id: str
    topic: str
    content: str
    created_at: str


@router.post("/", response_model=StudyGuideResponse)
async def create_study_guide(request: StudyGuideRequest):
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/", response_model=list[StudyGuideResponse])
async def list_study_guides(topic: str | None = None, level: str | None = None):
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/{guide_id}", response_model=StudyGuideResponse)
async def get_study_guide(guide_id: str):
    raise HTTPException(status_code=501, detail="Not implemented")
