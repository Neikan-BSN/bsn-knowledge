
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/quizzes", tags=["quizzes"])


class QuizRequest(BaseModel):
    topic: str
    question_count: int = 10
    difficulty: str = "medium"


class QuizQuestion(BaseModel):
    id: str
    question: str
    options: list[str]
    correct_answer: int


class QuizResponse(BaseModel):
    id: str
    topic: str
    questions: list[QuizQuestion]
    created_at: str


@router.post("/", response_model=QuizResponse)
async def create_quiz(request: QuizRequest):
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/", response_model=list[QuizResponse])
async def list_quizzes(topic: str | None = None, difficulty: str | None = None):
    raise HTTPException(status_code=501, detail="Not implemented")


@router.get("/{quiz_id}", response_model=QuizResponse)
async def get_quiz(quiz_id: str):
    raise HTTPException(status_code=501, detail="Not implemented")
