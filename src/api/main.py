from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import adaptive_learning, quizzes, study_guides

app = FastAPI(
    title="BSN Knowledge API",
    description="Educational resource management system for nursing students",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(study_guides.router, prefix="/api/v1")
app.include_router(quizzes.router, prefix="/api/v1")
app.include_router(adaptive_learning.router, prefix="/api/v1")


@app.get("/")
async def root():
    return {"message": "BSN Knowledge API"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
