import logging
import time
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .error_handlers import (
    APIError,
    create_error_response,
    generic_exception_handler,
    http_exception_handler,
    validation_error_handler,
)
from ..auth import rate_limit_middleware
from .routers import (
    adaptive_learning,
    analytics,
    assessment,
    auth,
    clinical_support,
    nclex,
    quizzes,
    study_guide,
    study_guides,
)

# Performance monitoring
logger = logging.getLogger(__name__)
request_metrics = {
    "total_requests": 0,
    "average_response_time": 0.0,
    "slow_requests": 0,
    "error_count": 0,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("BSN Knowledge API starting up")
    yield
    logger.info("BSN Knowledge API shutting down")


app = FastAPI(
    title="BSN Knowledge API",
    description="""
    ## Comprehensive Nursing Education Platform

    BSN Knowledge is a complete educational platform designed specifically for nursing students
    and educators. The platform provides adaptive learning, clinical decision support,
    comprehensive analytics, and assessment tools.

    ### Key Features

    * **🔐 JWT Authentication** - Secure role-based access control
    * **📚 NCLEX Question Generation** - AI-powered NCLEX-style practice questions
    * **🏥 Clinical Decision Support** - Evidence-based clinical recommendations
    * **📊 Learning Analytics** - Comprehensive progress tracking and reporting
    * **🎯 Adaptive Learning** - Personalized learning paths based on performance
    * **⚡ Rate Limiting** - Intelligent request throttling for optimal performance
    * **🔄 RAGnostic Integration** - Advanced content enrichment and processing

    ### Authentication

    All endpoints (except authentication and health) require JWT authentication.
    Use the `/api/v1/auth/login` endpoint to obtain access tokens.

    **To authenticate in Swagger UI:**
    1. Click the "Authorize" button
    2. Enter your token in format: `Bearer <your_jwt_token>`
    3. Click "Authorize" to apply to all endpoints

    ### Rate Limits

    - **General endpoints**: 1,000 requests/hour
    - **Content generation**: 50 requests/hour
    - **Assessment endpoints**: 200 requests/hour
    - **Analytics endpoints**: 500 requests/hour

    ### Support

    For technical support, contact the BSN Knowledge development team.
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    terms_of_service="https://bsn-knowledge.edu/terms",
    contact={
        "name": "BSN Knowledge Support",
        "url": "https://bsn-knowledge.edu/support",
        "email": "support@bsn-knowledge.edu",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    swagger_ui_parameters={
        "deepLinking": True,
        "displayRequestDuration": True,
        "docExpansion": "none",
        "operationsSorter": "method",
        "filter": True,
        "tryItOutEnabled": True,
    },
    openapi_tags=[
        {
            "name": "authentication",
            "description": "Authentication and user management endpoints. Handle login, logout, token refresh, and user information.",
        },
        {
            "name": "study-guides",
            "description": "Study guide generation and management. Create personalized study materials based on learning objectives and performance.",
        },
        {
            "name": "quizzes",
            "description": "Quiz creation and management. Generate practice quizzes and assessments with detailed feedback.",
        },
        {
            "name": "clinical-support",
            "description": "Clinical decision support tools. Provide evidence-based recommendations and case studies for clinical scenarios.",
        },
        {
            "name": "adaptive-learning",
            "description": "Adaptive learning engine. Personalize learning experiences based on individual performance and learning patterns.",
        },
        {
            "name": "assessment",
            "description": "Competency assessment and evaluation. Track progress against nursing competency frameworks.",
        },
        {
            "name": "analytics",
            "description": "Learning analytics and reporting. Comprehensive insights into student progress and institutional performance.",
        },
    ],
)


# Comprehensive exception handlers
@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    """Handle custom API errors"""
    return create_error_response(exc, request)


@app.exception_handler(ValidationError)
async def pydantic_validation_error_handler(request: Request, exc: ValidationError):
    """Handle Pydantic validation errors"""
    return validation_error_handler(request, exc)


@app.exception_handler(HTTPException)
async def fastapi_http_exception_handler(request: Request, exc: HTTPException):
    """Handle FastAPI HTTP exceptions"""
    return http_exception_handler(request, exc)


@app.exception_handler(Exception)
async def catch_all_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions"""
    return generic_exception_handler(request, exc)


# Performance middleware
@app.middleware("http")
async def performance_monitoring_middleware(request: Request, call_next: Callable):
    """Monitor request performance and log slow requests"""
    start_time = time.time()

    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        # Update metrics
        request_metrics["total_requests"] += 1
        request_metrics["average_response_time"] = (
            request_metrics["average_response_time"]
            * (request_metrics["total_requests"] - 1)
            + process_time
        ) / request_metrics["total_requests"]

        # Log slow requests (>500ms)
        if process_time > 0.5:
            request_metrics["slow_requests"] += 1
            logger.warning(
                f"Slow request detected: {request.method} {request.url.path} took {process_time:.3f}s"
            )

        # Add performance headers
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Request-ID"] = str(id(request))

        return response

    except Exception as e:
        request_metrics["error_count"] += 1
        process_time = time.time() - start_time
        logger.error(f"Request failed after {process_time:.3f}s: {str(e)}")

        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "request_id": str(id(request))},
            headers={"X-Process-Time": str(process_time)},
        )


# Add rate limiting middleware
app.middleware("http")(rate_limit_middleware)

# Add middleware stack
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Compress responses > 1KB

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=[
        "X-Process-Time",
        "X-Request-ID",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
    ],
)

# Include routers with enhanced error handling
app.include_router(auth.router, prefix="/api/v1", tags=["authentication"])
app.include_router(study_guides.router, prefix="/api/v1", tags=["study-guides"])
app.include_router(
    study_guide.router, prefix="/api/v1", tags=["study-guide"]
)  # Phase 3 required alias
app.include_router(quizzes.router, prefix="/api/v1", tags=["quizzes"])
app.include_router(
    nclex.router, prefix="/api/v1", tags=["nclex"]
)  # Phase 3 required endpoint
app.include_router(clinical_support.router, prefix="/api/v1", tags=["clinical-support"])
app.include_router(
    adaptive_learning.router, prefix="/api/v1", tags=["adaptive-learning"]
)
app.include_router(assessment.router, prefix="/api/v1", tags=["assessment"])
app.include_router(analytics.router, prefix="/api/v1", tags=["analytics"])


@app.get("/")
async def root():
    return {
        "message": "BSN Knowledge API - Comprehensive Nursing Education Platform",
        "version": "1.0.0",
        "description": "Complete nursing education platform with adaptive learning, clinical decision support, and analytics",
        "features": [
            "JWT Authentication with role-based access control",
            "Rate limiting and security middleware",
            "NCLEX question generation",
            "Clinical decision support",
            "Learning analytics and reporting",
            "Adaptive learning engine",
            "Competency assessment",
            "Study guide generation",
            "Performance monitoring",
            "RAGnostic integration",
        ],
        "endpoints": {
            "authentication": "/api/v1/auth/",
            "documentation": "/docs",
            "health": "/health",
            "metrics": "/metrics",
        },
    }


@app.get("/health")
async def health():
    """Enhanced health check with comprehensive system status"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "1.0.0",
        "performance_metrics": request_metrics,
        "features_status": {
            "authentication": "operational",
            "rate_limiting": "active",
            "ragnostic_integration": "operational",
            "caching": "enabled",
            "circuit_breaker": "active",
            "performance_monitoring": "active",
            "adaptive_learning": "operational",
            "clinical_support": "operational",
            "learning_analytics": "operational",
        },
        "security": {
            "jwt_authentication": "enabled",
            "role_based_access": "enabled",
            "rate_limiting": "enabled",
        },
    }


@app.get("/metrics")
async def get_performance_metrics():
    """Endpoint to retrieve detailed performance metrics"""
    return {
        "api_metrics": request_metrics,
        "uptime_info": {
            "total_requests": request_metrics["total_requests"],
            "average_response_time_ms": round(
                request_metrics["average_response_time"] * 1000, 2
            ),
            "slow_requests_percentage": (
                (
                    request_metrics["slow_requests"]
                    / max(1, request_metrics["total_requests"])
                )
                * 100
            ),
            "error_rate_percentage": (
                (
                    request_metrics["error_count"]
                    / max(1, request_metrics["total_requests"])
                )
                * 100
            ),
        },
    }
