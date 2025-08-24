import time
import logging
from typing import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from .routers import adaptive_learning, quizzes, study_guides, clinical_support, assessment, analytics

# Performance monitoring
logger = logging.getLogger(__name__)
request_metrics = {
    "total_requests": 0,
    "average_response_time": 0.0,
    "slow_requests": 0,
    "error_count": 0
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    logger.info("BSN Knowledge API starting up")
    yield
    logger.info("BSN Knowledge API shutting down")

app = FastAPI(
    title="BSN Knowledge API",
    description="Educational resource management system for nursing students with enhanced performance optimization",
    version="0.2.0",
    lifespan=lifespan
)

# Global exception handler for better error responses
@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error on {request.url}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
            "request_id": str(id(request))
        }
    )

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
            (request_metrics["average_response_time"] * (request_metrics["total_requests"] - 1) + process_time)
            / request_metrics["total_requests"]
        )
        
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
            headers={"X-Process-Time": str(process_time)}
        )

# Add middleware stack
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Compress responses > 1KB

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Process-Time", "X-Request-ID"]
)

# Include routers with enhanced error handling
app.include_router(study_guides.router, prefix="/api/v1", tags=["study-guides"])
app.include_router(quizzes.router, prefix="/api/v1", tags=["quizzes"])
app.include_router(clinical_support.router, prefix="/api/v1", tags=["clinical-support"])
app.include_router(adaptive_learning.router, prefix="/api/v1", tags=["adaptive-learning"])
app.include_router(assessment.router, prefix="/api/v1", tags=["assessment"])
app.include_router(analytics.router, prefix="/api/v1", tags=["analytics"])


@app.get("/")
async def root():
    return {
        "message": "BSN Knowledge API - Enhanced Integration Architecture",
        "version": "0.2.0",
        "features": [
            "Enhanced RAGnostic integration",
            "Circuit breaker pattern",
            "Request caching",
            "Performance monitoring",
            "Graceful degradation"
        ]
    }


@app.get("/health")
async def health():
    """Enhanced health check with performance metrics"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "performance_metrics": request_metrics,
        "features_status": {
            "ragnostic_integration": "operational",
            "caching": "enabled",
            "circuit_breaker": "active",
            "performance_monitoring": "active"
        }
    }


@app.get("/metrics")
async def get_performance_metrics():
    """Endpoint to retrieve detailed performance metrics"""
    return {
        "api_metrics": request_metrics,
        "uptime_info": {
            "total_requests": request_metrics["total_requests"],
            "average_response_time_ms": round(request_metrics["average_response_time"] * 1000, 2),
            "slow_requests_percentage": (
                (request_metrics["slow_requests"] / max(1, request_metrics["total_requests"])) * 100
            ),
            "error_rate_percentage": (
                (request_metrics["error_count"] / max(1, request_metrics["total_requests"])) * 100
            )
        }
    }