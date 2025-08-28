"""BSN Knowledge API Gateway - Main FastAPI application.

Implements Task Group 2 service coordination patterns with Neo4j integration.
"""

import asyncio
import time
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# FastAPI application
app = FastAPI(
    title="BSN Knowledge Base API",
    description="Neo4j-powered medical terminology and knowledge management system",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def logging_middleware(request, call_next):
    """Request/response logging middleware."""
    start_time = time.time()

    # Log request
    logger.info(
        "request_started",
        method=request.method,
        url=str(request.url),
        headers=dict(request.headers),
    )

    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        # Log response
        logger.info(
            "request_completed",
            method=request.method,
            url=str(request.url),
            status_code=response.status_code,
            process_time=process_time,
        )

        response.headers["X-Process-Time"] = str(process_time)
        return response

    except Exception as e:
        process_time = time.time() - start_time

        logger.error(
            "request_failed",
            method=request.method,
            url=str(request.url),
            error=str(e),
            process_time=process_time,
        )

        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )


@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Health check endpoint for load balancers and monitoring."""
    try:
        # Check database connections
        neo4j_status = await check_neo4j_connection()
        postgres_status = await check_postgres_connection()
        redis_status = await check_redis_connection()
        qdrant_status = await check_qdrant_connection()

        # Overall health status
        healthy = all([neo4j_status, postgres_status, redis_status, qdrant_status])

        return {
            "status": "healthy" if healthy else "degraded",
            "timestamp": time.time(),
            "services": {
                "neo4j": "up" if neo4j_status else "down",
                "postgres": "up" if postgres_status else "down",
                "redis": "up" if redis_status else "down",
                "qdrant": "up" if qdrant_status else "down",
            },
            "version": "0.1.0",
            "environment": "production",
        }

    except Exception as e:
        logger.error("health_check_failed", error=str(e))
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "timestamp": time.time(), "error": str(e)},
        )


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint with API information."""
    return {
        "message": "BSN Knowledge Base API",
        "version": "0.1.0",
        "description": "Neo4j-powered medical terminology and knowledge management system",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/api/v1/medical-terms")
async def get_medical_terms(
    category: str = None, search: str = None, limit: int = 100, offset: int = 0
) -> dict[str, Any]:
    """Get medical terms with optional filtering."""
    try:
        # Mock response - would implement actual Neo4j queries
        terms = [
            {
                "id": "term_1",
                "name": "Hypertension",
                "category": "cardiovascular",
                "description": "High blood pressure condition",
                "synonyms": ["High blood pressure", "HTN"],
                "created_at": "2024-01-01T00:00:00Z",
            },
            {
                "id": "term_2",
                "name": "Diabetes",
                "category": "endocrine",
                "description": "Metabolic disorder affecting blood sugar",
                "synonyms": ["Diabetes mellitus", "DM"],
                "created_at": "2024-01-01T00:00:00Z",
            },
        ]

        # Apply filters (mock implementation)
        if category:
            terms = [t for t in terms if t["category"] == category]

        if search:
            terms = [t for t in terms if search.lower() in t["name"].lower()]

        # Apply pagination
        total = len(terms)
        terms = terms[offset : offset + limit]

        logger.info(
            "medical_terms_retrieved",
            count=len(terms),
            total=total,
            category=category,
            search=search,
        )

        return {
            "terms": terms,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total,
        }

    except Exception as e:
        logger.error("get_medical_terms_failed", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to retrieve medical terms"
        ) from e


@app.post("/api/v1/medical-terms")
async def create_medical_term(term_data: dict[str, Any]) -> dict[str, Any]:
    """Create a new medical term."""
    try:
        # Validate required fields
        required_fields = ["name", "category"]
        for field in required_fields:
            if field not in term_data:
                raise HTTPException(
                    status_code=400, detail=f"Missing required field: {field}"
                ) from e

        # Mock creation - would implement actual Neo4j creation
        created_term = {
            "id": f"term_{int(time.time())}",
            "name": term_data["name"],
            "category": term_data["category"],
            "description": term_data.get("description", ""),
            "synonyms": term_data.get("synonyms", []),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

        logger.info(
            "medical_term_created",
            term_id=created_term["id"],
            name=created_term["name"],
            category=created_term["category"],
        )

        return created_term

    except HTTPException:
        raise
    except Exception as e:
        logger.error("create_medical_term_failed", error=str(e))
        raise HTTPException(
            status_code=500, detail="Failed to create medical term"
        ) from e


@app.get("/api/v1/search/semantic")
async def semantic_search(
    query: str, top_k: int = 10, threshold: float = 0.7
) -> dict[str, Any]:
    """Perform semantic search using vector embeddings."""
    try:
        # Mock semantic search - would implement actual Qdrant queries
        search_results = [
            {
                "term_id": "term_1",
                "name": "Hypertension",
                "category": "cardiovascular",
                "score": 0.95,
                "snippet": "High blood pressure condition affecting cardiovascular system",
            },
            {
                "term_id": "term_2",
                "name": "Blood pressure monitoring",
                "category": "diagnostic",
                "score": 0.87,
                "snippet": "Process of measuring blood pressure for diagnosis",
            },
        ]

        # Filter by threshold
        search_results = [r for r in search_results if r["score"] >= threshold]
        search_results = search_results[:top_k]

        logger.info(
            "semantic_search_completed",
            query=query,
            results_count=len(search_results),
            top_k=top_k,
            threshold=threshold,
        )

        return {
            "query": query,
            "results": search_results,
            "total": len(search_results),
            "search_time": 0.15,  # Mock search time
            "threshold": threshold,
        }

    except Exception as e:
        logger.error("semantic_search_failed", query=query, error=str(e))
        raise HTTPException(status_code=500, detail="Search failed") from e


@app.get("/api/v1/graph/traverse")
async def graph_traversal(
    start_term: str, max_depth: int = 3, relationship_types: str = None
) -> dict[str, Any]:
    """Perform graph traversal from a starting term."""
    try:
        # Mock graph traversal - would implement actual Neo4j traversal
        paths = [
            {
                "path": ["term_1", "term_2"],
                "depth": 1,
                "relationships": ["COMORBID_WITH"],
                "strength": 0.85,
            },
            {
                "path": ["term_1", "term_2", "term_3"],
                "depth": 2,
                "relationships": ["COMORBID_WITH", "RELATED_TO"],
                "strength": 0.72,
            },
        ]

        logger.info(
            "graph_traversal_completed",
            start_term=start_term,
            max_depth=max_depth,
            paths_found=len(paths),
        )

        return {
            "start_term": start_term,
            "max_depth": max_depth,
            "paths": paths,
            "total_paths": len(paths),
            "traversal_time": 0.25,
        }

    except Exception as e:
        logger.error("graph_traversal_failed", start_term=start_term, error=str(e))
        raise HTTPException(status_code=500, detail="Graph traversal failed") from e


# Health check helper functions (mock implementations)
async def check_neo4j_connection() -> bool:
    """Check Neo4j database connection."""
    try:
        # Mock connection check - would implement actual Neo4j connectivity test
        await asyncio.sleep(0.01)  # Simulate connection check
        return True
    except Exception:
        return False


async def check_postgres_connection() -> bool:
    """Check PostgreSQL database connection."""
    try:
        # Mock connection check - would implement actual PostgreSQL connectivity test
        await asyncio.sleep(0.01)
        return True
    except Exception:
        return False


async def check_redis_connection() -> bool:
    """Check Redis connection."""
    try:
        # Mock connection check - would implement actual Redis connectivity test
        await asyncio.sleep(0.01)
        return True
    except Exception:
        return False


async def check_qdrant_connection() -> bool:
    """Check Qdrant vector database connection."""
    try:
        # Mock connection check - would implement actual Qdrant connectivity test
        await asyncio.sleep(0.01)
        return True
    except Exception:
        return False


# Performance metrics endpoint
@app.get("/metrics")
async def get_metrics() -> dict[str, Any]:
    """Get application performance metrics."""
    try:
        # Mock metrics - would implement actual metrics collection
        return {
            "timestamp": time.time(),
            "requests_per_second": 45.2,
            "average_response_time": 0.15,
            "active_connections": 12,
            "database_connections": {
                "neo4j": 8,
                "postgres": 5,
                "redis": 3,
                "qdrant": 2,
            },
            "memory_usage": 0.65,
            "cpu_usage": 0.42,
            "cache_hit_rate": 0.89,
            "error_rate": 0.02,
        }
    except Exception as e:
        logger.error("metrics_collection_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to collect metrics") from e


if __name__ == "__main__":
    import uvicorn

    logger.info("starting_bsn_knowledge_api", version="0.1.0")

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        workers=1,  # Single worker for development
    )
