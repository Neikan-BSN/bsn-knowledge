import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class RAGnosticRequest(BaseModel):
    query: str
    context_type: str = "medical"
    max_results: int = 10
    filters: dict[str, Any] = {}


class RAGnosticResponse(BaseModel):
    results: list[dict[str, Any]]
    metadata: dict[str, Any]
    processing_time: float


class CircuitBreakerState:
    """Circuit breaker implementation for resilient API calls"""

    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failure_count = 0
        self.last_failure_time: datetime | None = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def is_open(self) -> bool:
        if self.state == "OPEN":
            if (datetime.now() - self.last_failure_time).seconds >= self.reset_timeout:
                self.state = "HALF_OPEN"
                return False
            return True
        return False

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"
        self.last_failure_time = None

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class RequestCache:
    """Simple in-memory cache with TTL for API responses"""

    def __init__(self, default_ttl: int = 300):
        self.cache: dict[str, tuple] = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Any | None:
        if key in self.cache:
            value, expiry = self.cache[key]
            if datetime.now() < expiry:
                return value
            else:
                del self.cache[key]
        return None

    def set(self, key: str, value: Any, ttl: int | None = None):
        expiry = datetime.now() + timedelta(seconds=ttl or self.default_ttl)
        self.cache[key] = (value, expiry)

    def clear(self):
        self.cache.clear()


class RAGnosticClient:
    """Enhanced client for interacting with RAGnostic pipeline API with performance optimizations"""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        max_retries: int = 3,
        cache_ttl: int = 300,
        connection_pool_size: int = 100,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.max_retries = max_retries

        # Enhanced client configuration
        headers = {"User-Agent": "BSN-Knowledge-Client/1.0"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Connection pooling and timeout configuration
        limits = httpx.Limits(
            max_keepalive_connections=connection_pool_size,
            max_connections=connection_pool_size,
        )
        timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=60.0)

        self.client = httpx.AsyncClient(
            timeout=timeout,
            headers=headers,
            limits=limits,
            http2=True,  # Enable HTTP/2 for better performance
        )

        # Performance optimization features
        self.circuit_breaker = CircuitBreakerState()
        self.cache = RequestCache(default_ttl=cache_ttl)
        self.request_semaphore = asyncio.Semaphore(50)  # Limit concurrent requests

        # Performance metrics
        self.metrics = {
            "total_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "circuit_breaker_trips": 0,
            "average_response_time": 0.0,
            "last_reset": datetime.now(),
        }

        logger.info(f"Enhanced RAGnostic client initialized with base URL: {base_url}")
        logger.info(
            f"Performance features: caching (TTL={cache_ttl}s), circuit breaker, connection pooling ({connection_pool_size})"
        )

    def _cache_key(self, endpoint: str, params: dict[str, Any]) -> str:
        """Generate cache key for request"""
        import hashlib
        import json

        key_data = f"{endpoint}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    async def _make_request_with_resilience(
        self,
        method: str,
        endpoint: str,
        payload: dict[str, Any] | None = None,
        cache_enabled: bool = True,
        cache_ttl: int | None = None,
    ) -> dict[str, Any]:
        """Make HTTP request with circuit breaker, caching, and retry logic"""

        # Check circuit breaker
        if self.circuit_breaker.is_open():
            self.metrics["circuit_breaker_trips"] += 1
            raise ConnectionError(
                "Circuit breaker is open - service temporarily unavailable"
            )

        # Check cache for GET requests
        cache_key = None
        if cache_enabled and method.upper() == "GET":
            cache_key = self._cache_key(endpoint, payload or {})
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                self.metrics["cache_hits"] += 1
                return cached_result
            self.metrics["cache_misses"] += 1

        start_time = datetime.now()

        async with self.request_semaphore:
            for attempt in range(self.max_retries + 1):
                try:
                    self.metrics["total_requests"] += 1

                    if method.upper() == "GET":
                        response = await self.client.get(endpoint, params=payload)
                    else:
                        response = await self.client.request(
                            method, endpoint, json=payload
                        )

                    response.raise_for_status()
                    result = response.json()

                    # Record success and update metrics
                    self.circuit_breaker.record_success()
                    response_time = (datetime.now() - start_time).total_seconds()
                    self.metrics["average_response_time"] = (
                        self.metrics["average_response_time"]
                        * (self.metrics["total_requests"] - 1)
                        + response_time
                    ) / self.metrics["total_requests"]

                    # Cache successful responses
                    if cache_enabled and cache_key and method.upper() == "GET":
                        self.cache.set(cache_key, result, cache_ttl)

                    return result

                except (httpx.RequestError, httpx.HTTPStatusError) as e:
                    if attempt == self.max_retries:
                        self.circuit_breaker.record_failure()
                        logger.error(
                            f"Request failed after {self.max_retries + 1} attempts: {str(e)}"
                        )
                        if isinstance(e, httpx.HTTPStatusError):
                            raise Exception(
                                f"RAGnostic API error: {e.response.status_code}"
                            ) from e
                        raise ConnectionError(
                            "Failed to connect to RAGnostic service"
                        ) from e

                    # Exponential backoff
                    wait_time = 2**attempt
                    logger.warning(
                        f"Request attempt {attempt + 1} failed, retrying in {wait_time}s: {str(e)}"
                    )
                    await asyncio.sleep(wait_time)

    async def search_content(
        self,
        query: str,
        filters: dict[str, Any] | None = None,
        limit: int = 10,
        offset: int = 0,
        cache_ttl: int | None = 300,
    ) -> dict[str, Any]:
        """
        Search enriched content from RAGnostic pipeline with caching

        Searches against UMLS-enriched, multi-embedded content
        """
        endpoint = f"{self.base_url}/api/v1/search"
        payload = {
            "query": query,
            "filters": filters or {},
            "limit": limit,
            "offset": offset,
        }

        try:
            results = await self._make_request_with_resilience(
                "POST", endpoint, payload, cache_enabled=True, cache_ttl=cache_ttl
            )
            logger.info(
                f"Search completed: {len(results.get('items', []))} results for query: {query[:50]}..."
            )
            return results
        except Exception as e:
            logger.error(f"Search failed for query '{query}': {str(e)}")
            # Graceful degradation - return empty results with error indication
            return {"items": [], "total": 0, "error": str(e), "fallback_mode": True}

    async def get_concept_graph(
        self, concept_id: str, cache_ttl: int | None = 600
    ) -> dict[str, Any]:
        """Get prerequisite and relationship graph with extended caching"""
        endpoint = f"{self.base_url}/api/v1/concepts/{concept_id}/graph"

        try:
            graph_data = await self._make_request_with_resilience(
                "GET", endpoint, cache_enabled=True, cache_ttl=cache_ttl
            )
            logger.info(f"Retrieved concept graph for {concept_id}")
            return graph_data
        except Exception as e:
            logger.error(f"Failed to retrieve concept graph for {concept_id}: {str(e)}")
            # Graceful degradation - return minimal graph structure
            return {
                "concept_id": concept_id,
                "nodes": [],
                "edges": [],
                "error": str(e),
                "fallback_mode": True,
            }

    async def get_content_by_metadata(
        self,
        metadata_filters: dict[str, Any],
        sort_by: str | None = "relevance",
        limit: int = 50,
        cache_ttl: int | None = 300,
    ) -> dict[str, Any]:
        """Retrieve content by rich metadata with caching"""
        endpoint = f"{self.base_url}/api/v1/content/metadata"
        payload = {"filters": metadata_filters, "sort_by": sort_by, "limit": limit}

        try:
            results = await self._make_request_with_resilience(
                "POST", endpoint, payload, cache_enabled=True, cache_ttl=cache_ttl
            )
            logger.info(
                f"Metadata search completed: {len(results.get('items', []))} results"
            )
            return results
        except Exception as e:
            logger.error(f"Metadata search failed: {str(e)}")
            return {"items": [], "total": 0, "error": str(e), "fallback_mode": True}

    async def query_knowledge_base(
        self, query: str, context_type: str = "medical", max_results: int = 10
    ) -> RAGnosticResponse:
        """Query knowledge base with enhanced error handling"""
        request = RAGnosticRequest(
            query=query, context_type=context_type, max_results=max_results
        )
        endpoint = f"{self.base_url}/api/v1/query"

        try:
            response_data = await self._make_request_with_resilience(
                "POST", endpoint, request.dict(), cache_enabled=True, cache_ttl=180
            )
            return RAGnosticResponse(**response_data)
        except Exception as e:
            logger.error(f"Knowledge base query failed: {str(e)}")
            # Return fallback response
            return RAGnosticResponse(
                results=[],
                metadata={"error": str(e), "fallback_mode": True},
                processing_time=0.0,
            )

    async def get_study_materials(
        self, topic: str, level: str = "undergraduate"
    ) -> list[dict[str, Any]]:
        """Get study materials with enhanced caching and error handling"""
        request = RAGnosticRequest(
            query=f"study materials for {topic}",
            context_type="educational",
            filters={"level": level},
        )
        endpoint = f"{self.base_url}/api/v1/study-materials"

        try:
            response_data = await self._make_request_with_resilience(
                "POST", endpoint, request.dict(), cache_enabled=True, cache_ttl=600
            )
            materials = response_data.get("materials", [])
            logger.info(
                f"Retrieved {len(materials)} study materials for topic: {topic}"
            )
            return materials
        except Exception as e:
            logger.error(f"Failed to get study materials for {topic}: {str(e)}")
            return []

    async def validate_medical_content(self, content: str) -> dict[str, Any]:
        """Validate medical content with improved error handling"""
        endpoint = f"{self.base_url}/api/v1/validate"
        payload = {"content": content}

        try:
            result = await self._make_request_with_resilience(
                "POST",
                endpoint,
                payload,
                cache_enabled=False,  # Don't cache validation results
            )
            return result
        except Exception as e:
            logger.error(f"Medical content validation failed: {str(e)}")
            return {
                "is_valid": False,
                "errors": [f"Validation service error: {str(e)}"],
                "fallback_mode": True,
            }

    async def batch_search(self, queries: list[str], **kwargs) -> list[dict[str, Any]]:
        """Perform multiple searches concurrently for improved performance"""
        tasks = [self.search_content(query, **kwargs) for query in queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions in batch results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch search failed for query {i}: {str(result)}")
                processed_results.append(
                    {"items": [], "total": 0, "error": str(result), "query_index": i}
                )
            else:
                processed_results.append(result)

        return processed_results

    def get_performance_metrics(self) -> dict[str, Any]:
        """Get client performance metrics"""
        uptime = (datetime.now() - self.metrics["last_reset"]).total_seconds()
        return {
            **self.metrics,
            "uptime_seconds": uptime,
            "cache_hit_rate": (
                self.metrics["cache_hits"]
                / max(1, self.metrics["cache_hits"] + self.metrics["cache_misses"])
            )
            * 100,
            "circuit_breaker_state": self.circuit_breaker.state,
        }

    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            "total_requests": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "circuit_breaker_trips": 0,
            "average_response_time": 0.0,
            "last_reset": datetime.now(),
        }
        self.cache.clear()
        logger.info("RAGnostic client metrics reset")

    async def health_check(self) -> dict[str, Any]:
        """Check RAGnostic service health"""
        endpoint = f"{self.base_url}/api/v1/health"
        try:
            result = await self._make_request_with_resilience(
                "GET", endpoint, cache_enabled=False
            )
            return {
                "status": "healthy",
                "service_response": result,
                "client_metrics": self.get_performance_metrics(),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "client_metrics": self.get_performance_metrics(),
            }

    async def close(self):
        """Close client with cleanup"""
        await self.client.aclose()
        self.cache.clear()
        logger.info("RAGnostic client connection closed and resources cleaned up")

        # Log final performance metrics
        metrics = self.get_performance_metrics()
        logger.info(
            f"Final client metrics - Requests: {metrics['total_requests']}, "
            f"Cache hit rate: {metrics['cache_hit_rate']:.1f}%, "
            f"Avg response time: {metrics['average_response_time']:.3f}s"
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    @asynccontextmanager
    async def batch_context(self):
        """Context manager for batch operations with optimized settings"""
        # Temporarily increase semaphore for batch operations
        original_semaphore = self.request_semaphore
        self.request_semaphore = asyncio.Semaphore(100)

        try:
            yield self
        finally:
            self.request_semaphore = original_semaphore
