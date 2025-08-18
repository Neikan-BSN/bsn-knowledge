from typing import Any, Dict, List, Optional
import logging

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class RAGnosticRequest(BaseModel):
    query: str
    context_type: str = "medical"
    max_results: int = 10
    filters: Dict[str, Any] = {}


class RAGnosticResponse(BaseModel):
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    processing_time: float


class RAGnosticClient:
    """Client for interacting with RAGnostic pipeline API"""
    
    def __init__(self, base_url: str = "http://localhost:8000", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        self.client = httpx.AsyncClient(timeout=30.0, headers=headers)
        logger.info(f"Initialized RAGnostic client with base URL: {base_url}")

    async def search_content(
        self, 
        query: str, 
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Search enriched content from RAGnostic pipeline
        
        Searches against UMLS-enriched, multi-embedded content
        """
        try:
            endpoint = f"{self.base_url}/api/v1/search"
            payload = {
                "query": query,
                "filters": filters or {},
                "limit": limit,
                "offset": offset
            }
            
            response = await self.client.post(endpoint, json=payload)
            response.raise_for_status()
            
            results = response.json()
            logger.info(f"Search completed: {len(results.get('items', []))} results")
            return results
            
        except Exception as e:
            logger.error(f"Search failed for query '{query}': {str(e)}")
            raise

    async def get_concept_graph(self, concept_id: str) -> Dict[str, Any]:
        """Get prerequisite and relationship graph"""
        try:
            endpoint = f"{self.base_url}/api/v1/concepts/{concept_id}/graph"
            
            response = await self.client.get(endpoint)
            response.raise_for_status()
            
            graph_data = response.json()
            logger.info(f"Retrieved concept graph for {concept_id}")
            return graph_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve concept graph for {concept_id}: {str(e)}")
            raise

    async def get_content_by_metadata(
        self, 
        metadata_filters: Dict[str, Any],
        sort_by: Optional[str] = "relevance",
        limit: int = 50
    ) -> Dict[str, Any]:
        """Retrieve content by rich metadata"""
        try:
            endpoint = f"{self.base_url}/api/v1/content/metadata"
            payload = {
                "filters": metadata_filters,
                "sort_by": sort_by,
                "limit": limit
            }
            
            response = await self.client.post(endpoint, json=payload)
            response.raise_for_status()
            
            results = response.json()
            logger.info(f"Metadata search completed: {len(results.get('items', []))} results")
            return results
            
        except Exception as e:
            logger.error(f"Metadata search failed: {str(e)}")
            raise

    async def query_knowledge_base(
        self, query: str, context_type: str = "medical", max_results: int = 10
    ) -> RAGnosticResponse:
        request = RAGnosticRequest(
            query=query, context_type=context_type, max_results=max_results
        )

        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/query", json=request.dict()
            )
            response.raise_for_status()
            return RAGnosticResponse(**response.json())
        except httpx.RequestError:
            raise ConnectionError("Failed to connect to RAGnostic service")
        except httpx.HTTPStatusError as e:
            raise Exception(f"RAGnostic API error: {e.response.status_code}")

    async def get_study_materials(
        self, topic: str, level: str = "undergraduate"
    ) -> List[Dict[str, Any]]:
        request = RAGnosticRequest(
            query=f"study materials for {topic}",
            context_type="educational",
            filters={"level": level},
        )

        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/study-materials", json=request.dict()
            )
            response.raise_for_status()
            return response.json().get("materials", [])
        except Exception:
            return []

    async def validate_medical_content(self, content: str) -> Dict[str, Any]:
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/validate", json={"content": content}
            )
            response.raise_for_status()
            return response.json()
        except Exception:
            return {"is_valid": False, "errors": ["Validation service unavailable"]}

    async def close(self):
        await self.client.aclose()
        logger.info("RAGnostic client connection closed")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
