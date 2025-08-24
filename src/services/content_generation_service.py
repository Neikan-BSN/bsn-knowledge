"""
Content Generation Service for BSN Knowledge
Integrates OpenAI with RAGnostic for educational content generation
"""
import logging
from typing import Any, Dict, List, Optional
import json
import asyncio
from datetime import datetime

import openai
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from .ragnostic_client import RAGnosticClient

logger = logging.getLogger(__name__)


class ContentGenerationError(Exception):
    """Custom exception for content generation errors"""
    pass


class GenerationRequest(BaseModel):
    """Base request model for content generation"""
    topic: str
    difficulty: str = Field(default="intermediate", pattern="^(beginner|intermediate|advanced)$")
    count: int = Field(default=10, ge=1, le=50)
    context_filters: Optional[Dict[str, Any]] = None
    include_rationales: bool = True
    medical_accuracy_threshold: float = Field(default=0.95, ge=0.8, le=1.0)


class MedicalValidationResult(BaseModel):
    """Result of medical content validation"""
    is_accurate: bool
    confidence_score: float
    evidence_citations: List[str] = []
    potential_issues: List[str] = []
    umls_concepts: List[str] = []


class ContentGenerationService:
    """
    Comprehensive content generation service that combines:
    - OpenAI for content generation
    - RAGnostic for medical content validation and enrichment
    - Evidence-based medical accuracy verification
    """
    
    def __init__(
        self, 
        openai_api_key: str,
        ragnostic_client: RAGnosticClient,
        model_name: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 2000
    ):
        self.openai_client = AsyncOpenAI(api_key=openai_api_key)
        self.ragnostic = ragnostic_client
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        logger.info(f"Content generation service initialized with model: {model_name}")

    async def _get_enriched_context(
        self, 
        topic: str, 
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve enriched medical context from RAGnostic
        """
        try:
            # Search for relevant content in RAGnostic
            search_results = await self.ragnostic.search_content(
                query=topic,
                filters=filters,
                limit=5
            )
            
            # Get UMLS concepts if available
            context_data = {
                "relevant_content": search_results.get("items", []),
                "medical_concepts": [],
                "evidence_base": []
            }
            
            # Extract medical concepts and evidence
            for item in search_results.get("items", []):
                if "umls_concepts" in item:
                    context_data["medical_concepts"].extend(item["umls_concepts"])
                if "evidence_citations" in item:
                    context_data["evidence_base"].extend(item["evidence_citations"])
            
            return context_data
            
        except Exception as e:
            logger.warning(f"Failed to get enriched context for {topic}: {str(e)}")
            return {"relevant_content": [], "medical_concepts": [], "evidence_base": []}

    async def _validate_medical_accuracy(
        self, 
        content: str, 
        topic: str,
        threshold: float = 0.95
    ) -> MedicalValidationResult:
        """
        Validate medical accuracy using RAGnostic and evidence base
        """
        try:
            # Use RAGnostic's validation endpoint
            validation_result = await self.ragnostic.validate_medical_content(content)
            
            # Extract validation metrics
            is_accurate = validation_result.get("is_valid", False)
            confidence = validation_result.get("confidence_score", 0.0)
            
            # Get evidence citations from related content
            search_results = await self.ragnostic.search_content(
                query=f"evidence validation {topic}",
                limit=3
            )
            
            citations = []
            umls_concepts = []
            issues = []
            
            for item in search_results.get("items", []):
                if "citations" in item:
                    citations.extend(item["citations"])
                if "umls_concepts" in item:
                    umls_concepts.extend(item["umls_concepts"])
            
            # Check if validation meets threshold
            if confidence < threshold:
                issues.append(f"Medical accuracy confidence {confidence:.2f} below threshold {threshold}")
                is_accurate = False
            
            return MedicalValidationResult(
                is_accurate=is_accurate and confidence >= threshold,
                confidence_score=confidence,
                evidence_citations=citations[:10],  # Limit citations
                potential_issues=issues,
                umls_concepts=umls_concepts[:20]  # Limit concepts
            )
            
        except Exception as e:
            logger.error(f"Medical validation failed for topic {topic}: {str(e)}")
            return MedicalValidationResult(
                is_accurate=False,
                confidence_score=0.0,
                potential_issues=[f"Validation service error: {str(e)}"]
            )

    async def _generate_with_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Optional[str] = None
    ) -> str:
        """
        Generate content using OpenAI with error handling and retries
        """
        max_retries = 3
        retry_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
                
                kwargs = {
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens
                }
                
                if response_format:
                    kwargs["response_format"] = {"type": response_format}
                
                response = await self.openai_client.chat.completions.create(**kwargs)
                
                return response.choices[0].message.content.strip()
                
            except openai.RateLimitError:
                wait_time = retry_delay * (2 ** attempt)
                logger.warning(f"Rate limit exceeded, waiting {wait_time}s before retry {attempt + 1}")
                await asyncio.sleep(wait_time)
                
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"OpenAI generation failed after {max_retries} attempts: {str(e)}")
                    raise ContentGenerationError(f"Failed to generate content: {str(e)}")
                await asyncio.sleep(retry_delay)
        
        raise ContentGenerationError("Max retries exceeded for content generation")

    async def generate_content_with_validation(
        self,
        request: GenerationRequest,
        system_prompt: str,
        user_prompt_template: str,
        response_format: Optional[str] = None,
        max_validation_attempts: int = 3
    ) -> Dict[str, Any]:
        """
        Generate content with medical accuracy validation loop
        """
        # Get enriched context from RAGnostic
        context = await self._get_enriched_context(
            request.topic, 
            request.context_filters
        )
        
        # Format user prompt with context
        user_prompt = user_prompt_template.format(
            topic=request.topic,
            difficulty=request.difficulty,
            count=request.count,
            medical_context=json.dumps(context, indent=2)
        )
        
        # Generation and validation loop
        for attempt in range(max_validation_attempts):
            try:
                # Generate content
                generated_content = await self._generate_with_openai(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=response_format
                )
                
                # Validate medical accuracy
                validation = await self._validate_medical_accuracy(
                    content=generated_content,
                    topic=request.topic,
                    threshold=request.medical_accuracy_threshold
                )
                
                if validation.is_accurate:
                    logger.info(f"Content generated and validated successfully for {request.topic}")
                    return {
                        "content": generated_content,
                        "validation": validation.dict(),
                        "context": context,
                        "generation_metadata": {
                            "model": self.model_name,
                            "temperature": self.temperature,
                            "validation_attempts": attempt + 1,
                            "generated_at": datetime.utcnow().isoformat()
                        }
                    }
                else:
                    logger.warning(
                        f"Generated content failed validation (attempt {attempt + 1}): "
                        f"confidence={validation.confidence_score:.2f}, "
                        f"issues={validation.potential_issues}"
                    )
                    
                    if attempt < max_validation_attempts - 1:
                        # Enhance prompt with validation feedback for retry
                        user_prompt += f"\n\nPrevious attempt had validation issues: {validation.potential_issues}. Please ensure medical accuracy and include proper evidence."
                    
            except Exception as e:
                logger.error(f"Content generation attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_validation_attempts - 1:
                    raise
        
        # If all validation attempts failed
        raise ContentGenerationError(
            f"Failed to generate medically accurate content for {request.topic} "
            f"after {max_validation_attempts} attempts"
        )

    async def close(self):
        """Clean up resources"""
        await self.openai_client.close()
        logger.info("Content generation service closed")