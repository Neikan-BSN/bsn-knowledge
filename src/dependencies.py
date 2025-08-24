"""
Dependency injection for BSN Knowledge services
"""
from functools import lru_cache
import logging

from .config import get_settings
from .services.ragnostic_client import RAGnosticClient
from .services.content_generation_service import ContentGenerationService
from .services.clinical_decision_support import ClinicalDecisionSupportService
from .services.analytics_service import AnalyticsService
from .assessment.competency_framework import AACNCompetencyFramework
from .generators.nclex_generator import NCLEXGenerator
from .generators.study_guide_generator import StudyGuideGenerator

logger = logging.getLogger(__name__)


@lru_cache()
def get_ragnostic_client() -> RAGnosticClient:
    """Get enhanced RAGnostic client instance with performance optimizations"""
    settings = get_settings()
    client = RAGnosticClient(
        base_url=settings.ragnostic_base_url,
        api_key=settings.ragnostic_api_key,
        max_retries=settings.ragnostic_max_retries,
        cache_ttl=settings.ragnostic_cache_ttl,
        connection_pool_size=settings.ragnostic_connection_pool_size
    )
    logger.info(f"Enhanced RAGnostic client initialized with caching (TTL={settings.ragnostic_cache_ttl}s)")
    return client


@lru_cache()
def get_content_generation_service() -> ContentGenerationService:
    """Get content generation service instance"""
    settings = get_settings()
    ragnostic_client = get_ragnostic_client()
    
    return ContentGenerationService(
        openai_api_key=settings.openai_api_key,
        ragnostic_client=ragnostic_client,
        model_name=settings.openai_model,
        temperature=settings.openai_temperature,
        max_tokens=settings.openai_max_tokens
    )


@lru_cache()
def get_clinical_decision_service() -> ClinicalDecisionSupportService:
    """Get clinical decision support service instance"""
    content_service = get_content_generation_service()
    return ClinicalDecisionSupportService(content_service)


@lru_cache()
def get_nclex_generator() -> NCLEXGenerator:
    """Get NCLEX question generator instance"""
    content_service = get_content_generation_service()
    return NCLEXGenerator(content_service)


@lru_cache()
def get_study_guide_generator() -> StudyGuideGenerator:
    """Get study guide generator instance"""
    content_service = get_content_generation_service()
    return StudyGuideGenerator(content_service)


@lru_cache()
def get_analytics_service() -> AnalyticsService:
    """Get analytics service instance with RAGnostic integration"""
    ragnostic_client = get_ragnostic_client()
    db_connection = None  # Would be injected in production
    
    service = AnalyticsService(ragnostic_client, db_connection)
    logger.info("Analytics service initialized")
    return service


@lru_cache()
def get_competency_framework() -> AACNCompetencyFramework:
    """Get AACN Competency Framework instance with RAGnostic integration"""
    ragnostic_client = get_ragnostic_client()
    framework = AACNCompetencyFramework(ragnostic_client)
    logger.info("AACN Competency Framework initialized")
    return framework


# FastAPI dependency functions with enhanced error handling
def get_content_service():
    """FastAPI dependency for content generation service"""
    try:
        return get_content_generation_service()
    except Exception as e:
        logger.error(f"Failed to initialize content generation service: {str(e)}")
        raise


def get_clinical_service():
    """FastAPI dependency for clinical decision support service"""
    return get_clinical_decision_service()


def get_quiz_generator():
    """FastAPI dependency for NCLEX generator"""
    return get_nclex_generator()


def get_guide_generator():
    """FastAPI dependency for study guide generator"""
    return get_study_guide_generator()


def get_analytics_service_dep():
    """FastAPI dependency for analytics service"""
    try:
        return get_analytics_service()
    except Exception as e:
        logger.error(f"Failed to initialize analytics service: {str(e)}")
        raise


# Enhanced health check dependency
def get_ragnostic_client_with_health():
    """Get RAGnostic client and perform health check"""
    client = get_ragnostic_client()
    
    async def health_checked_client():
        try:
            health_status = await client.health_check()
            if health_status["status"] != "healthy":
                logger.warning(f"RAGnostic service health check warning: {health_status}")
            return client
        except Exception as e:
            logger.error(f"RAGnostic health check failed: {str(e)}")
            # Return client anyway for graceful degradation
            return client
    
    return health_checked_client


def get_competency_framework_dep():
    """FastAPI dependency for competency framework"""
    return get_competency_framework()