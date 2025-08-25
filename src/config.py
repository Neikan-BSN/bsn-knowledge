"""
Configuration management for BSN Knowledge application
"""

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # API Configuration
    app_name: str = "BSN Knowledge API"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False)

    # OpenAI Configuration
    openai_api_key: str | None = Field(default=None)
    openai_model: str = Field(default="gpt-4")
    openai_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    openai_max_tokens: int = Field(default=2000, ge=1, le=8000)

    # RAGnostic Configuration - Enhanced
    ragnostic_base_url: str = Field(
        default="http://localhost:8000", env="RAGNOSTIC_BASE_URL"
    )
    ragnostic_api_key: str | None = Field(default=None, env="RAGNOSTIC_API_KEY")
    ragnostic_timeout: int = Field(default=30, env="RAGNOSTIC_TIMEOUT")

    # RAGnostic Client Performance Settings
    ragnostic_max_retries: int = Field(default=3, env="RAGNOSTIC_MAX_RETRIES")
    ragnostic_cache_ttl: int = Field(default=300, env="RAGNOSTIC_CACHE_TTL")
    ragnostic_connection_pool_size: int = Field(
        default=100, env="RAGNOSTIC_CONNECTION_POOL_SIZE"
    )
    ragnostic_circuit_breaker_failure_threshold: int = Field(
        default=5, env="RAGNOSTIC_CIRCUIT_BREAKER_FAILURE_THRESHOLD"
    )
    ragnostic_circuit_breaker_reset_timeout: int = Field(
        default=60, env="RAGNOSTIC_CIRCUIT_BREAKER_RESET_TIMEOUT"
    )

    # Content Generation Settings
    medical_accuracy_threshold: float = Field(
        default=0.95, env="MEDICAL_ACCURACY_THRESHOLD", ge=0.8, le=1.0
    )
    max_validation_attempts: int = Field(
        default=3, env="MAX_VALIDATION_ATTEMPTS", ge=1, le=10
    )
    content_generation_timeout: int = Field(
        default=120, env="CONTENT_GENERATION_TIMEOUT"
    )

    # Database Configuration
    database_url: str = Field(default="sqlite:///./data/bsn.db", env="DATABASE_URL")

    # Logging Configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    # Performance Configuration
    api_slow_request_threshold: float = Field(
        default=0.5, env="API_SLOW_REQUEST_THRESHOLD"
    )
    enable_gzip_compression: bool = Field(default=True, env="ENABLE_GZIP_COMPRESSION")
    gzip_minimum_size: int = Field(default=1000, env="GZIP_MINIMUM_SIZE")

    # CORS Configuration
    cors_origins: list[str] = Field(default=["*"], env="CORS_ORIGINS")

    # Monitoring and Health Check Settings
    enable_performance_monitoring: bool = Field(
        default=True, env="ENABLE_PERFORMANCE_MONITORING"
    )
    metrics_retention_hours: int = Field(default=24, env="METRICS_RETENTION_HOURS")

    model_config = {"env_file": ".env", "case_sensitive": False, "env_prefix": ""}

    def get_ragnostic_client_config(self) -> dict:
        """Get RAGnostic client configuration"""
        return {
            "base_url": self.ragnostic_base_url,
            "api_key": self.ragnostic_api_key,
            "max_retries": self.ragnostic_max_retries,
            "cache_ttl": self.ragnostic_cache_ttl,
            "connection_pool_size": self.ragnostic_connection_pool_size,
        }


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings"""
    return settings


def get_performance_config() -> dict:
    """Get performance monitoring configuration"""
    return {
        "slow_request_threshold": settings.api_slow_request_threshold,
        "enable_monitoring": settings.enable_performance_monitoring,
        "gzip_enabled": settings.enable_gzip_compression,
        "gzip_min_size": settings.gzip_minimum_size,
    }
