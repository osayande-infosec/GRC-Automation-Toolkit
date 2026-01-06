"""
Application Configuration
"""

from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "Compliance Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # API
    API_V1_PREFIX: str = "/api/v1"
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Database
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/compliance_db"
    
    # Redis (for caching and Celery)
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Authentication
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Integrations (API keys loaded from env)
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"
    
    OKTA_DOMAIN: str = ""
    OKTA_API_TOKEN: str = ""
    
    GITHUB_TOKEN: str = ""
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
