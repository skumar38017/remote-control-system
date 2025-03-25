#  controller/settings.py

from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # General Settings
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_HOSTS: List[str] = ["*"]
    SECRET_KEY: str = "7F771E5A77468E8884E34BF537158"
    CORS_ORIGINS: List[str] = ["*"]
    DEV_MODE: bool = False
    
    # Redis Settings
    REDIS_HOST: str = "192.168.192.2"
    REDIS_PORT: int = 6379      
    REDIS_USER: str = "Neon-Studioz-Holi-T25"
    REDIS_PASSWORD: str = "Neon-Studioz-Holi-T25"
    REDIS_DB_CACHE: int = 0
    REDIS_DB_RESULT: int = 1
    REDIS_DB_BROKER: int = 2
    REDIS_DB_SCHEDULER: int = 3
    REDIS_DB_QUEUE: int = 4
    REDIS_DB_TASKS: int = 5
