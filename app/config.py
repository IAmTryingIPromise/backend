import os
from pydantic import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg2://savvas:Savvas123!@localhost:5432/security_db"
    secret_key: str = "your-secret-key-here"
    api_prefix: str = "/api/v1"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True
    log_level: str = "INFO"
    nvd_api_key: str = "4a116d75-367e-4c9b-90de-904679b57060"
    environment: str = "development"

    class Config:
        env_file = ".env"

settings = Settings()