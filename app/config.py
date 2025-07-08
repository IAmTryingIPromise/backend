import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    database_url: str = os.getenv("DATABASE_URL", "postgresql://username:password@localhost:5432/your_database")
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    api_host: str = os.getenv("API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("API_PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "True").lower() == "true"
    external_api_key: str = os.getenv("EXTERNAL_API_KEY", "your-external-api-key")
    external_api_base_url: str = os.getenv("EXTERNAL_API_BASE_URL", "https://api.example.com")

    class Config:
        env_file = ".env"

settings = Settings()