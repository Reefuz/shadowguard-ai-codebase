import os
from dataclasses import dataclass
from dotenv import load_dotenv
load_dotenv()

@dataclass(frozen=True)
class Settings:
    database_url: str | None = os.getenv("DATABASE_URL")
    api_key: str | None = os.getenv("SHADOWGUARD_API_KEY")
    environment: str = os.getenv("ENVIRONMENT", "development")
    cors_origins: tuple[str, ...] = tuple(x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if x.strip())
    disable_docs: bool = os.getenv("DISABLE_DOCS", "false").lower() == "true"

settings = Settings()
