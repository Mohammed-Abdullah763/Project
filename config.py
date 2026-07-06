"""
app/core/config.py
──────────────────
All settings loaded from environment variables via pydantic-settings.
Never hardcode secrets — always use .env.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ────────────────────────────────────────────────────────────────
    APP_NAME: str = "Study Mind API"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"          # development | staging | production
    DEBUG: bool = True

    # ── Server ─────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "https://studymind.vercel.app",
    ]

    # ── Database ───────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./studymind.db"
    # For PostgreSQL: postgresql+asyncpg://user:pass@host:5432/dbname

    # ── Auth / JWT ─────────────────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_USE_32_CHAR_MINIMUM"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60          # 1 hour
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30            # 30 days

    # ── Anthropic ──────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-6"
    ANTHROPIC_MAX_TOKENS: int = 2000

    # ── File uploads ───────────────────────────────────────────────────────
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 10

    # ── Email (for verification / password reset) ──────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "noreply@studymind.app"
    EMAIL_FROM_NAME: str = "Study Mind"

    # ── Redis (for token blacklist / rate limiting) ─────────────────────────
    REDIS_URL: str = "redis://localhost:6379"

    # ── Rate limiting ──────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = 60
    AI_RATE_LIMIT_PER_MINUTE: int = 20

    # ── Sentry (production error tracking) ────────────────────────────────
    SENTRY_DSN: str = ""

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.APP_ENV == "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
