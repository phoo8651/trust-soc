from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    POLICY_SIGNING_SECRET: str
    JOB_SIGNING_SECRET: str

    # Optional
    ENV_STATE: str = "dev"
    ACCESS_TOKEN_TTL_SECONDS: int = 3600
    AES_GCM_KEY_HEX: str | None = None

    # LLM Config
    LLM_API_URL: str = "http://localhost:11434/api/generate"
    LLM_MODEL_NAME: str = "mistral"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
