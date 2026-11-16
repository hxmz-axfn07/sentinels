from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.services.detection.config import DetectionConfig

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    database_url: str = "sqlite:///./sentinel.db"
    frontend_origin: str = "http://localhost:5174"
    upload_storage_dir: Path = PROJECT_ROOT / "storage" / "pcaps"
    model_storage_dir: Path = PROJECT_ROOT / "storage" / "models"
    max_upload_size_bytes: int = 104_857_600
    ml_max_training_samples: int = Field(default=50_000, ge=20, le=1_000_000)
    detection_config: DetectionConfig = Field(default_factory=DetectionConfig)

    @field_validator("upload_storage_dir", mode="before")
    @classmethod
    def resolve_upload_storage_dir(cls, value: str | Path) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else PROJECT_ROOT / path

    @field_validator("model_storage_dir", mode="before")
    @classmethod
    def resolve_model_storage_dir(cls, value: str | Path) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else PROJECT_ROOT / path

    @field_validator("max_upload_size_bytes")
    @classmethod
    def validate_max_upload_size(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_upload_size_bytes must be positive")
        return value

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        nested_model_default_partial_update=True,
        extra="ignore",
    )


settings = Settings()
