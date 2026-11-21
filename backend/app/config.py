import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "8000"))
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,*"
    )

    TSHARK_PATH: str = os.environ.get(
        "TSHARK_PATH",
        r"C:\Program Files\Wireshark\tshark.exe" if os.name == "nt" else "tshark"
    )
    DEFAULT_INTERFACE: str = os.environ.get("DEFAULT_INTERFACE", "Wi-Fi" if os.name == "nt" else "eth0")

    SQLITE_DB_PATH: str = "data/netscope.db"
    UPLOAD_DIR: str = "uploads"
    LOG_DIR: str = "logs"

    MAX_BUFFERED_PACKETS: int = 5000
    MAX_UPLOAD_SIZE_MB: int = 15
    GEMINI_API_KEY: str = ""

    # Supabase Configuration
    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""
    SUPABASE_SERVICE_KEY: str = ""
    SUPABASE_JWT_SECRET: str = ""

    @property
    def has_supabase(self) -> bool:
        return bool(self.SUPABASE_URL and (self.SUPABASE_KEY or self.SUPABASE_SERVICE_KEY))

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    @property
    def db_file_path(self) -> Path:
        p = Path(self.SQLITE_DB_PATH)
        return p if p.is_absolute() else BACKEND_ROOT / p

    @property
    def uploads_path(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        return p if p.is_absolute() else BACKEND_ROOT / p

    @property
    def logs_path(self) -> Path:
        p = Path(self.LOG_DIR)
        return p if p.is_absolute() else BACKEND_ROOT / p


settings = Settings()

# Ensure directories exist
settings.db_file_path.parent.mkdir(parents=True, exist_ok=True)
settings.uploads_path.mkdir(parents=True, exist_ok=True)
settings.logs_path.mkdir(parents=True, exist_ok=True)
