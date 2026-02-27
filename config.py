import os
from datetime import timedelta


class BaseConfig:
    SECRET_KEY = os.environ.get("SECURESHARE_SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SECURESHARE_DATABASE_URI",
        "sqlite:///secureshare.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  # Overridden in production
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = False
    WTF_CSRF_TIME_LIMIT = None

    # Directory where encrypted files are stored
    STORAGE_DIR = os.path.abspath(os.environ.get("SECURESHARE_STORAGE_DIR", "storage"))

    # AES-256 key for file encryption (32 bytes base64 or hex in production)
    FILE_ENCRYPTION_KEY = os.environ.get(
        "SECURESHARE_FILE_KEY",
        # Development-only key – must be overridden in production
        "0" * 64,
    )

    # Rate limiting
    RATELIMIT_DEFAULT = "100 per hour"


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development").lower()
    return config_by_name.get(env, DevelopmentConfig)

