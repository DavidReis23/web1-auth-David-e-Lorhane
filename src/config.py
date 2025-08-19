import os
from dotenv import load_dotenv

# Carregar variáveis do .env
load_dotenv()

class Config:
    # Logs
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # JWT
    JWT_SECRET = os.getenv("JWT_SECRET", "default-jwt-secret")
    JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", 15))

    # Flask
    SECRET_KEY_SESSION = os.getenv("SECRET_KEY_SESSION", "default-session-key")
    FLASK_ENV = os.getenv("FLASK_ENV", "production")
