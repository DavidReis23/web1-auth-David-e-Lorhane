import logging
import os
from datetime import datetime

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger("app")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def mask_password(password: str) -> str:
    """Mascara a senha, mantendo só 2 primeiros caracteres."""
    if not password:
        return "***"
    return password[:2] + "*" * max(1, (len(password) - 2))

# DEBUG rules (somente quando LOG_LEVEL=DEBUG)
def log_login_attempt(username: str, ip: str, password: str):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            f"Tentativa de login | user={username} | ip={ip} | senha={mask_password(password)}"
        )

def log_login_result(username: str, success: bool, reason: str = ""):
    if logger.isEnabledFor(logging.DEBUG):
        status = "SUCESSO" if success else "FALHA"
        msg = f"Resultado do login | user={username} | status={status}"
        if reason:
            msg += f" | motivo={reason}"
        logger.debug(msg)

def log_jwt_issued(payload: dict):
    if logger.isEnabledFor(logging.DEBUG):
        # Nunca logar segredo do JWT!
        logger.debug(f"JWT emitido | payload={payload}")

def log_protected_access(username: str = None, error: str = None):
    if logger.isEnabledFor(logging.DEBUG):
        if username:
            logger.debug(f"Acesso permitido | user={username}")
        else:
            logger.debug(f"Acesso negado | erro={error}")
