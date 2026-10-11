import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Security ──────────────────────────────────────────────
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "CHANGE-ME-IN-PRODUCTION-USE-openssl-rand-hex-32",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

if SECRET_KEY == "CHANGE-ME-IN-PRODUCTION-USE-openssl-rand-hex-32":
    logger.warning(
        "Using default SECRET_KEY. Set the SECRET_KEY environment variable for production!"
    )

# ── Server ────────────────────────────────────────────────
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]

# ── Paths ─────────────────────────────────────────────────
import sys as _sys
_DEFAULT_BASE = "/" if _sys.platform != "win32" else str(Path(__file__).resolve().parent.parent)
BASE_DIR = Path(os.environ.get("BASE_DIR", _DEFAULT_BASE))
DATA_DIR = Path(os.environ.get(
    "DATA_DIR", str(Path(__file__).resolve().parent.parent / "data")
))
USERS_FILE = DATA_DIR / "users.json"
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

# ── File Upload ───────────────────────────────────────────
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MB
EDITOR_MAX_SIZE = 5 * 1024 * 1024  # 5 MB — max file size for inline editing

# -- Terminal ---------------------------------------------
import sys

if sys.platform == "win32":
    DEFAULT_SHELL = os.environ.get("SHELL", "powershell.exe")
else:
    DEFAULT_SHELL = os.environ.get("SHELL", "/bin/bash")
TERM_COLS = 80
TERM_ROWS = 24
