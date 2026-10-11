import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, USERS_FILE, BASE_DIR

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

# ── Pydantic Models ──────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    password: str
    allowed_dirs: Optional[list[str]] = None  # e.g. ["/home/user", "/var/log"]

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# ── User Store (JSON file) ───────────────────────────────

def _load_users() -> dict:
    """Load users from JSON file. Returns empty dict if file doesn't exist."""
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to read users file: %s", e)
        return {}

def _save_users(users: dict):
    """Persist users to JSON file."""
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    tmp.replace(USERS_FILE)

def get_user(username: str) -> Optional[dict]:
    return _load_users().get(username)

def create_user(username: str, password: str, role: str = "user", allowed_dirs: Optional[list[str]] = None) -> dict:
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    users = _load_users()
    if username in users:
        raise HTTPException(status_code=409, detail="Username already exists")

    # Admins get full filesystem access by default;
    # regular users are restricted to their allowed_dirs or BASE_DIR
    if allowed_dirs is None and role == "admin":
        allowed_dirs = ["/"]
    elif allowed_dirs is None:
        allowed_dirs = [str(BASE_DIR.resolve())]

    users[username] = {
        "username": username,
        "hashed_password": bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
        "role": role,
        "allowed_dirs": [str(Path(d).resolve()) for d in allowed_dirs],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_users(users)
    logger.info("User '%s' created with role '%s'", username, role)
    return users[username]

def delete_user(username: str):
    users = _load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[username]
    _save_users(users)
    logger.info("User '%s' deleted", username)

def list_users() -> list[dict]:
    users = _load_users()
    return [
        {
            "username": u["username"],
            "role": u["role"],
            "allowed_dirs": u.get("allowed_dirs", ["/"]),
            "created_at": u["created_at"],
        }
        for u in users.values()
    ]

def is_setup_done() -> bool:
    return len(_load_users()) > 0

# ── Password Helpers ─────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

# ── JWT ──────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    """Decode and verify a JWT. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token: missing subject")
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

# ── FastAPI Dependencies ─────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_token(credentials.credentials)
    user = get_user(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── HMAC Download Tokens (single-use, short-lived) ────────

def create_download_token(path: str, user: dict) -> str:
    """Create a short-lived, path-bound HMAC token for file downloads.

    This avoids putting the JWT in the URL (which would appear in logs,
    browser history, and referrer headers).
    """
    exp = int(time.time()) + 60  # 60-second expiry
    payload = f"{user['username']}:{path}:{exp}"
    sig = hmac.new(
        SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    # Format: username:exp:signature
    import base64
    token_b64 = base64.urlsafe_b64encode(
        f"{user['username']}:{exp}:{sig}".encode()
    ).decode()
    return token_b64


def verify_download_token(token_b64: str, path: str) -> Optional[str]:
    """Verify an HMAC download token and return the username if valid.
    Returns None if the token is invalid or expired.
    """
    try:
        import base64
        decoded = base64.urlsafe_b64decode(token_b64).decode()
        username, exp_str, sig = decoded.split(":", 2)
        exp = int(exp_str)

        # Check expiry
        if time.time() > exp:
            return None

        # Verify HMAC
        expected_payload = f"{username}:{path}:{exp}"
        expected_sig = hmac.new(
            SECRET_KEY.encode(), expected_payload.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return None

        return username
    except Exception:
        return None
