import logging
from pathlib import Path
from typing import Optional

from fastapi import (
    FastAPI, HTTPException, Depends, UploadFile, File, Query,
    WebSocket, WebSocketDisconnect, Request,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import (
    HOST, PORT, DATA_DIR, WEB_DIR, MAX_UPLOAD_SIZE, TERM_COLS, TERM_ROWS,
    CORS_ORIGINS,
)
from .auth import (
    is_setup_done, get_user, create_user, delete_user, list_users,
    verify_password, create_access_token, verify_token,
    get_current_user, require_admin,
    create_download_token, verify_download_token,
    UserCreate, UserLogin, TokenResponse, UserResponse,
)
from .file_service import (
    list_directory, create_directory, delete_path, rename_path,
    read_file_text, write_file_text, get_file_for_download, save_upload,
)
from .terminal_service import TerminalSession
from .system_service import get_system_stats
from .log_service import get_logs, install_log_handler
from .security_service import get_security_status
from .middleware.rate_limiter import limiter, LOGIN_LIMIT, SETUP_LIMIT, USER_CREATE_LIMIT
from .middleware.security_headers import SecurityHeadersMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)
install_log_handler()

app = FastAPI(title="Remote Admin", version="2.0.0")

# ── Global error handler ────────────────────────────────
@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s %s: %s", request.method, request.url, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": str(exc)})

# ── Middleware ───────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=bool(CORS_ORIGINS) and "*" not in CORS_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Wire up the rate limiter with the FastAPI app state
app.state.limiter = limiter


@app.middleware("http")
async def log_api_requests(request: Request, call_next):
    """Record API activity without logging query strings or credentials."""
    import time

    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        if request.url.path.startswith("/api/"):
            logger.exception("HTTP %s %s failed", request.method, request.url.path)
        raise
    if request.url.path.startswith("/api/") and request.url.path != "/api/logs":
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "HTTP %s %s -> %d (%.1f ms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
    return response

# ── Download auth (HMAC token OR JWT Bearer) ────────────
async def _download_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    token: Optional[str] = Query(None),
    path: str = Query(...),
) -> dict:
    """Authenticate download requests.

    Accepts either:
    1. A JWT in the Authorization header (standard API call)
    2. A short-lived HMAC token as ?token= query param (browser download links)
    """
    # Try HMAC download token first (query param)
    if token and path:
        username = verify_download_token(token, path)
        if username:
            user = get_user(username)
            if user:
                return user

    # Fall back to JWT Bearer
    if credentials:
        try:
            payload = verify_token(credentials.credentials)
            user = get_user(payload["sub"])
            if user:
                return user
        except Exception:
            pass

    raise HTTPException(status_code=401, detail="Not authenticated or token expired")


# ── Startup ─────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Remote Admin v2.0 starting on %s:%d", HOST, PORT)
    logger.info("Base directory: %s", Path("/").resolve())
    logger.info("Data directory: %s", DATA_DIR.resolve())


# ═══════════════════════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════════════════════

@app.post("/api/auth/setup")
@limiter.limit(SETUP_LIMIT)
async def setup(request: Request, data: UserCreate):
    """One-time admin account creation. Only works when no users exist."""
    if is_setup_done():
        raise HTTPException(status_code=400, detail="Setup already completed. Use login.")
    create_user(data.username, data.password, role="admin", allowed_dirs=data.allowed_dirs)
    return {"message": "Admin account created. You can now log in."}


@app.post("/api/auth/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT)
async def login(request: Request, data: UserLogin):
    """Authenticate and receive a JWT."""
    user = get_user(data.username)
    if not user or not verify_password(data.password, user["hashed_password"]):
        logger.warning("Failed login for user '%s' from %s", data.username, request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    logger.info("User '%s' signed in from %s", user["username"], request.client.host if request.client else "unknown")
    return TokenResponse(
        access_token=token,
        user=UserResponse(username=user["username"], role=user["role"]),
    )


@app.get("/api/auth/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    return UserResponse(username=user["username"], role=user["role"])


@app.get("/api/auth/setup-status")
async def setup_status():
    """Check whether initial setup has been completed (no auth required)."""
    return {"setup_done": is_setup_done()}


# ── User management (admin only) ────────────────────────

@app.get("/api/auth/users")
async def get_users(user: dict = Depends(require_admin)):
    return list_users()


@app.post("/api/auth/users", status_code=201)
@limiter.limit(USER_CREATE_LIMIT)
async def add_user(request: Request, data: UserCreate, admin: dict = Depends(require_admin)):
    create_user(data.username, data.password, role="user", allowed_dirs=data.allowed_dirs)
    return {"message": f"User '{data.username}' created"}


@app.delete("/api/auth/users/{username}")
async def remove_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    delete_user(username)
    return {"message": f"User '{username}' deleted"}


# ── Secure download token generation ────────────────────

@app.get("/api/files/download-token")
async def get_download_token(
    path: str = Query(..., description="File path to generate token for"),
    user: dict = Depends(get_current_user),
):
    """Generate a short-lived HMAC token for a file download.

    The client uses this token in the download URL instead of the JWT,
    preventing the JWT from appearing in browser history and server logs.
    """
    # Verify the user has access to this path
    from .file_service import get_file_for_download as _check
    _check(path, user=user)

    token = create_download_token(path, user)
    return {"token": token, "expires_in": 60}


# ═══════════════════════════════════════════════════════════
#  FILE ROUTES
# ═══════════════════════════════════════════════════════════

@app.get("/api/files/list")
async def api_list_files(
    path: str = Query("/", description="Absolute directory path to list"),
    user: dict = Depends(get_current_user),
):
    return list_directory(path, user=user)


@app.post("/api/files/mkdir")
async def api_mkdir(request: dict, user: dict = Depends(get_current_user)):
    if "path" not in request:
        raise HTTPException(status_code=400, detail="Missing 'path' field")
    return create_directory(request["path"], user=user)


@app.delete("/api/files/delete")
async def api_delete(
    path: str = Query(..., description="Path to delete"),
    user: dict = Depends(get_current_user),
):
    return delete_path(path, user=user)


@app.post("/api/files/rename")
async def api_rename(request: dict, user: dict = Depends(get_current_user)):
    for key in ("old_path", "new_path"):
        if key not in request:
            raise HTTPException(status_code=400, detail=f"Missing '{key}' field")
    return rename_path(request["old_path"], request["new_path"], user=user)


@app.get("/api/files/read")
async def api_read_file(
    path: str = Query(..., description="File path to read"),
    user: dict = Depends(get_current_user),
):
    content = await read_file_text(path, user=user)
    return {"content": content, "path": path}


@app.post("/api/files/write")
async def api_write_file(request: dict, user: dict = Depends(get_current_user)):
    for key in ("path", "content"):
        if key not in request:
            raise HTTPException(status_code=400, detail=f"Missing '{key}' field")
    return await write_file_text(request["path"], request["content"], user=user)


@app.post("/api/files/upload")
async def api_upload(
    file: UploadFile = File(...),
    path: str = Query("/", description="Target directory"),
    user: dict = Depends(get_current_user),
):
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum upload size is {MAX_UPLOAD_SIZE // (1024*1024)} MB.",
        )
    return save_upload(path, file.filename or "untitled", content, user=user)


@app.get("/api/files/download")
async def api_download(
    path: str = Query(..., description="File path to download"),
    user: dict = Depends(_download_auth),
):
    file_path = get_file_for_download(path, user=user)
    return FileResponse(str(file_path), filename=file_path.name)


# ═══════════════════════════════════════════════════════════
#  WEBSOCKET TERMINAL
# ═══════════════════════════════════════════════════════════

@app.websocket("/ws/terminal")
async def terminal_websocket(
    ws: WebSocket,
    token: str = Query(...),
    cols: int = Query(TERM_COLS, ge=2, le=1000),
    rows: int = Query(TERM_ROWS, ge=1, le=500),
):
    """
    WebSocket endpoint for the interactive terminal.

    Protocol:
    - Client sends: raw bytes (keystrokes/paste) OR text frame with "resize:COLS:ROWS"
    - Server sends: raw bytes (terminal output)
    """
    # Verify JWT before accepting
    try:
        payload = verify_token(token)
        user = get_user(payload["sub"])
        if user is None:
            raise ValueError("User not found")
    except Exception:
        await ws.close(code=4001, reason="Unauthorized")
        return

    if user.get("role") != "admin":
        logger.warning("Terminal access denied for non-admin user '%s'", user["username"])
        await ws.close(code=4003, reason="Administrator access required")
        return

    # Origin check — prevent CSRF from other websites
    origin = ws.headers.get("origin", "")
    host_header = ws.headers.get("host", "")
    expected_origins = {f"http://{host_header}", f"https://{host_header}"}
    # Allow connections with no origin (non-browser clients like curl)
    if origin and origin not in expected_origins:
        logger.warning("Rejected WebSocket from unexpected origin: %s", origin)
        await ws.close(code=4003, reason="Forbidden origin")
        return

    await ws.accept()
    # Start at the browser's already-fitted size so PowerShell/PSReadLine never
    # renders its first prompt against the narrow fallback dimensions.
    session = TerminalSession(ws, user["username"], cols=cols, rows=rows)
    await session.start()

    try:
        while session._running:
            msg = await ws.receive()

            if msg["type"] == "websocket.disconnect":
                break

            if msg["type"] == "websocket.receive":
                text_data = msg.get("text")
                binary_data = msg.get("bytes")
                # Handle text frames for resize commands
                if text_data is not None and text_data.startswith("resize:"):
                    try:
                        _, cols, rows = text_data.split(":")
                        await session.resize(int(cols), int(rows))
                    except (ValueError, AttributeError):
                        pass
                # Handle binary frames (terminal input)
                elif binary_data is not None:
                    await session.write(binary_data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("WebSocket error: %s", e)
    finally:
        await session.cleanup()


# ═══════════════════════════════════════════════════════════
#  SYSTEM MONITORING
# ═══════════════════════════════════════════════════════════

@app.get("/api/system/stats")
async def api_system_stats(user: dict = Depends(get_current_user)):
    return get_system_stats()


@app.get("/api/logs")
async def api_logs(
    limit: int = Query(250, ge=1, le=1000),
    level: Optional[str] = Query(None, pattern="^(INFO|WARNING|ERROR)$"),
    search: Optional[str] = Query(None, max_length=200),
    admin: dict = Depends(require_admin),
):
    return get_logs(limit=limit, level=level, search=search)


@app.get("/api/security/status")
async def api_security_status(
    request: Request,
    admin: dict = Depends(require_admin),
):
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    is_https = request.url.scheme == "https" or forwarded_proto == "https"
    return get_security_status(is_https=is_https)


# ═══════════════════════════════════════════════════════════
#  STATIC FILES & SPA FALLBACK
# ═══════════════════════════════════════════════════════════

# Serve frontend assets (JS, CSS, fonts for offline use)
ASSETS_DIR = WEB_DIR / "assets"
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# Serve web root as static (for index.html direct access)
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR), html=True), name="static")


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    """Serve index.html for any non-API route (SPA client-side routing)."""
    index = WEB_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(
        {"error": "Frontend not found. Build the web/ directory first."},
        status_code=404,
    )


# ── Direct Run ──────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host=HOST, port=PORT, reload=True)
