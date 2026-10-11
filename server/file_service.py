import logging
import shutil
from pathlib import Path
from typing import Optional

from fastapi import HTTPException

from .config import BASE_DIR, EDITOR_MAX_SIZE

logger = logging.getLogger(__name__)

# ── Path Safety ──────────────────────────────────────────


def _resolve_path(requested_path: str, user: Optional[dict] = None) -> Path:
    """
    Resolve a user-supplied path and ensure it stays within allowed directories.

    Security layers:
      1. Path.resolve() canonicalizes the path (follows symlinks, collapses ..)
      2. Validate against per-user allowed_dirs (if configured)
      3. Fall back to BASE_DIR if no user restrictions
    """
    # Resolve to absolute canonical path
    path = Path(requested_path).resolve()

    # Determine the allowed roots for this user
    if user and user.get("allowed_dirs"):
        allowed_roots = [Path(d).resolve() for d in user["allowed_dirs"]]
    else:
        allowed_roots = [BASE_DIR.resolve()]

    # The resolved path must be under at least one allowed root
    for root in allowed_roots:
        try:
            path.relative_to(root)
            return path  # Access granted
        except ValueError:
            continue

    # Build a helpful error message (don't reveal full paths to non-admins)
    if user and user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access denied: you don't have permission to access this path",
        )
    raise HTTPException(
        status_code=403,
        detail=f"Access denied: path escapes the allowed root(s)",
    )


def _validate_path(requested_path: str) -> Path:
    """Legacy path validation (no user context). Used for download tokens."""
    return _resolve_path(requested_path, user=None)


# ── Directory Listing ────────────────────────────────────

def list_directory(path: str, user: Optional[dict] = None) -> dict:
    resolved = _resolve_path(path, user)
    if not resolved.is_dir():
        raise HTTPException(status_code=404, detail="Directory not found")

    entries = []
    try:
        for entry in sorted(resolved.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                st = entry.stat()
                entries.append({
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "size": st.st_size if entry.is_file() else 0,
                    "modified": st.st_mtime,
                    "permissions": oct(st.st_mode & 0o777),
                })
            except (PermissionError, OSError):
                entries.append({
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "size": 0,
                    "modified": 0,
                    "error": "Permission denied",
                })
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")

    return {"path": str(resolved), "entries": entries}


# ── Create Directory ─────────────────────────────────────

def create_directory(path: str, user: Optional[dict] = None) -> dict:
    resolved = _resolve_path(path, user)
    parent = resolved.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    try:
        resolved.mkdir(exist_ok=False)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Directory already exists")
    return {"message": f"Directory created: {resolved.name}"}


# ── Delete ───────────────────────────────────────────────

def delete_path(path: str, user: Optional[dict] = None) -> dict:
    resolved = _resolve_path(path, user)
    if not resolved.exists():
        raise HTTPException(status_code=404, detail="Path not found")

    # Prevent deleting the root itself
    base = BASE_DIR.resolve()
    if resolved == base:
        raise HTTPException(status_code=400, detail="Cannot delete the root directory")

    # Prevent deleting user data directory
    from .config import DATA_DIR
    data_resolved = DATA_DIR.resolve()
    try:
        resolved.relative_to(data_resolved)
        if resolved == data_resolved or resolved.name == "users.json":
            raise HTTPException(status_code=400, detail="Cannot delete system data")
    except ValueError:
        pass  # Not inside data dir, fine to delete

    try:
        if resolved.is_dir():
            shutil.rmtree(resolved)
        else:
            resolved.unlink()
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": f"Deleted: {resolved.name}"}


# ── Rename ───────────────────────────────────────────────

def rename_path(old_path: str, new_path: str, user: Optional[dict] = None) -> dict:
    old_resolved = _resolve_path(old_path, user)
    new_resolved = _resolve_path(new_path, user)

    if not old_resolved.exists():
        raise HTTPException(status_code=404, detail="Source not found")
    if new_resolved.exists():
        raise HTTPException(status_code=409, detail="Destination already exists")

    try:
        old_resolved.rename(new_resolved)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": f"Renamed to: {new_resolved.name}"}


# ── Read / Write (for inline editor) ─────────────────────

async def read_file_text(path: str, user: Optional[dict] = None) -> str:
    resolved = _resolve_path(path, user)
    if not resolved.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    if resolved.stat().st_size > EDITOR_MAX_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large for inline editing (>{EDITOR_MAX_SIZE // (1024*1024)} MB)",
        )
    try:
        return resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Cannot read binary file as text. Download it instead.")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")


async def write_file_text(path: str, content: str, user: Optional[dict] = None) -> dict:
    resolved = _resolve_path(path, user)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    try:
        resolved.write_text(content, encoding="utf-8")
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": f"Saved: {resolved.name}"}


# ── Upload / Download helpers ────────────────────────────

def get_file_for_download(path: str, user: Optional[dict] = None) -> Path:
    resolved = _resolve_path(path, user)
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail="Not a file")
    return resolved


def save_upload(target_dir: str, filename: str, content: bytes, user: Optional[dict] = None) -> dict:
    dest = Path(target_dir) / filename
    resolved = _resolve_path(str(dest), user)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    try:
        resolved.write_bytes(content)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": f"Uploaded: {filename}"}
