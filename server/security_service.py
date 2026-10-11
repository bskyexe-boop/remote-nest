"""Read-only security posture checks for the administrator dashboard."""

import os
import platform
import sys
import time

from .auth import list_users
from .config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    CORS_ORIGINS,
    HOST,
    SECRET_KEY,
)
from .terminal_service import get_active_session_count


DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION-USE-openssl-rand-hex-32"
STARTED_AT = time.monotonic()


def _check(status: str, title: str, detail: str, recommendation: str = "") -> dict:
    return {
        "status": status,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }


def get_security_status(is_https: bool = False) -> dict:
    users = list_users()
    admins = [user for user in users if user.get("role") == "admin"]
    root_scoped = [
        user["username"]
        for user in users
        if any(path in ("/", "C:\\") for path in user.get("allowed_dirs", []))
    ]
    checks = []

    if SECRET_KEY == DEFAULT_SECRET:
        checks.append(_check(
            "critical",
            "Default signing secret",
            "JWTs and download tokens use the bundled development secret.",
            "Set a unique SECRET_KEY environment variable of at least 32 random characters.",
        ))
    elif len(SECRET_KEY) < 32:
        checks.append(_check(
            "warning",
            "Short signing secret",
            "The configured SECRET_KEY is shorter than 32 characters.",
            "Replace it with at least 32 cryptographically random characters.",
        ))
    else:
        checks.append(_check("pass", "Signing secret", "A custom signing secret is configured."))

    checks.append(_check(
        "pass" if is_https else "warning",
        "Transport encryption",
        "This request is protected by HTTPS." if is_https else "The dashboard is currently being accessed over HTTP.",
        "Use HTTPS through a trusted reverse proxy before exposing the service." if not is_https else "",
    ))

    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    checks.append(_check(
        "pass" if HOST in loopback_hosts else "warning",
        "Network binding",
        f"The server is configured to listen on {HOST}.",
        "Restrict the bind address or enforce firewall/VPN access." if HOST not in loopback_hosts else "",
    ))

    wildcard_cors = "*" in CORS_ORIGINS
    checks.append(_check(
        "critical" if wildcard_cors else "pass",
        "Cross-origin access",
        "Wildcard CORS access is enabled." if wildcard_cors else (
            "Cross-origin browser access is disabled by default."
            if not CORS_ORIGINS else "Cross-origin access is limited to configured origins."
        ),
        "Replace wildcard CORS with explicit trusted origins." if wildcard_cors else "",
    ))

    checks.append(_check(
        "warning" if root_scoped else "pass",
        "Filesystem permissions",
        (
            "Full filesystem access is granted to: " + ", ".join(root_scoped)
            if root_scoped else "All users are restricted to configured directories."
        ),
        "Limit allowed_dirs to only the directories each user needs." if root_scoped else "",
    ))

    checks.append(_check(
        "warning" if ACCESS_TOKEN_EXPIRE_MINUTES > 480 else "pass",
        "Session lifetime",
        f"Access tokens remain valid for {ACCESS_TOKEN_EXPIRE_MINUTES // 60} hours.",
        "Use an eight-hour or shorter token lifetime for exposed deployments."
        if ACCESS_TOKEN_EXPIRE_MINUTES > 480 else "",
    ))
    checks.append(_check(
        "warning",
        "Password policy",
        "New passwords require six characters; complexity and MFA are not enforced.",
        "Increase the minimum length and add MFA before internet exposure.",
    ))
    checks.append(_check("pass", "Security headers", "CSP, anti-framing, MIME, referrer, and permissions policies are enabled."))
    checks.append(_check("pass", "Authentication rate limiting", "Login and account-creation endpoints are rate limited."))

    severity_counts = {
        status: sum(1 for check in checks if check["status"] == status)
        for status in ("critical", "warning", "pass")
    }
    score = max(0, 100 - severity_counts["critical"] * 25 - severity_counts["warning"] * 10)

    return {
        "score": score,
        "counts": severity_counts,
        "checks": checks,
        "runtime": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "pid": os.getpid(),
            "server_uptime_seconds": int(time.monotonic() - STARTED_AT),
            "active_terminal_sessions": get_active_session_count(),
            "users": len(users),
            "administrators": len(admins),
            "token_algorithm": "HS256",
            "cors_origins": CORS_ORIGINS,
            "executable": sys.executable,
        },
    }
