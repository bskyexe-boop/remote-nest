"""Security headers middleware — CSP, HSTS, X-Frame-Options, etc."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every HTTP response.

    NOTE: WebSocket upgrade responses are NOT intercepted by
    BaseHTTPMiddleware, so this only applies to HTTP requests.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Content Security Policy
        # - 'self' for same-origin scripts/styles
        # - CDN domains for Tailwind CSS, xterm.js, fonts
        # - 'wss:' / 'ws:' for WebSocket terminal
        # - 'unsafe-inline' required for Tailwind CDN runtime script
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "frame-ancestors 'none'"
        )

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # XSS protection (legacy, still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy — don't leak URLs
        response.headers["Referrer-Policy"] = "no-referrer"

        # HSTS (only set if the request is already HTTPS)
        # In production behind a reverse proxy with TLS, this enforces
        # HTTPS for all future requests from this client for 1 year.
        if request.url.scheme == "https":
            response.headers[
                "Strict-Transport-Security"
            ] = "max-age=31536000; includeSubDomains"

        # Permissions policy — restrict browser features we don't need
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        return response
