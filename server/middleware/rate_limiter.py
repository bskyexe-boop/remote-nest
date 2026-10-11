"""Rate limiting for sensitive endpoints (login, setup, user creation)."""
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

# Create a single limiter instance; the key function extracts the
# client IP from the request (works behind proxies if you set
# FASTAPI_RATE_LIMIT_KEY_FUNC or trust X-Forwarded-For).
limiter = Limiter(key_func=get_remote_address)

# Limits applied per route via decorator:
#   @limiter.limit("5/minute")
#   @limiter.limit("3/minute")

# Login: 5 attempts per minute per IP
LOGIN_LIMIT = "5/minute"

# Setup (admin creation): 3 per minute per IP
SETUP_LIMIT = "3/minute"

# User creation (admin): 10 per minute per IP
USER_CREATE_LIMIT = "10/minute"
