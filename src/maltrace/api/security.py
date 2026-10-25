"""
API Security & Rate Limiting Module for MalTrace-LM REST Service.
Provides configurable API Key / Bearer Token authentication and in-memory rate limiting.
"""

import os
import time
from typing import Optional, Dict
from fastapi import Request, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)


def verify_api_security(
    request: Request,
    api_key: Optional[str] = Security(api_key_header),
    token: Optional[HTTPAuthorizationCredentials] = Security(bearer_auth)
) -> bool:
    """
    Validate incoming request against configured MALTRACE_API_KEY environment variable.
    If MALTRACE_API_KEY is not configured (default / dev mode), all requests are accepted.
    """
    configured_key = os.environ.get("MALTRACE_API_KEY", "").strip()
    if not configured_key:
        return True  # Dev mode / unauthenticated access enabled

    # Check X-API-Key header
    if api_key and api_key == configured_key:
        return True

    # Check Bearer token
    if token and token.credentials == configured_key:
        return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid or missing API Key. Pass 'X-API-Key' header or 'Authorization: Bearer <key>'."
    )


class InMemoryRateLimiter:
    """
    Simple in-memory sliding window rate limiter per client IP.
    """

    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.client_history: Dict[str, list] = {}

    def check_rate_limit(self, client_ip: str):
        now = time.time()
        window_start = now - self.window_seconds

        history = self.client_history.get(client_ip, [])
        # Filter timestamps within current sliding window
        history = [ts for ts in history if ts > window_start]

        if len(history) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: Maximum {self.max_requests} requests per {self.window_seconds}s."
            )

        history.append(now)
        self.client_history[client_ip] = history
