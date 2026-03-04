"""
ID-Networkers Combined Lab 2 — Vulnerable JWT Authentication Module

VULNERABILITY: The verify_token() function accepts JWTs with alg="none",
which allows an attacker to forge tokens without knowing the secret key.
"""

import json
import base64
from jose import jwt, JWTError


SECRET_KEY = "sup3r_s3cr3t_k3y_n0_0ne_will_gu3ss"
ALGORITHM = "HS256"

# Simulated user database
USERS_DB = {
    "guest": {"password": "guest123", "role": "user"},
}


def authenticate_user(username: str, password: str) -> dict | None:
    """Authenticate a user against the simulated database."""
    user = USERS_DB.get(username)
    if user and user["password"] == password:
        return user
    return None


def create_token(username: str, role: str) -> str:
    """Create a signed JWT for an authenticated user."""
    payload = {"sub": username, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Verify a JWT and return its payload.

    *** VULNERABLE IMPLEMENTATION ***
    If the JWT header specifies alg: "none", the signature verification
    is skipped entirely, and the payload is trusted as-is.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None

        # Decode the header to inspect the algorithm
        header = json.loads(_base64url_decode(parts[0]))

        if header.get("alg", "").lower() == "none":
            # VULNERABILITY: No signature verification!
            payload = json.loads(_base64url_decode(parts[1]))
            return payload
        else:
            # Normal verification path
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    except (JWTError, Exception):
        return None


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data with padding correction."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)
