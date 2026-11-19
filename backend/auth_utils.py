"""JWT helpers for XAI-Sec API."""
import os
import time
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt

SECRET_KEY = os.getenv("XAI_SECRET_KEY", "xai-sec-super-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    # Use integer unix timestamp to avoid Windows CRT mktime [Errno 22] in python-jose
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
