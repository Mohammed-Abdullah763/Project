"""
app/api/deps.py
───────────────
Reusable FastAPI dependencies:
  - get_current_user  — extract + validate JWT, return User
  - PaginationParams  — standard page/page_size query params
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_token
from app.db.database import get_db
from app.models.models import User

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract the Bearer token from the Authorization header,
    decode the JWT, and return the matching User.

    Raises 401 if token is missing, invalid, or expired.
    Raises 403 if the account is inactive.
    """
    if not credentials:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    return user


class PaginationParams:
    """Standard pagination query parameters."""
    def __init__(
        self,
        page: int = 1,
        page_size: int = 20,
    ):
        if page < 1:
            raise HTTPException(400, "page must be >= 1")
        if not (1 <= page_size <= 100):
            raise HTTPException(400, "page_size must be between 1 and 100")
        self.page = page
        self.page_size = page_size
        self.offset = (page - 1) * page_size
