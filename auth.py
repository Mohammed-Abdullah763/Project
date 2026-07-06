"""
app/routers/auth.py
────────────────────
Phase 4 – Authentication:
  POST /auth/signup
  POST /auth/login
  POST /auth/logout
  POST /auth/refresh
  GET  /auth/verify-email?token=...
  POST /auth/forgot-password
  POST /auth/reset-password
  POST /auth/change-password
  GET  /auth/me
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import (
    create_access_token,
    create_email_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import RefreshTokenBlacklist, User
from app.schemas.user import (
    ChangePassword,
    ForgotPassword,
    RefreshRequest,
    ResetPassword,
    TokenResponse,
    UserCreate,
    UserLogin,
    UserOut,
    UserUpdate,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── SIGNUP ────────────────────────────────────────────────────────────────────
@router.post("/signup", response_model=TokenResponse, status_code=201)
async def signup(
    body: UserCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    # Check duplicate email
    existing = await db.execute(
        select(User).where(User.email == body.email.lower())
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        name=body.name.strip(),
        email=body.email.lower(),
        hashed_password=hash_password(body.password),
        features=json.dumps(body.features),
        subjects=json.dumps(body.subjects),
        is_verified=True,   # Set False when email SMTP is configured
    )
    db.add(user)
    await db.flush()  # get the user.id

    # background_tasks.add_task(send_verification_email, user.email)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserOut.model_validate(user),
    )


# ── LOGIN ─────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where(User.email == body.email.lower())
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been disabled.",
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserOut.model_validate(user),
    )


# ── REFRESH ───────────────────────────────────────────────────────────────────
@router.post("/refresh")
async def refresh_token(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    # Check blacklist
    bl = await db.execute(
        select(RefreshTokenBlacklist).where(
            RefreshTokenBlacklist.token == body.refresh_token
        )
    )
    if bl.scalar_one_or_none():
        raise HTTPException(status_code=401, detail="Token has been revoked.")

    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError
        user_id = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive.")

    new_access = create_access_token(user.id)
    new_refresh = create_refresh_token(user.id)

    # Blacklist the old refresh token
    db.add(RefreshTokenBlacklist(token=body.refresh_token))

    return {"access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer"}


# ── LOGOUT ────────────────────────────────────────────────────────────────────
@router.post("/logout")
async def logout(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db.add(RefreshTokenBlacklist(token=body.refresh_token))
    return {"message": "Logged out successfully."}


# ── ME ────────────────────────────────────────────────────────────────────────
@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)


# ── UPDATE PROFILE ────────────────────────────────────────────────────────────
@router.patch("/me", response_model=UserOut)
async def update_profile(
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if body.name is not None:
        current_user.name = body.name.strip()
    if body.features is not None:
        current_user.features = json.dumps(body.features)
    if body.subjects is not None:
        current_user.subjects = json.dumps(body.subjects)
    if body.avatar_url is not None:
        current_user.avatar_url = body.avatar_url
    return UserOut.model_validate(current_user)


# ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
@router.post("/change-password")
async def change_password(
    body: ChangePassword,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    current_user.hashed_password = hash_password(body.new_password)
    return {"message": "Password updated successfully."}


# ── FORGOT PASSWORD ───────────────────────────────────────────────────────────
@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPassword,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email.lower()))
    user = result.scalar_one_or_none()

    # Always return 200 to avoid email enumeration
    if user:
        token = create_email_token(user.email, purpose="reset")
        # background_tasks.add_task(send_reset_email, user.email, token)
        # For development, return the token directly:
        return {"message": "Reset link sent.", "dev_token": token}

    return {"message": "If this email exists, a reset link has been sent."}


# ── RESET PASSWORD ────────────────────────────────────────────────────────────
@router.post("/reset-password")
async def reset_password(body: ResetPassword, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.token)
        if payload.get("purpose") != "reset":
            raise ValueError
        email = payload["sub"]
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.hashed_password = hash_password(body.new_password)
    return {"message": "Password reset successfully. Please log in."}


# ── EMAIL VERIFY ──────────────────────────────────────────────────────────────
@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(token)
        if payload.get("purpose") != "verify":
            raise ValueError
        email = payload["sub"]
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_verified = True
    return {"message": "Email verified successfully. You can now log in."}
