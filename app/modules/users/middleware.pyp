"""
ERP User Module — Auth & Permission Middleware
JWT authentication + Role-Based Access Control (RBAC)
"""

import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..core.database import get_db, settings
from .models import User, UserRole, Role, RolePermission, Permission, UserStatus


# ─────────────────────────────────────────────
# PASSWORD HASHING
# ─────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ─────────────────────────────────────────────
# JWT TOKENS
# ─────────────────────────────────────────────

bearer_scheme = HTTPBearer()


def create_access_token(user_id: uuid.UUID, extra: dict = {}) -> str:
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MIN)
    payload = {
        "sub":  str(user_id),
        "exp":  expire,
        "type": "access",
        **extra,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: uuid.UUID) -> str:
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub":  str(user_id),
        "exp":  expire,
        "type": "refresh",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─────────────────────────────────────────────
# CURRENT USER DEPENDENCY
# ─────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type.")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token payload invalid.")

    result = await db.execute(
        select(User)
        .where(User.id == uuid.UUID(user_id), User.deleted_at.is_(None))
        .options(
            selectinload(User.roles)
            .selectinload(UserRole.role)
            .selectinload(Role.permissions)
            .selectinload(RolePermission.permission)
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    if user.status == UserStatus.SUSPENDED:
        raise HTTPException(status_code=403, detail="Account suspended.")

    if user.status == UserStatus.INACTIVE:
        raise HTTPException(status_code=403, detail="Account inactive.")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=403,
            detail=f"Account locked until {user.locked_until.isoformat()}.",
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active.")
    return current_user


# ─────────────────────────────────────────────
# PERMISSION HELPERS
# ─────────────────────────────────────────────

def get_user_permissions(user: User) -> set[str]:
    """
    Collect all permission codes (module:action) granted
    to a user through their roles.
    """
    permissions = set()
    now = datetime.utcnow()
    for user_role in user.roles:
        # Skip expired role assignments
        if user_role.expires_at and user_role.expires_at < now:
            continue
        for role_perm in user_role.role.permissions:
            permissions.add(role_perm.permission.code)
    return permissions


def get_user_role_slugs(user: User) -> set[str]:
    now = datetime.utcnow()
    return {
        ur.role.slug
        for ur in user.roles
        if not ur.expires_at or ur.expires_at >= now
    }


# ─────────────────────────────────────────────
# PERMISSION DEPENDENCY FACTORIES
# ─────────────────────────────────────────────

def require_permission(*permissions: str):
    """
    Dependency factory — requires the current user to have
    ALL listed permissions.

    Usage:
        @router.get("/invoices", dependencies=[Depends(require_permission("invoices:read"))])
    """
    async def checker(current_user: User = Depends(get_current_active_user)):
        if current_user.is_superadmin:
            return current_user
        user_perms = get_user_permissions(current_user)
        missing = [p for p in permissions if p not in user_perms]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission(s): {', '.join(missing)}",
            )
        return current_user
    return checker


def require_any_permission(*permissions: str):
    """
    Requires the current user to have AT LEAST ONE of the listed permissions.
    """
    async def checker(current_user: User = Depends(get_current_active_user)):
        if current_user.is_superadmin:
            return current_user
        user_perms = get_user_permissions(current_user)
        if not any(p in user_perms for p in permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )
        return current_user
    return checker


def require_role(*role_slugs: str):
    """
    Requires the current user to have AT LEAST ONE of the listed roles.

    Usage:
        @router.post("/payroll/run", dependencies=[Depends(require_role("payroll_manager"))])
    """
    async def checker(current_user: User = Depends(get_current_active_user)):
        if current_user.is_superadmin:
            return current_user
        user_roles = get_user_role_slugs(current_user)
        if not any(r in user_roles for r in role_slugs):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role(s): {', '.join(role_slugs)}",
            )
        return current_user
    return checker


def require_superadmin():
    """Restricts endpoint to superadmin only."""
    async def checker(current_user: User = Depends(get_current_active_user)):
        if not current_user.is_superadmin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superadmin access required.",
            )
        return current_user
    return checker


def require_self_or_permission(permission: str):
    """
    Allows a user to access their own resource,
    or any user with the given permission.
    Requires the path to have a `user_id` parameter.
    """
    async def checker(
        user_id: uuid.UUID,
        current_user: User = Depends(get_current_active_user),
    ):
        if current_user.is_superadmin:
            return current_user
        if current_user.id == user_id:
            return current_user
        user_perms = get_user_permissions(current_user)
        if permission not in user_perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own resource.",
            )
        return current_user
    return checker