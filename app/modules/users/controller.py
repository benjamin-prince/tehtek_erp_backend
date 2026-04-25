import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select, func
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from .models import User, UserRole, Role, RolePermission, UserAuditLog, UserStatus
from .middleware import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from .schemas import LoginRequest, UserCreate, UserUpdate


def log_action(
    db: Session,
    user_id: uuid.UUID,
    action: str,
    actor_id: Optional[uuid.UUID] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
):
    db.add(
        UserAuditLog(
            user_id=user_id,
            actor_id=actor_id,
            action=action,
            detail=detail,
            ip_address=ip_address,
        )
    )


class AuthController:
    @staticmethod
    def login(db: Session, payload: LoginRequest, ip: str) -> dict:
        result = db.execute(
            select(User)
            .where(User.email == payload.email, User.deleted_at.is_(None))
            .options(
                selectinload(User.roles)
                .selectinload(UserRole.role)
                .selectinload(Role.permissions)
                .selectinload(RolePermission.permission)
            )
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=403,
                detail=f"Account locked. Try again after {user.locked_until.isoformat()}",
            )

        if not verify_password(payload.password, user.hashed_password):
            user.failed_login_count += 1

            if user.failed_login_count >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(
                    minutes=settings.LOCKOUT_MINUTES
                )
                log_action(
                    db,
                    user.id,
                    "account_locked",
                    detail="Too many failed attempts",
                    ip_address=ip,
                )

            db.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if user.status in (UserStatus.INACTIVE, UserStatus.SUSPENDED):
            raise HTTPException(status_code=403, detail=f"Account {user.status.value}.")

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()

        log_action(db, user.id, "login", ip_address=ip)

        db.commit()

        return {
            "access_token": create_access_token(user.id),
            "refresh_token": create_refresh_token(user.id),
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MIN * 60,
        }

    @staticmethod
    def refresh(db: Session, refresh_token: str) -> dict:
        payload = decode_token(refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type.")

        result = db.execute(
            select(User).where(
                User.id == uuid.UUID(payload["sub"]),
                User.deleted_at.is_(None),
            )
        )
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive.")

        return {
            "access_token": create_access_token(user.id),
            "refresh_token": create_refresh_token(user.id),
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MIN * 60,
        }


class UserController:
    @staticmethod
    def list_users(
        db: Session,
        page: int = 1,
        size: int = 20,
        search: Optional[str] = None,
        user_type=None,
        status=None,
        department: Optional[str] = None,
    ):
        query = select(User).where(User.deleted_at.is_(None))

        if search:
            query = query.where(
                (User.first_name.ilike(f"%{search}%"))
                | (User.last_name.ilike(f"%{search}%"))
                | (User.email.ilike(f"%{search}%"))
            )

        if user_type:
            query = query.where(User.user_type == user_type)

        if status:
            query = query.where(User.status == status)

        if department:
            query = query.where(User.department == department)

        count_result = db.execute(select(func.count()).select_from(query.subquery()))
        total = count_result.scalar()

        result = db.execute(
            query.options(selectinload(User.roles).selectinload(UserRole.role))
            .order_by(User.created_at.desc())
            .offset((page - 1) * size)
            .limit(size)
        )

        return result.scalars().all(), total

    @staticmethod
    def get_user(db: Session, user_id: uuid.UUID) -> User:
        result = db.execute(
            select(User)
            .where(User.id == user_id, User.deleted_at.is_(None))
            .options(selectinload(User.roles).selectinload(UserRole.role))
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        return user

    @staticmethod
    def create_user(db: Session, payload: UserCreate, actor: User) -> User:
        existing = db.execute(select(User).where(User.email == payload.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already registered.")

        user = User(
            email=payload.email,
            phone=payload.phone,
            hashed_password=hash_password(payload.password),
            first_name=payload.first_name,
            last_name=payload.last_name,
            user_type=payload.user_type,
            department=payload.department,
            job_title=payload.job_title,
            status=UserStatus.ACTIVE,
            created_by=actor.id if actor else None,
        )

        db.add(user)
        db.flush()

        log_action(db, user.id, "user_created", actor_id=actor.id if actor else None)
        db.commit()
        db.refresh(user)

        return user


class ReferralController:
    pass