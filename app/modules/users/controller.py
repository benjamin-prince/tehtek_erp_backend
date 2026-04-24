"""
ERP User Module — Controllers (Business Logic)
All DB interactions and business rules live here,
keeping routers thin and testable.
"""

import uuid
import secrets
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .models import (
    User, UserRole, Role, RolePermission, Permission,
    ReferralAgent, ReferralLead, Commission,
    UserAuditLog, UserStatus, UserType,
    ReferralStatus, CommissionStatus, CommissionType
)
from .middleware import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token
)
from .schemas import (
    UserCreate, UserUpdate, AssignRolesRequest,
    LoginRequest, ChangePasswordRequest,
    ReferralAgentCreate, ReferralAgentUpdate,
    ReferralLeadCreate, ReferralLeadUpdate,
    CommissionApproveRequest, CommissionPayRequest,
)
from ..core.database import settings


# ─────────────────────────────────────────────
# AUDIT HELPER
# ─────────────────────────────────────────────

async def log_action(
    db: AsyncSession,
    user_id: uuid.UUID,
    action: str,
    actor_id: Optional[uuid.UUID] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
):
    log = UserAuditLog(
        user_id=user_id,
        actor_id=actor_id,
        action=action,
        detail=detail,
        ip_address=ip_address,
    )
    db.add(log)


# ─────────────────────────────────────────────
# AUTH CONTROLLER
# ─────────────────────────────────────────────

class AuthController:

    @staticmethod
    async def login(db: AsyncSession, payload: LoginRequest, ip: str) -> dict:
        result = await db.execute(
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

        # Check lockout
        if user.locked_until and user.locked_until > datetime.utcnow():
            raise HTTPException(
                status_code=403,
                detail=f"Account locked. Try again after {user.locked_until.isoformat()}.",
            )

        if not verify_password(payload.password, user.hashed_password):
            user.failed_login_count += 1
            if user.failed_login_count >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=settings.LOCKOUT_MINUTES)
                await log_action(db, user.id, "account_locked", detail="Too many failed attempts", ip_address=ip)
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if user.status in (UserStatus.INACTIVE, UserStatus.SUSPENDED):
            raise HTTPException(status_code=403, detail=f"Account {user.status.value}.")

        # Successful login — reset counters
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        await log_action(db, user.id, "login", ip_address=ip)

        access_token  = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        return {
            "access_token":  access_token,
            "refresh_token": refresh_token,
            "token_type":    "bearer",
            "expires_in":    settings.ACCESS_TOKEN_EXPIRE_MIN * 60,
        }

    @staticmethod
    async def refresh(db: AsyncSession, refresh_token: str) -> dict:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type.")

        result = await db.execute(
            select(User).where(User.id == uuid.UUID(payload["sub"]), User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive.")

        return {
            "access_token":  create_access_token(user.id),
            "refresh_token": create_refresh_token(user.id),
            "token_type":    "bearer",
            "expires_in":    settings.ACCESS_TOKEN_EXPIRE_MIN * 60,
        }

    @staticmethod
    async def request_password_reset(db: AsyncSession, email: str) -> bool:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        # Always return True to prevent email enumeration
        if not user:
            return True
        token = secrets.token_urlsafe(48)
        user.reset_token = token
        user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MIN)
        await log_action(db, user.id, "password_reset_requested")
        # In production: send email with reset link containing token
        return True

    @staticmethod
    async def confirm_password_reset(db: AsyncSession, token: str, new_password: str) -> bool:
        result = await db.execute(
            select(User).where(
                User.reset_token == token,
                User.reset_token_expiry > datetime.utcnow(),
            )
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        user.hashed_password    = hash_password(new_password)
        user.reset_token        = None
        user.reset_token_expiry = None
        user.failed_login_count = 0
        user.locked_until       = None
        await log_action(db, user.id, "password_reset_confirmed")
        return True


# ─────────────────────────────────────────────
# USER CONTROLLER
# ─────────────────────────────────────────────

class UserController:

    @staticmethod
    async def create_user(
        db: AsyncSession,
        payload: UserCreate,
        actor: User,
    ) -> User:
        # Check duplicate email
        existing = await db.execute(select(User).where(User.email == payload.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already registered.")

        user = User(
            email           = payload.email,
            phone           = payload.phone,
            hashed_password = hash_password(payload.password),
            first_name      = payload.first_name,
            last_name       = payload.last_name,
            user_type       = payload.user_type,
            department      = payload.department,
            job_title       = payload.job_title,
            status          = UserStatus.ACTIVE,
            created_by      = actor.id,
        )
        db.add(user)
        await db.flush()  # get user.id without committing

        # Assign initial roles
        if payload.role_ids:
            roles_res = await db.execute(select(Role).where(Role.id.in_(payload.role_ids)))
            roles = roles_res.scalars().all()
            for role in roles:
                db.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=actor.id))

        await log_action(db, user.id, "user_created", actor_id=actor.id)
        return user

    @staticmethod
    async def get_user(db: AsyncSession, user_id: uuid.UUID) -> User:
        result = await db.execute(
            select(User)
            .where(User.id == user_id, User.deleted_at.is_(None))
            .options(
                selectinload(User.roles).selectinload(UserRole.role)
            )
        )
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        return user

    @staticmethod
    async def list_users(
        db: AsyncSession,
        page: int = 1,
        size: int = 20,
        search: Optional[str] = None,
        user_type: Optional[UserType] = None,
        status: Optional[UserStatus] = None,
        department: Optional[str] = None,
    ):
        query = select(User).where(User.deleted_at.is_(None))

        if search:
            query = query.where(
                (User.first_name.ilike(f"%{search}%")) |
                (User.last_name.ilike(f"%{search}%")) |
                (User.email.ilike(f"%{search}%"))
            )
        if user_type:
            query = query.where(User.user_type == user_type)
        if status:
            query = query.where(User.status == status)
        if department:
            query = query.where(User.department == department)

        count_res = await db.execute(select(func.count()).select_from(query.subquery()))
        total = count_res.scalar()

        query = (
            query
            .options(selectinload(User.roles).selectinload(UserRole.role))
            .offset((page - 1) * size)
            .limit(size)
            .order_by(User.created_at.desc())
        )
        result = await db.execute(query)
        return result.scalars().all(), total

    @staticmethod
    async def update_user(
        db: AsyncSession,
        user_id: uuid.UUID,
        payload: UserUpdate,
        actor: User,
    ) -> User:
        user = await UserController.get_user(db, user_id)
        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(user, field, value)
        await log_action(db, user.id, "user_updated", actor_id=actor.id)
        return user

    @staticmethod
    async def soft_delete_user(db: AsyncSession, user_id: uuid.UUID, actor: User):
        user = await UserController.get_user(db, user_id)
        if user.is_superadmin:
            raise HTTPException(status_code=400, detail="Cannot delete a superadmin account.")
        user.deleted_at = datetime.utcnow()
        user.status = UserStatus.INACTIVE
        await log_action(db, user.id, "user_deleted", actor_id=actor.id)

    @staticmethod
    async def assign_roles(
        db: AsyncSession,
        user_id: uuid.UUID,
        payload: AssignRolesRequest,
        actor: User,
    ) -> User:
        user = await UserController.get_user(db, user_id)

        # Remove current roles not in new list
        await db.execute(
            UserRole.__table__.delete().where(UserRole.user_id == user_id)
        )
        # Assign new roles
        roles_res = await db.execute(select(Role).where(Role.id.in_(payload.role_ids)))
        for role in roles_res.scalars().all():
            db.add(UserRole(
                user_id=user_id,
                role_id=role.id,
                assigned_by=actor.id,
                expires_at=payload.expires_at,
            ))
        await log_action(db, user_id, "roles_assigned", actor_id=actor.id,
                         detail=str([str(r) for r in payload.role_ids]))
        return user

    @staticmethod
    async def change_password(
        db: AsyncSession,
        user: User,
        payload: ChangePasswordRequest,
    ):
        if not verify_password(payload.current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        user.hashed_password = hash_password(payload.new_password)
        await log_action(db, user.id, "password_changed", actor_id=user.id)


# ─────────────────────────────────────────────
# REFERRAL CONTROLLER
# ─────────────────────────────────────────────

class ReferralController:

    @staticmethod
    async def create_agent(
        db: AsyncSession,
        user_id: uuid.UUID,
        payload: ReferralAgentCreate,
        actor: User,
    ) -> ReferralAgent:
        user = await UserController.get_user(db, user_id)

        if user.referral_profile:
            raise HTTPException(status_code=409, detail="User already has a referral profile.")

        # Ensure user type is set to REFERRAL
        user.user_type = UserType.REFERRAL

        agent = ReferralAgent(user_id=user_id, **payload.model_dump())
        db.add(agent)
        await log_action(db, user_id, "referral_agent_created", actor_id=actor.id)
        return agent

    @staticmethod
    async def submit_lead(
        db: AsyncSession,
        agent: ReferralAgent,
        payload: ReferralLeadCreate,
    ) -> ReferralLead:
        lead = ReferralLead(agent_id=agent.id, **payload.model_dump())
        db.add(lead)
        agent.total_referrals += 1
        return lead

    @staticmethod
    async def update_lead(
        db: AsyncSession,
        lead_id: uuid.UUID,
        payload: ReferralLeadUpdate,
        actor: User,
    ) -> ReferralLead:
        result = await db.execute(select(ReferralLead).where(ReferralLead.id == lead_id))
        lead = result.scalar_one_or_none()
        if not lead:
            raise HTTPException(status_code=404, detail="Lead not found.")

        for field, value in payload.model_dump(exclude_unset=True).items():
            setattr(lead, field, value)

        # Auto-generate commission when lead is converted
        if payload.status == ReferralStatus.CONVERTED and not lead.commission:
            await ReferralController._generate_commission(db, lead)

        return lead

    @staticmethod
    async def _generate_commission(
        db: AsyncSession,
        lead: ReferralLead,
    ):
        result = await db.execute(
            select(ReferralAgent).where(ReferralAgent.id == lead.agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent or not lead.deal_value:
            return

        deal = lead.deal_value
        if agent.commission_type == CommissionType.PERCENTAGE:
            amount = (deal * agent.commission_rate / Decimal("100")).quantize(Decimal("0.01"))
        else:
            amount = agent.commission_rate  # flat fee

        lead.converted_at = datetime.utcnow()
        agent.total_converted += 1

        commission = Commission(
            agent_id        = agent.id,
            lead_id         = lead.id,
            commission_type = agent.commission_type,
            rate            = agent.commission_rate,
            deal_value      = deal,
            amount          = amount,
            currency        = agent.currency,
            status          = CommissionStatus.PENDING,
        )
        db.add(commission)

    @staticmethod
    async def approve_commission(
        db: AsyncSession,
        commission_id: uuid.UUID,
        payload: CommissionApproveRequest,
        actor: User,
    ) -> Commission:
        result = await db.execute(
            select(Commission).where(Commission.id == commission_id)
        )
        commission = result.scalar_one_or_none()
        if not commission:
            raise HTTPException(status_code=404, detail="Commission not found.")
        if commission.status != CommissionStatus.PENDING:
            raise HTTPException(status_code=400, detail=f"Commission is already {commission.status.value}.")

        commission.status      = CommissionStatus.APPROVED
        commission.approved_by = actor.id
        commission.approved_at = datetime.utcnow()
        commission.notes       = payload.notes
        await log_action(db, actor.id, "commission_approved",
                         actor_id=actor.id, detail=str(commission_id))
        return commission

    @staticmethod
    async def mark_commission_paid(
        db: AsyncSession,
        commission_id: uuid.UUID,
        payload: CommissionPayRequest,
        actor: User,
    ) -> Commission:
        result = await db.execute(
            select(Commission)
            .where(Commission.id == commission_id)
            .options(selectinload(Commission.agent))
        )
        commission = result.scalar_one_or_none()
        if not commission:
            raise HTTPException(status_code=404, detail="Commission not found.")
        if commission.status != CommissionStatus.APPROVED:
            raise HTTPException(status_code=400, detail="Commission must be approved before marking as paid.")

        commission.status      = CommissionStatus.PAID
        commission.paid_at     = datetime.utcnow()
        commission.payment_ref = payload.payment_ref
        commission.notes       = payload.notes

        # Update agent totals
        commission.agent.total_earned += commission.amount
        await log_action(db, actor.id, "commission_paid",
                         actor_id=actor.id, detail=f"{commission.amount} {commission.currency}")
        return commission

    @staticmethod
    async def get_commission_summary(db: AsyncSession, agent_id: uuid.UUID) -> dict:
        result = await db.execute(
            select(ReferralAgent).where(ReferralAgent.id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Referral agent not found.")

        pending_res = await db.execute(
            select(func.coalesce(func.sum(Commission.amount), 0))
            .where(Commission.agent_id == agent_id, Commission.status == CommissionStatus.PENDING)
        )
        paid_res = await db.execute(
            select(func.coalesce(func.sum(Commission.amount), 0))
            .where(Commission.agent_id == agent_id, Commission.status == CommissionStatus.PAID)
        )

        total_pending = pending_res.scalar()
        total_paid    = paid_res.scalar()
        conversion_rate = (
            (agent.total_converted / agent.total_referrals * 100)
            if agent.total_referrals > 0 else 0.0
        )

        return {
            "agent_id":        agent.id,
            "total_referrals": agent.total_referrals,
            "total_converted": agent.total_converted,
            "conversion_rate": round(conversion_rate, 2),
            "total_earned":    agent.total_earned,
            "total_pending":   total_pending,
            "total_paid":      total_paid,
            "currency":        agent.currency,
        }