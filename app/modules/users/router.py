"""
ERP User Module — FastAPI Router
All endpoints: Auth, Users, Roles, Referrals, Commissions
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from .controller import AuthController, UserController, ReferralController
from .middleware import (
    get_current_active_user,
    require_permission,
    require_role,
    require_superadmin,
    require_self_or_permission,
)
from .models import User, UserType, UserStatus, ReferralAgent
from .schemas import (
    # Auth
    LoginRequest, TokenResponse, RefreshRequest,
    PasswordResetRequest, PasswordResetConfirm,
    # Users
    UserCreate, UserUpdate, UserResponse, UserListResponse,
    AssignRolesRequest, ChangePasswordRequest,
    # Roles
    RoleCreate, RoleUpdate, RoleResponse,
    # Referral
    ReferralAgentCreate, ReferralAgentUpdate, ReferralAgentResponse,
    ReferralLeadCreate, ReferralLeadUpdate, ReferralLeadResponse, ReferralLeadListResponse,
    # Commissions
    CommissionResponse, CommissionListResponse,
    CommissionApproveRequest, CommissionPayRequest, CommissionSummary,
)
from sqlalchemy import select
from sqlalchemy.orm import selectinload


router = APIRouter(prefix="/api/v1", tags=["Users"])


# ═══════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════

auth_router = APIRouter(prefix="/auth", tags=["Auth"])


@auth_router.post("/login", response_model=TokenResponse, summary="Login")
def login(
    request: Request,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with email + password. Returns JWT access & refresh tokens."""
    ip = request.client.host if request.client else None
    return AuthController.login(db, payload, ip)


@auth_router.post("/refresh", response_model=TokenResponse, summary="Refresh token")
def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    return  AuthController.refresh(db, payload.refresh_token)


@auth_router.post("/password-reset/request", status_code=200, summary="Request password reset")
def request_password_reset(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    AuthController.request_password_reset(db, payload.email)
    return {"message": "If the email is registered, a reset link has been sent."}


@auth_router.post("/password-reset/confirm", status_code=200, summary="Confirm password reset")
def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    AuthController.confirm_password_reset(db, payload.token, payload.new_password)
    return {"message": "Password successfully reset."}


@auth_router.get("/me", response_model=UserResponse, summary="Get current user")
def get_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@auth_router.patch("/me/password", status_code=200, summary="Change own password")
def change_my_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    UserController.change_password(db, current_user, payload)
    return {"message": "Password updated successfully."}


# ═══════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════

users_router = APIRouter(prefix="/users", tags=["Users"])


@users_router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user",
    dependencies=[Depends(require_permission("users:write"))],
)
def create_user(
    payload: UserCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    user =  UserController.create_user(db, payload, current_user)
    return user


@users_router.get(
    "/",
    response_model=UserListResponse,
    summary="List users",
    dependencies=[Depends(require_permission("users:read"))],
)
def list_users(
    page:       int = Query(1, ge=1),
    size:       int = Query(20, ge=1, le=100),
    search:     Optional[str] = Query(None),
    user_type:  Optional[UserType] = Query(None),
    status:     Optional[UserStatus] = Query(None),
    department: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    users, total =  UserController.list_users(
        db, page, size, search, user_type, status, department
    )
    return UserListResponse(total=total, page=page, size=size, items=users)


@users_router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user",
    dependencies=[Depends(require_self_or_permission("users:read"))],
)
def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    return  UserController.get_user(db, user_id)


@users_router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user",
    dependencies=[Depends(require_self_or_permission("users:write"))],
)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  UserController.update_user(db, user_id, payload, current_user)


@users_router.delete(
    "/{user_id}",
    status_code=204,
    summary="Delete user (soft)",
    dependencies=[Depends(require_permission("users:delete"))],
)
def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
     UserController.soft_delete_user(db, user_id, current_user)


@users_router.put(
    "/{user_id}/roles",
    response_model=UserResponse,
    summary="Assign roles to user",
    dependencies=[Depends(require_permission("users:manage_roles"))],
)
def assign_roles(
    user_id: uuid.UUID,
    payload: AssignRolesRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  UserController.assign_roles(db, user_id, payload, current_user)


@users_router.get(
    "/{user_id}/audit-log",
    summary="View user audit log",
    dependencies=[Depends(require_permission("users:audit"))],
)
def get_user_audit_log(
    user_id: uuid.UUID,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    from .models import UserAuditLog
    from sqlalchemy import select, func
    count_res =  db.execute(
        select(func.count()).where(UserAuditLog.user_id == user_id)
    )
    result = db.execute(
        select(UserAuditLog)
        .where(UserAuditLog.user_id == user_id)
        .order_by(UserAuditLog.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )
    logs = result.scalars().all()
    return {"total": count_res.scalar(), "page": page, "size": size, "items": logs}


# ═══════════════════════════════════════════════════
# ROLES
# ═══════════════════════════════════════════════════

roles_router = APIRouter(prefix="/roles", tags=["Roles & Permissions"])


@roles_router.post(
    "/",
    response_model=RoleResponse,
    status_code=201,
    summary="Create role",
    dependencies=[Depends(require_permission("roles:write"))],
)
def create_role(
    payload: RoleCreate,
    db: AsyncSession = Depends(get_db),
):
    from .models import Role, RolePermission, Permission
    existing =  db.execute(select(Role).where(Role.slug == payload.slug))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Role slug already exists.")

    role = Role(
        name=payload.name, slug=payload.slug,
        department=payload.department, description=payload.description,
    )
    db.add(role)
    db.flush()

    if payload.permission_ids:
        perms =  db.execute(select(Permission).where(Permission.id.in_(payload.permission_ids)))
        for p in perms.scalars().all():
            db.add(RolePermission(role_id=role.id, permission_id=p.id))

    return role


@roles_router.get("/", summary="List all roles", dependencies=[Depends(require_permission("roles:read"))])
def list_roles(db: AsyncSession = Depends(get_db)):
    result = db.execute(
        select(Role).options(
            selectinload(Role.permissions).selectinload(RolePermission.permission)
        )
    )
    return result.scalars().all()


@roles_router.delete(
    "/{role_id}",
    status_code=204,
    summary="Delete role",
    dependencies=[Depends(require_superadmin())],
)
def delete_role(role_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    from .models import Role
    from fastapi import HTTPException
    result = db.execute(select(Role).where(Role.id == role_id))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found.")
    if role.is_system:
        raise HTTPException(status_code=400, detail="Cannot delete a system role.")
    db.delete(role)


# ═══════════════════════════════════════════════════
# REFERRAL AGENTS
# ═══════════════════════════════════════════════════

referral_router = APIRouter(prefix="/referrals", tags=["Referrals & Commissions"])


@referral_router.post(
    "/agents/{user_id}",
    response_model=ReferralAgentResponse,
    status_code=201,
    summary="Create referral agent profile for a user",
    dependencies=[Depends(require_permission("referrals:write"))],
)
def create_referral_agent(
    user_id: uuid.UUID,
    payload: ReferralAgentCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  ReferralController.create_agent(db, user_id, payload, current_user)


@referral_router.get(
    "/agents",
    summary="List all referral agents",
    dependencies=[Depends(require_permission("referrals:read"))],
)
def list_referral_agents(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import func
    count_res =  db.execute(select(func.count()).select_from(ReferralAgent))
    result = db.execute(
        select(ReferralAgent)
        .options(selectinload(ReferralAgent.user))
        .offset((page - 1) * size)
        .limit(size)
        .order_by(ReferralAgent.created_at.desc())
    )
    items = result.scalars().all()
    return {"total": count_res.scalar(), "page": page, "size": size, "items": items}


@referral_router.get(
    "/agents/{agent_id}/summary",
    response_model=CommissionSummary,
    summary="Get commission summary for an agent",
    dependencies=[Depends(require_permission("referrals:read"))],
)
def get_agent_summary(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    return  ReferralController.get_commission_summary(db, agent_id)


# ─── Leads ───────────────────────────────────

@referral_router.post(
    "/agents/{agent_id}/leads",
    response_model=ReferralLeadResponse,
    status_code=201,
    summary="Submit a new referral lead",
    dependencies=[Depends(require_permission("referrals:write"))],
)
def submit_lead(
    agent_id: uuid.UUID,
    payload: ReferralLeadCreate,
    db: AsyncSession = Depends(get_db),
):
    result = db.execute(select(ReferralAgent).where(ReferralAgent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Referral agent not found.")
    return  ReferralController.submit_lead(db, agent, payload)


@referral_router.get(
    "/agents/{agent_id}/leads",
    response_model=ReferralLeadListResponse,
    summary="List leads for an agent",
    dependencies=[Depends(require_permission("referrals:read"))],
)
def list_agent_leads(
    agent_id: uuid.UUID,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    from .models import ReferralLead
    from sqlalchemy import func
    count_res =  db.execute(
        select(func.count()).where(ReferralLead.agent_id == agent_id)
    )
    result = db.execute(
        select(ReferralLead)
        .where(ReferralLead.agent_id == agent_id)
        .order_by(ReferralLead.submitted_at.desc())
        .offset((page - 1) * size).limit(size)
    )
    items = result.scalars().all()
    return ReferralLeadListResponse(total=count_res.scalar(), page=page, size=size, items=items)


@referral_router.patch(
    "/leads/{lead_id}",
    response_model=ReferralLeadResponse,
    summary="Update lead status (sales team)",
    dependencies=[Depends(require_permission("referrals:manage"))],
)
def update_lead(
    lead_id: uuid.UUID,
    payload: ReferralLeadUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  ReferralController.update_lead(db, lead_id, payload, current_user)


# ─── Commissions ─────────────────────────────

@referral_router.get(
    "/commissions",
    summary="List all commissions",
    dependencies=[Depends(require_permission("commissions:read"))],
)
def list_commissions(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    agent_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    from .models import Commission
    from sqlalchemy import func
    query = select(Commission)
    if agent_id:
        query = query.where(Commission.agent_id == agent_id)
    count_res =  db.execute(select(func.count()).select_from(query.subquery()))
    result = db.execute(
        query.order_by(Commission.created_at.desc())
        .offset((page - 1) * size).limit(size)
    )
    return {"total": count_res.scalar(), "page": page, "size": size, "items": result.scalars().all()}


@referral_router.post(
    "/commissions/{commission_id}/approve",
    response_model=CommissionResponse,
    summary="Approve a commission",
    dependencies=[Depends(require_permission("commissions:approve"))],
)
def approve_commission(
    commission_id: uuid.UUID,
    payload: CommissionApproveRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  ReferralController.approve_commission(db, commission_id, payload, current_user)


@referral_router.post(
    "/commissions/{commission_id}/pay",
    response_model=CommissionResponse,
    summary="Mark commission as paid",
    dependencies=[Depends(require_permission("commissions:pay"))],
)
def pay_commission(
    commission_id: uuid.UUID,
    payload: CommissionPayRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    return  ReferralController.mark_commission_paid(db, commission_id, payload, current_user)


# ═══════════════════════════════════════════════════
# ASSEMBLE MAIN ROUTER
# ═══════════════════════════════════════════════════

from fastapi import HTTPException

router.include_router(auth_router)
router.include_router(users_router)
router.include_router(roles_router)
router.include_router(referral_router)
