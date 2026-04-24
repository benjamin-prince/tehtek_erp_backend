"""
ERP User Module — Pydantic v2 Schemas
Request/Response validation for all endpoints.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from .models import (
    UserStatus, UserType, ReferralStatus,
    CommissionStatus, CommissionType
)


# ─────────────────────────────────────────────
# BASE
# ─────────────────────────────────────────────

class TimestampMixin(BaseModel):
    created_at: datetime
    updated_at: datetime


# ─────────────────────────────────────────────
# PERMISSIONS
# ─────────────────────────────────────────────

class PermissionBase(BaseModel):
    module: str = Field(..., max_length=60, examples=["users"])
    action: str = Field(..., max_length=60, examples=["read"])
    description: Optional[str] = None


class PermissionCreate(PermissionBase):
    pass


class PermissionResponse(PermissionBase, TimestampMixin):
    id: uuid.UUID
    code: str

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# ROLES
# ─────────────────────────────────────────────

class RoleBase(BaseModel):
    name:       str = Field(..., max_length=100, examples=["Sales Manager"])
    slug:       str = Field(..., max_length=100, examples=["sales_manager"])
    department: Optional[str] = Field(None, max_length=100, examples=["Sales"])
    description:Optional[str] = None


class RoleCreate(RoleBase):
    permission_ids: Optional[List[uuid.UUID]] = []


class RoleUpdate(BaseModel):
    name:           Optional[str] = None
    description:    Optional[str] = None
    department:     Optional[str] = None
    permission_ids: Optional[List[uuid.UUID]] = None


class RoleResponse(RoleBase):
    id:         uuid.UUID
    is_system:  bool
    permissions: List[PermissionResponse] = []

    model_config = {"from_attributes": True}


class RoleShort(BaseModel):
    id:   uuid.UUID
    name: str
    slug: str

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────

class UserCreate(BaseModel):
    email:      EmailStr
    phone:      Optional[str]   = None
    password:   str             = Field(..., min_length=8)
    first_name: str             = Field(..., max_length=100)
    last_name:  str             = Field(..., max_length=100)
    user_type:  UserType        = UserType.INTERNAL
    department: Optional[str]   = None
    job_title:  Optional[str]   = None
    role_ids:   List[uuid.UUID] = []

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


class UserUpdate(BaseModel):
    phone:      Optional[str] = None
    first_name: Optional[str] = None
    last_name:  Optional[str] = None
    department: Optional[str] = None
    job_title:  Optional[str] = None
    status:     Optional[UserStatus] = None
    avatar_url: Optional[str] = None


class UserResponse(BaseModel):
    id:         uuid.UUID
    email:      str
    phone:      Optional[str]
    first_name: str
    last_name:  str
    full_name:  str
    user_type:  UserType
    status:     UserStatus
    department: Optional[str]
    job_title:  Optional[str]
    avatar_url: Optional[str]
    is_superadmin: bool
    mfa_enabled:   bool
    last_login:    Optional[datetime]
    created_at:    datetime
    roles:         List[RoleShort] = []

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    total:  int
    page:   int
    size:   int
    items:  List[UserResponse]


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must have at least one uppercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must have at least one digit.")
        return v


class AssignRolesRequest(BaseModel):
    role_ids:   List[uuid.UUID]
    expires_at: Optional[datetime] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token:        str
    new_password: str = Field(..., min_length=8)


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────

class LoginRequest(BaseModel):
    email:    EmailStr
    password: str
    mfa_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int


class RefreshRequest(BaseModel):
    refresh_token: str


# ─────────────────────────────────────────────
# REFERRAL AGENT
# ─────────────────────────────────────────────

class ReferralAgentCreate(BaseModel):
    company_name:     Optional[str]          = None
    commission_type:  CommissionType         = CommissionType.PERCENTAGE
    commission_rate:  Decimal                = Field(..., ge=0, le=100)
    currency:         str                    = "USD"
    payment_method:   Optional[str]          = None
    bank_account_info:Optional[str]          = None
    notes:            Optional[str]          = None

    @model_validator(mode="after")
    def validate_rate(self):
        if self.commission_type == CommissionType.PERCENTAGE and self.commission_rate > 100:
            raise ValueError("Percentage commission cannot exceed 100.")
        return self


class ReferralAgentUpdate(BaseModel):
    company_name:     Optional[str]         = None
    commission_type:  Optional[CommissionType] = None
    commission_rate:  Optional[Decimal]     = None
    currency:         Optional[str]         = None
    payment_method:   Optional[str]         = None
    bank_account_info:Optional[str]         = None
    is_active:        Optional[bool]        = None
    notes:            Optional[str]         = None


class ReferralAgentResponse(BaseModel):
    id:               uuid.UUID
    user_id:          uuid.UUID
    company_name:     Optional[str]
    commission_type:  CommissionType
    commission_rate:  Decimal
    currency:         str
    payment_method:   Optional[str]
    total_referrals:  int
    total_converted:  int
    total_earned:     Decimal
    is_active:        bool
    created_at:       datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# REFERRAL LEADS
# ─────────────────────────────────────────────

class ReferralLeadCreate(BaseModel):
    company_name:     str = Field(..., max_length=200)
    contact_name:     str = Field(..., max_length=200)
    contact_email:    EmailStr
    contact_phone:    Optional[str] = None
    estimated_value:  Optional[Decimal] = None
    notes:            Optional[str] = None


class ReferralLeadUpdate(BaseModel):
    status:       Optional[ReferralStatus] = None
    assigned_to:  Optional[uuid.UUID]      = None
    deal_value:   Optional[Decimal]        = None
    notes:        Optional[str]            = None


class ReferralLeadResponse(BaseModel):
    id:              uuid.UUID
    agent_id:        uuid.UUID
    company_name:    str
    contact_name:    str
    contact_email:   str
    contact_phone:   Optional[str]
    estimated_value: Optional[Decimal]
    deal_value:      Optional[Decimal]
    status:          ReferralStatus
    assigned_to:     Optional[uuid.UUID]
    converted_at:    Optional[datetime]
    submitted_at:    datetime
    updated_at:      datetime

    model_config = {"from_attributes": True}


class ReferralLeadListResponse(BaseModel):
    total: int
    page:  int
    size:  int
    items: List[ReferralLeadResponse]


# ─────────────────────────────────────────────
# COMMISSIONS
# ─────────────────────────────────────────────

class CommissionResponse(BaseModel):
    id:              uuid.UUID
    agent_id:        uuid.UUID
    lead_id:         Optional[uuid.UUID]
    commission_type: CommissionType
    rate:            Decimal
    deal_value:      Decimal
    amount:          Decimal
    currency:        str
    status:          CommissionStatus
    approved_by:     Optional[uuid.UUID]
    approved_at:     Optional[datetime]
    paid_at:         Optional[datetime]
    payment_ref:     Optional[str]
    notes:           Optional[str]
    created_at:      datetime

    model_config = {"from_attributes": True}


class CommissionApproveRequest(BaseModel):
    notes: Optional[str] = None


class CommissionPayRequest(BaseModel):
    payment_ref: str
    notes:       Optional[str] = None


class CommissionListResponse(BaseModel):
    total:      int
    page:       int
    size:       int
    items:      List[CommissionResponse]
    total_paid: Decimal = Decimal("0.00")


class CommissionSummary(BaseModel):
    agent_id:        uuid.UUID
    total_referrals: int
    total_converted: int
    conversion_rate: float
    total_earned:    Decimal
    total_pending:   Decimal
    total_paid:      Decimal
    currency:        str