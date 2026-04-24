"""
ERP User Module — SQLAlchemy Models
Database: PostgreSQL | ORM: SQLAlchemy 2.0 (async)
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer,
    Numeric, String, Text, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, DeclarativeBase
import enum


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class UserStatus(str, enum.Enum):
    ACTIVE      = "active"
    INACTIVE    = "inactive"
    SUSPENDED   = "suspended"
    PENDING     = "pending"


class UserType(str, enum.Enum):
    INTERNAL    = "internal"    # employees / staff
    EXTERNAL    = "external"    # customers, vendors, portal users
    REFERRAL    = "referral"    # referral/commission agents


class ReferralStatus(str, enum.Enum):
    SUBMITTED   = "submitted"
    CONTACTED   = "contacted"
    QUALIFIED   = "qualified"
    CONVERTED   = "converted"
    LOST        = "lost"


class CommissionStatus(str, enum.Enum):
    PENDING     = "pending"
    APPROVED    = "approved"
    PAID        = "paid"
    CANCELLED   = "cancelled"


class CommissionType(str, enum.Enum):
    PERCENTAGE  = "percentage"
    FLAT        = "flat"


# ─────────────────────────────────────────────
# PERMISSIONS
# ─────────────────────────────────────────────

class Permission(Base):
    """
    Granular permissions (e.g. users:read, invoices:approve).
    Format: <module>:<action>
    """
    __tablename__ = "permissions"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    module      = Column(String(60), nullable=False)            # e.g. "users", "payroll"
    action      = Column(String(60), nullable=False)            # e.g. "read", "write", "approve"
    description = Column(String(255), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    roles = relationship("RolePermission", back_populates="permission")

    __table_args__ = (UniqueConstraint("module", "action", name="uq_permission_module_action"),)

    @property
    def code(self):
        return f"{self.module}:{self.action}"

    def __repr__(self):
        return f"<Permission {self.code}>"


# ─────────────────────────────────────────────
# ROLES
# ─────────────────────────────────────────────

class Role(Base):
    """
    Named roles grouping multiple permissions.
    Covers all 40 ERP roles defined in the module spec.
    """
    __tablename__ = "roles"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(100), unique=True, nullable=False)   # e.g. "Sales Manager"
    slug        = Column(String(100), unique=True, nullable=False)   # e.g. "sales_manager"
    department  = Column(String(100), nullable=True)                 # e.g. "Finance", "HR"
    description = Column(Text, nullable=True)
    is_system   = Column(Boolean, default=False)   # system roles cannot be deleted
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    users       = relationship("UserRole", back_populates="role")

    def __repr__(self):
        return f"<Role {self.name}>"


class RolePermission(Base):
    """Association: Role ↔ Permission"""
    __tablename__ = "role_permissions"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id       = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)
    granted_at    = Column(DateTime, default=datetime.utcnow)

    role       = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),)


# ─────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────

class User(Base):
    """
    Core user entity. Covers all user types:
    internal staff, external portal users, and referral agents.
    """
    __tablename__ = "users"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email           = Column(String(255), unique=True, nullable=False, index=True)
    phone           = Column(String(30), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    first_name      = Column(String(100), nullable=False)
    last_name       = Column(String(100), nullable=False)
    user_type       = Column(SAEnum(UserType), default=UserType.INTERNAL, nullable=False)
    status          = Column(SAEnum(UserStatus), default=UserStatus.PENDING, nullable=False)
    department      = Column(String(100), nullable=True)
    job_title       = Column(String(150), nullable=True)
    avatar_url      = Column(String(500), nullable=True)

    # Auth
    is_superadmin       = Column(Boolean, default=False)
    last_login          = Column(DateTime, nullable=True)
    failed_login_count  = Column(Integer, default=0)
    locked_until        = Column(DateTime, nullable=True)

    # Multi-factor
    mfa_enabled     = Column(Boolean, default=False)
    mfa_secret      = Column(String(255), nullable=True)

    # Password reset
    reset_token         = Column(String(255), nullable=True)
    reset_token_expiry  = Column(DateTime, nullable=True)

    # Audit
    created_by  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at  = Column(DateTime, nullable=True)   # soft delete

    # Relationships
    roles           = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    referral_profile= relationship("ReferralAgent", back_populates="user", uselist=False)
    audit_logs      = relationship("UserAuditLog", back_populates="user")

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def is_active(self):
        return self.status == UserStatus.ACTIVE

    def __repr__(self):
        return f"<User {self.email}>"


class UserRole(Base):
    """Association: User ↔ Role (a user can have multiple roles)"""
    __tablename__ = "user_roles"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id     = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    expires_at  = Column(DateTime, nullable=True)   # optional time-bound role assignment

    user = relationship("User", foreign_keys=[user_id], back_populates="roles")
    role = relationship("Role", back_populates="users")

    __table_args__ = (UniqueConstraint("user_id", "role_id", name="uq_user_role"),)


# ─────────────────────────────────────────────
# REFERRAL & COMMISSION
# ─────────────────────────────────────────────

class ReferralAgent(Base):
    """
    Extended profile for users with type=REFERRAL.
    Tracks commission structure and payment details.
    """
    __tablename__ = "referral_agents"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id             = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    company_name        = Column(String(200), nullable=True)
    commission_type     = Column(SAEnum(CommissionType), default=CommissionType.PERCENTAGE, nullable=False)
    commission_rate     = Column(Numeric(5, 2), nullable=False)   # e.g. 10.00 = 10% or flat 500.00
    currency            = Column(String(10), default="USD")
    payment_method      = Column(String(100), nullable=True)      # e.g. "bank_transfer", "mobile_money"
    bank_account_info   = Column(Text, nullable=True)             # encrypted in production
    total_referrals     = Column(Integer, default=0)
    total_converted     = Column(Integer, default=0)
    total_earned        = Column(Numeric(14, 2), default=Decimal("0.00"))
    is_active           = Column(Boolean, default=True)
    notes               = Column(Text, nullable=True)
    created_at          = Column(DateTime, default=datetime.utcnow)
    updated_at          = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user        = relationship("User", back_populates="referral_profile")
    leads       = relationship("ReferralLead", back_populates="agent")
    commissions = relationship("Commission", back_populates="agent")

    def __repr__(self):
        return f"<ReferralAgent user_id={self.user_id} rate={self.commission_rate}>"


class ReferralLead(Base):
    """A business lead submitted by a referral agent."""
    __tablename__ = "referral_leads"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id            = Column(UUID(as_uuid=True), ForeignKey("referral_agents.id", ondelete="CASCADE"), nullable=False)
    company_name        = Column(String(200), nullable=False)
    contact_name        = Column(String(200), nullable=False)
    contact_email       = Column(String(255), nullable=False)
    contact_phone       = Column(String(50), nullable=True)
    estimated_value     = Column(Numeric(14, 2), nullable=True)
    notes               = Column(Text, nullable=True)
    status              = Column(SAEnum(ReferralStatus), default=ReferralStatus.SUBMITTED, nullable=False)
    assigned_to         = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)  # sales rep
    converted_at        = Column(DateTime, nullable=True)
    deal_value          = Column(Numeric(14, 2), nullable=True)   # final closed value
    submitted_at        = Column(DateTime, default=datetime.utcnow)
    updated_at          = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent       = relationship("ReferralAgent", back_populates="leads")
    commission  = relationship("Commission", back_populates="lead", uselist=False)

    def __repr__(self):
        return f"<ReferralLead {self.company_name} [{self.status}]>"


class Commission(Base):
    """Commission record generated when a referral lead is converted."""
    __tablename__ = "commissions"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id        = Column(UUID(as_uuid=True), ForeignKey("referral_agents.id", ondelete="CASCADE"), nullable=False)
    lead_id         = Column(UUID(as_uuid=True), ForeignKey("referral_leads.id"), nullable=True)
    commission_type = Column(SAEnum(CommissionType), nullable=False)
    rate            = Column(Numeric(5, 2), nullable=False)
    deal_value      = Column(Numeric(14, 2), nullable=False)
    amount          = Column(Numeric(14, 2), nullable=False)   # calculated commission
    currency        = Column(String(10), default="USD")
    status          = Column(SAEnum(CommissionStatus), default=CommissionStatus.PENDING, nullable=False)
    approved_by     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at     = Column(DateTime, nullable=True)
    paid_at         = Column(DateTime, nullable=True)
    payment_ref     = Column(String(255), nullable=True)
    notes           = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = relationship("ReferralAgent", back_populates="commissions")
    lead  = relationship("ReferralLead", back_populates="commission")

    def __repr__(self):
        return f"<Commission {self.amount} {self.currency} [{self.status}]>"


# ─────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────

class UserAuditLog(Base):
    """Tracks all sensitive actions performed on/by a user."""
    __tablename__ = "user_audit_logs"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    actor_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)   # who did the action
    action      = Column(String(100), nullable=False)    # e.g. "login", "role_assigned", "password_reset"
    detail      = Column(Text, nullable=True)
    ip_address  = Column(String(50), nullable=True)
    user_agent  = Column(String(500), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id], back_populates="audit_logs")