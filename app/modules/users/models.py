"""
TEHTEK ERP — User Module Models
Database: PostgreSQL | ORM: SQLAlchemy 2.0 sync
"""

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer,
    Numeric, String, Text, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class UserType(str, enum.Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    REFERRAL = "referral"


class ReferralStatus(str, enum.Enum):
    SUBMITTED = "submitted"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    CONVERTED = "converted"
    LOST = "lost"


class CommissionStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    PAID = "paid"
    CANCELLED = "cancelled"


class CommissionType(str, enum.Enum):
    PERCENTAGE = "percentage"
    FLAT = "flat"


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    module = Column(String(60), nullable=False)
    action = Column(String(60), nullable=False)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    roles = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("module", "action", name="uq_permission_module_action"),
    )

    @property
    def code(self):
        return f"{self.module}:{self.action}"


class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    department = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    users = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow)

    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone = Column(String(30), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    user_type = Column(SAEnum(UserType), default=UserType.INTERNAL, nullable=False)
    status = Column(SAEnum(UserStatus), default=UserStatus.PENDING, nullable=False)
    department = Column(String(100), nullable=True)
    job_title = Column(String(150), nullable=True)
    avatar_url = Column(String(500), nullable=True)

    is_superadmin = Column(Boolean, default=False)
    last_login = Column(DateTime, nullable=True)
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)

    reset_token = Column(String(255), nullable=True)
    reset_token_expiry = Column(DateTime, nullable=True)

    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)

    roles = relationship(
        "UserRole",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserRole.user_id",
    )

    referral_profile = relationship(
        "ReferralAgent",
        back_populates="user",
        uselist=False,
        foreign_keys="ReferralAgent.user_id",
    )

    audit_logs = relationship(
        "UserAuditLog",
        back_populates="user",
        foreign_keys="UserAuditLog.user_id",
        cascade="all, delete-orphan",
    )

    created_users = relationship(
        "User",
        remote_side=[id],
        foreign_keys=[created_by],
    )

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def is_active(self):
        return self.status == UserStatus.ACTIVE


class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    user = relationship("User", foreign_keys=[user_id], back_populates="roles")
    role = relationship("Role", back_populates="users")
    assigned_by_user = relationship("User", foreign_keys=[assigned_by])

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_role"),
    )


class ReferralAgent(Base):
    __tablename__ = "referral_agents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    company_name = Column(String(200), nullable=True)
    commission_type = Column(SAEnum(CommissionType), default=CommissionType.PERCENTAGE, nullable=False)
    commission_rate = Column(Numeric(5, 2), nullable=False)
    currency = Column(String(10), default="USD")
    payment_method = Column(String(100), nullable=True)
    bank_account_info = Column(Text, nullable=True)
    total_referrals = Column(Integer, default=0)
    total_converted = Column(Integer, default=0)
    total_earned = Column(Numeric(14, 2), default=Decimal("0.00"))
    is_active = Column(Boolean, default=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="referral_profile", foreign_keys=[user_id])
    leads = relationship("ReferralLead", back_populates="agent", cascade="all, delete-orphan")
    commissions = relationship("Commission", back_populates="agent", cascade="all, delete-orphan")


class ReferralLead(Base):
    __tablename__ = "referral_leads"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("referral_agents.id", ondelete="CASCADE"), nullable=False)
    company_name = Column(String(200), nullable=False)
    contact_name = Column(String(200), nullable=False)
    contact_email = Column(String(255), nullable=False)
    contact_phone = Column(String(50), nullable=True)
    estimated_value = Column(Numeric(14, 2), nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(SAEnum(ReferralStatus), default=ReferralStatus.SUBMITTED, nullable=False)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    converted_at = Column(DateTime, nullable=True)
    deal_value = Column(Numeric(14, 2), nullable=True)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = relationship("ReferralAgent", back_populates="leads")
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    commission = relationship("Commission", back_populates="lead", uselist=False)


class Commission(Base):
    __tablename__ = "commissions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("referral_agents.id", ondelete="CASCADE"), nullable=False)
    lead_id = Column(UUID(as_uuid=True), ForeignKey("referral_leads.id"), nullable=True)
    commission_type = Column(SAEnum(CommissionType), nullable=False)
    rate = Column(Numeric(5, 2), nullable=False)
    deal_value = Column(Numeric(14, 2), nullable=False)
    amount = Column(Numeric(14, 2), nullable=False)
    currency = Column(String(10), default="USD")
    status = Column(SAEnum(CommissionStatus), default=CommissionStatus.PENDING, nullable=False)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    paid_at = Column(DateTime, nullable=True)
    payment_ref = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    agent = relationship("ReferralAgent", back_populates="commissions")
    lead = relationship("ReferralLead", back_populates="commission")
    approved_by_user = relationship("User", foreign_keys=[approved_by])


class UserAuditLog(Base):
    __tablename__ = "user_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    actor_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    detail = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id], back_populates="audit_logs")
    actor = relationship("User", foreign_keys=[actor_id])
