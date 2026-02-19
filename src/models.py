from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import Enum, Integer, String
from nexo.enums.medical import MedicalRole
from nexo.enums.organization import (
    OrganizationRole,
    OrganizationType,
)
from nexo.enums.system import SystemRole
from nexo.enums.user import UserType
from nexo.schemas.security.enums import Domain
from nexo.schemas.model import DataIdentifier, DataStatus
from nexo.types.integer import OptInt


class Base(DeclarativeBase):
    """Declarative Base"""


class User(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "users"
    type: Mapped[UserType] = mapped_column(
        "user_type", Enum(UserType, name="user_type"), nullable=False
    )
    username: Mapped[str] = mapped_column(
        "username", String(50), unique=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        "email", String(255), unique=True, nullable=False
    )

    # relationships
    principals: Mapped[list["Principal"]] = relationship(
        "Principal",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Organization(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "organizations"
    type: Mapped[OrganizationType] = mapped_column(
        "organization_type",
        Enum(OrganizationType, name="organization_type"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column("key", String(255), unique=True, nullable=False)

    # relationships
    principals: Mapped[list["Principal"]] = relationship(
        "Principal",
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class Principal(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "principals"
    domain: Mapped[Domain] = mapped_column(
        "domain", Enum(Domain, name="domain"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[OptInt] = mapped_column(
        "organization_id",
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="principals")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="principals"
    )
    api_key: Mapped["APIKey | None"] = relationship(
        "APIKey", back_populates="principal"
    )
    medical_roles: Mapped[list["PrincipalMedicalRole"]] = relationship(
        "PrincipalMedicalRole",
        back_populates="principal",
        cascade="all, delete-orphan",
    )
    organization_roles: Mapped[list["PrincipalOrganizationRole"]] = relationship(
        "PrincipalOrganizationRole",
        back_populates="principal",
        cascade="all, delete-orphan",
    )
    system_roles: Mapped[list["PrincipalSystemRole"]] = relationship(
        "PrincipalSystemRole",
        back_populates="principal",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("domain", "user_id", "organization_id"),
        # CHECK
        CheckConstraint(
            "(domain IN ('PERSONAL', 'SYSTEM') AND organization_id IS NULL) "
            "OR (domain = 'TENANT' AND organization_id IS NOT NULL)",
            name="principals_check",
        ),
        # PERSONAL + SYSTEM
        Index(
            "uniq_principals_personal_system",
            "domain",
            "user_id",
            unique=True,
            postgresql_where=(domain.in_(["PERSONAL", "SYSTEM"])),
        ),
        # TENANT
        Index(
            "uniq_principals_tenant",
            "domain",
            "user_id",
            "organization_id",
            unique=True,
            postgresql_where=(domain == "TENANT"),
        ),
    )


class APIKey(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "api_keys_v2"
    principal_id: Mapped[int] = mapped_column(
        "principal_id",
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    api_key: Mapped[str] = mapped_column(
        "api_key", String(255), unique=True, nullable=False
    )

    # relationships
    principal: Mapped["Principal"] = relationship("Principal", back_populates="api_key")


class PrincipalMedicalRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "principal_medical_roles"
    principal_id: Mapped[int] = mapped_column(
        "principal_id",
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    medical_role: Mapped[MedicalRole] = mapped_column(
        "medical_role",
        Enum(MedicalRole, name="medical_role"),
        nullable=False,
    )

    # relationships
    principal: Mapped["Principal"] = relationship(
        "Principal", back_populates="medical_roles"
    )

    __table_args__ = (UniqueConstraint("principal_id", "medical_role"),)


class PrincipalOrganizationRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "principal_organization_roles"
    principal_id: Mapped[int] = mapped_column(
        "principal_id",
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_role: Mapped[OrganizationRole] = mapped_column(
        "organization_role",
        Enum(OrganizationRole, name="organization_role"),
        nullable=False,
    )

    # relationships
    principal: Mapped["Principal"] = relationship(
        "Principal", back_populates="organization_roles"
    )

    __table_args__ = (UniqueConstraint("principal_id", "organization_role"),)


class PrincipalSystemRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "principal_system_roles"
    principal_id: Mapped[int] = mapped_column(
        "principal_id",
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    system_role: Mapped[SystemRole] = mapped_column(
        "system_role",
        Enum(SystemRole, name="system_role"),
        nullable=False,
    )

    # relationships
    principal: Mapped["Principal"] = relationship(
        "Principal", back_populates="system_roles"
    )

    __table_args__ = (UniqueConstraint("principal_id", "system_role"),)
