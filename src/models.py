from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import Enum, Integer, String
from nexo.schemas.security.enums import Domain
from nexo.schemas.model import DataIdentifier, DataStatus
from nexo.types.integer import OptInt


class Base(DeclarativeBase):
    """Declarative Base"""


class MedicalRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "medical_roles"
    parent_id: Mapped[OptInt] = mapped_column(
        "parent_id",
        ForeignKey("medical_roles.id", ondelete="SET NULL", onupdate="CASCADE"),
    )
    order: Mapped[OptInt] = mapped_column(name="order")
    code: Mapped[str] = mapped_column(
        name="code", type_=String(20), unique=True, nullable=False
    )
    key: Mapped[str] = mapped_column(
        name="key", type_=String(255), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(
        name="name", type_=String(255), unique=True, nullable=False
    )

    parent: Mapped["MedicalRole | None"] = relationship(
        back_populates="children", remote_side="MedicalRole.id", lazy="select"
    )

    children: Mapped[list["MedicalRole"]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        lazy="select",
        order_by="MedicalRole.order",
    )

    principal_medical_roles: Mapped[list["PrincipalMedicalRole"]] = relationship(
        "PrincipalMedicalRole", back_populates="medical_role"
    )


class OrganizationRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "organization_roles_v2"
    order: Mapped[OptInt] = mapped_column(name="order")
    key: Mapped[str] = mapped_column(
        name="key", type_=String(20), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(
        name="name", type_=String(20), unique=True, nullable=False
    )

    principal_organization_roles: Mapped[list["PrincipalOrganizationRole"]] = (
        relationship("PrincipalOrganizationRole", back_populates="organization_role")
    )


class OrganizationType(DataStatus, DataIdentifier, Base):
    __tablename__ = "organization_types"
    key: Mapped[str] = mapped_column(
        name="key", type_=String(40), unique=True, nullable=False
    )

    organizations: Mapped[list["Organization"]] = relationship(
        "Organization",
        back_populates="organization_type",
    )


class SystemRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "system_roles"
    order: Mapped[OptInt] = mapped_column(name="order")
    key: Mapped[str] = mapped_column(
        name="key", type_=String(20), unique=True, nullable=False
    )
    name: Mapped[str] = mapped_column(
        name="name", type_=String(20), unique=True, nullable=False
    )

    principal_system_roles: Mapped[list["PrincipalSystemRole"]] = relationship(
        "PrincipalSystemRole", back_populates="system_role"
    )


class UserType(DataStatus, DataIdentifier, Base):
    __tablename__ = "user_types"
    key: Mapped[str] = mapped_column(
        name="key", type_=String(20), unique=True, nullable=False
    )

    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="user_type",
    )


class Organization(DataStatus, DataIdentifier, Base):
    __tablename__ = "organizations"

    organization_type_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("organization_types.id", ondelete="RESTRICT", onupdate="CASCADE"),
        default=1,
        nullable=False,
    )
    organization_type: Mapped["OrganizationType"] = relationship(
        "OrganizationType",
        back_populates="organizations",
    )

    key: Mapped[str] = mapped_column("key", String(255), unique=True, nullable=False)

    # relationships
    principals: Mapped[list["Principal"]] = relationship(
        "Principal",
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class User(DataStatus, DataIdentifier, Base):
    __tablename__ = "users"

    user_type_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("user_types.id", ondelete="RESTRICT", onupdate="CASCADE"),
        default=1,
        nullable=False,
    )
    user_type: Mapped["UserType"] = relationship(
        "UserType",
        back_populates="users",
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


class PrincipalMedicalRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "principal_medical_roles"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "medical_role_id",
            name="principal_medical_roles_principal_id_medical_role_id_key",
        ),
    )

    principal_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    principal: Mapped["Principal"] = relationship(
        "Principal",
        back_populates="medical_roles",
    )

    medical_role_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("medical_roles.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    medical_role: Mapped["MedicalRole"] = relationship(
        "MedicalRole",
        back_populates="principal_medical_roles",
    )


class PrincipalOrganizationRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "principal_organization_roles"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "organization_role_id",
            name="principal_organization_roles_principal_id_organization_role_id_key",
        ),
    )

    principal_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    principal: Mapped["Principal"] = relationship(
        "Principal",
        back_populates="organization_roles",
    )

    organization_role_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("organization_roles_v2.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_role: Mapped["OrganizationRole"] = relationship(
        "OrganizationRole",
        back_populates="principal_organization_roles",
    )


class PrincipalSystemRole(DataStatus, DataIdentifier, Base):
    __tablename__ = "principal_system_roles"
    __table_args__ = (
        UniqueConstraint(
            "principal_id",
            "system_role_id",
            name="principal_system_roles_principal_id_system_role_id_key",
        ),
    )

    principal_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("principals.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    principal: Mapped["Principal"] = relationship(
        "Principal",
        back_populates="system_roles",
    )

    system_role_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("system_roles.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    system_role: Mapped["SystemRole"] = relationship(
        "SystemRole",
        back_populates="principal_system_roles",
    )


class Principal(DataStatus, DataIdentifier, Base):
    __tablename__ = "principals"
    __table_args__ = (
        UniqueConstraint(
            "domain",
            "user_id",
            "organization_id",
            name="principals_domain_user_id_organization_id_key",
        ),
        # CHECK
        CheckConstraint(
            """
            (
                (domain IN ('PERSONAL', 'SYSTEM') AND organization_id IS NULL)
                OR
                (domain = 'TENANT' AND organization_id IS NOT NULL)
            )
            """,
            name="principals_check",
        ),
        # PERSONAL + SYSTEM → unique (domain, user_id)
        Index(
            "uniq_principals_personal_system",
            "domain",
            "user_id",
            unique=True,
            postgresql_where=text("domain IN ('PERSONAL', 'SYSTEM')"),
        ),
        # TENANT → unique (domain, user_id, organization_id)
        Index(
            "uniq_principals_tenant",
            "domain",
            "user_id",
            "organization_id",
            unique=True,
            postgresql_where=text("domain = 'TENANT'"),
        ),
    )

    domain: Mapped[Domain] = mapped_column(
        name="domain", type_=Enum(Domain, name="domain"), nullable=False
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    user: Mapped["User"] = relationship("User", back_populates="principals")

    organization_id: Mapped[OptInt] = mapped_column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
    )

    organization: Mapped["Organization | None"] = relationship(
        "Organization", back_populates="principals"
    )

    medical_roles: Mapped[list["PrincipalMedicalRole"]] = relationship(
        "PrincipalMedicalRole", back_populates="principal"
    )

    organization_roles: Mapped[list["PrincipalOrganizationRole"]] = relationship(
        "PrincipalOrganizationRole", back_populates="principal"
    )

    system_roles: Mapped[list["PrincipalSystemRole"]] = relationship(
        "PrincipalSystemRole", back_populates="principal"
    )

    api_key: Mapped["APIKey | None"] = relationship(
        "APIKey", back_populates="principal"
    )


class APIKey(DataStatus, DataIdentifier, Base):
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

    principal: Mapped["Principal"] = relationship("Principal", back_populates="api_key")
