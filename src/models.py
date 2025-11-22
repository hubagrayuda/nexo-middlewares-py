from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import Enum, Integer, String
from nexo.enums.medical import MedicalRole, ListOfMedicalRoles
from nexo.enums.organization import (
    OrganizationRole,
    ListOfOrganizationRoles,
    OrganizationType,
)
from nexo.enums.status import OptListOfDataStatuses, FULL_DATA_STATUSES
from nexo.enums.system import SystemRole, ListOfSystemRoles
from nexo.enums.user import UserType
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
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    medical_roles: Mapped[list["UserMedicalRole"]] = relationship(
        "UserMedicalRole",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    organization_roles: Mapped[list["UserOrganizationRole"]] = relationship(
        "UserOrganizationRole",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    organizations: Mapped[list["UserOrganization"]] = relationship(
        "UserOrganization",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    system_roles: Mapped[list["UserSystemRole"]] = relationship(
        "UserSystemRole",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def get_organization_roles(
        self, organization_id: int, statuses: OptListOfDataStatuses = None
    ) -> ListOfOrganizationRoles:
        if not statuses:
            statuses = FULL_DATA_STATUSES
        return [
            uor.organization_role
            for uor in self.organization_roles
            if uor.status in statuses and uor.organization_id == organization_id
        ]

    def get_medical_roles(
        self, organization_id: int, statuses: OptListOfDataStatuses = None
    ) -> ListOfMedicalRoles:
        if not statuses:
            statuses = FULL_DATA_STATUSES
        return [
            umr.medical_role
            for umr in self.medical_roles
            if umr.status in statuses and umr.organization_id == organization_id
        ]

    def get_system_roles(
        self, statuses: OptListOfDataStatuses = None
    ) -> ListOfSystemRoles:
        if not statuses:
            statuses = FULL_DATA_STATUSES
        return [usr.system_role for usr in self.system_roles if usr.status in statuses]


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
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    medical_roles: Mapped[list["UserMedicalRole"]] = relationship(
        "UserMedicalRole",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    user_roles: Mapped[list["UserOrganizationRole"]] = relationship(
        "UserOrganizationRole",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    users: Mapped[list["UserOrganization"]] = relationship(
        "UserOrganization",
        back_populates="organization",
        cascade="all, delete-orphan",
    )


class UserOrganization(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "user_organizations"
    user_id: Mapped[int] = mapped_column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[int] = mapped_column(
        "organization_id",
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="organizations")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="users"
    )

    __table_args__ = (UniqueConstraint("user_id", "organization_id"),)


class APIKey(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "api_keys"
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
    api_key: Mapped[str] = mapped_column(
        "api_key", String(255), unique=True, nullable=False
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")
    organization: Mapped["Organization | None"] = relationship(
        "Organization", back_populates="api_keys"
    )

    __table_args__ = (UniqueConstraint("user_id", "organization_id", "api_key"),)


class UserMedicalRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "user_medical_roles"
    user_id: Mapped[int] = mapped_column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[int] = mapped_column(
        "organization_id",
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    medical_role: Mapped[MedicalRole] = mapped_column(
        "medical_role",
        Enum(MedicalRole, name="medical_role"),
        nullable=False,
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="medical_roles")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="medical_roles"
    )

    __table_args__ = (UniqueConstraint("user_id", "organization_id", "medical_role"),)


class UserOrganizationRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "user_organization_roles_v2"
    user_id: Mapped[int] = mapped_column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[int] = mapped_column(
        "organization_id",
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    organization_role: Mapped[OrganizationRole] = mapped_column(
        "organization_role",
        Enum(OrganizationRole, name="organization_role"),
        nullable=False,
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="organization_roles")
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="user_roles"
    )

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", "organization_role"),
    )


class UserSystemRole(
    DataStatus,
    DataIdentifier,
    Base,
):
    __tablename__ = "user_system_roles"
    user_id: Mapped[int] = mapped_column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    system_role: Mapped[SystemRole] = mapped_column(
        "system_role", Enum(SystemRole, name="system_role"), nullable=False
    )

    # relationships
    user: Mapped["User"] = relationship("User", back_populates="system_roles")

    __table_args__ = (UniqueConstraint("user_id", "system_role"),)
