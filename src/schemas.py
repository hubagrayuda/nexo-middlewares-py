from Crypto.PublicKey import RSA
from pydantic import Field, field_validator
from typing import Annotated
from uuid import UUID
from nexo.crypto.key.rsa.enums import KeyType
from nexo.crypto.key.rsa.loader import with_pycryptodome
from nexo.enums.status import DataStatus, SimpleDataStatusMixin
from nexo.schemas.mixins.identity import (
    SimpleDataIdentifier,
    RecordIdentifier,
)
from nexo.schemas.security.enums import DomainMixin, Domain
from nexo.types.string import ListOfStrs


class ClientSchema(
    SimpleDataStatusMixin[DataStatus],
    SimpleDataIdentifier,
):
    secret: Annotated[UUID, Field(..., description="Client's Secret")]
    public_key: Annotated[str, Field(..., description="Client's Public Key")]

    @property
    def rsa_public_key(self) -> RSA.RsaKey:
        return with_pycryptodome(KeyType.PUBLIC, extern_key=self.public_key)


class OrganizationTypeSchema(RecordIdentifier):
    key: str = Field(..., max_length=40, description="Organization type's key")


class OrganizationSchema(RecordIdentifier):
    organization_type: Annotated[
        OrganizationTypeSchema, Field(..., description="Organization's type")
    ]
    key: Annotated[str, Field(..., description="Organization's key", max_length=255)]


class UserTypeSchema(RecordIdentifier):
    key: str = Field(..., max_length=20, description="User type's key")


class UserSchema(RecordIdentifier):
    user_type: Annotated[UserTypeSchema, Field(..., description="User's type")]
    username: Annotated[str, Field(..., description="User's username", max_length=50)]
    email: Annotated[str, Field(..., description="User's email", max_length=255)]


class MedicalRoleSchema(RecordIdentifier):
    key: str = Field(..., max_length=255, description="Medical role's key")


class PrincipalMedicalRoleSchema(RecordIdentifier):
    medical_role: Annotated[
        MedicalRoleSchema, Field(..., description="Principal's Medical Role")
    ]


class OrganizationRoleSchema(RecordIdentifier):
    key: str = Field(..., max_length=20, description="Organization role's key")


class PrincipalOrganizationRoleSchema(RecordIdentifier):
    organization_role: Annotated[
        OrganizationRoleSchema, Field(..., description="Principal's Organization Role")
    ]


class SystemRoleSchema(RecordIdentifier):
    key: str = Field(..., max_length=20, description="System role's key")


class PrincipalSystemRoleSchema(RecordIdentifier):
    system_role: Annotated[
        SystemRoleSchema, Field(..., description="Principal's System Role")
    ]


class PrincipalSchema(
    DomainMixin[Domain],
    RecordIdentifier,
):
    user: Annotated[UserSchema, Field(..., description="Principal's user")]
    organization: Annotated[
        OrganizationSchema | None, Field(..., description="Principal's organization")
    ]

    @field_validator(
        "medical_roles",
        "organization_roles",
        "system_roles",
        mode="before",
    )
    @classmethod
    def empty_list_to_none(cls, v):
        if isinstance(v, list) and not v:
            return None
        return v

    medical_roles: Annotated[
        list[PrincipalMedicalRoleSchema] | None,
        Field(..., description="Principal's medical roles"),
    ]

    @property
    def active_medical_roles(self) -> ListOfStrs | None:
        if self.medical_roles is None:
            return None
        return [
            pmr.medical_role.key
            for pmr in self.medical_roles
            if (
                pmr.status is DataStatus.ACTIVE
                and pmr.medical_role.status is DataStatus.ACTIVE
            )
        ]

    organization_roles: Annotated[
        list[PrincipalOrganizationRoleSchema] | None,
        Field(..., description="Principal's organization roles"),
    ]

    @property
    def active_organization_roles(self) -> ListOfStrs | None:
        if not self.organization_roles:
            return None
        return [
            por.organization_role.key
            for por in self.organization_roles
            if (
                por.status is DataStatus.ACTIVE
                and por.organization_role.status is DataStatus.ACTIVE
            )
        ]

    system_roles: Annotated[
        list[PrincipalSystemRoleSchema] | None,
        Field(..., description="Principal's system roles"),
    ]

    @property
    def active_system_roles(self) -> ListOfStrs | None:
        if not self.system_roles:
            return None
        return [
            psr.system_role.key
            for psr in self.system_roles
            if (
                psr.status is DataStatus.ACTIVE
                and psr.system_role.status is DataStatus.ACTIVE
            )
        ]
