from pydantic import Field, field_validator
from typing import Annotated
from nexo.enums.medical import (
    MedicalRole as MedicalRoleEnum,
    FullMedicalRoleMixin,
    ListOfMedicalRoles,
)
from nexo.enums.organization import (
    OrganizationRole as OrganizationRoleEnum,
    FullOrganizationRoleMixin,
    ListOfOrganizationRoles,
    OrganizationType,
)
from nexo.enums.status import DataStatus as DataStatusEnum
from nexo.enums.system import (
    SystemRole as SystemRoleEnum,
    FullSystemRoleMixin,
    ListOfSystemRoles,
)
from nexo.enums.user import UserType
from nexo.schemas.mixins.identity import RecordIdentifier, TypedRecord
from nexo.schemas.security.enums import DomainMixin, Domain


class UserSchema(TypedRecord[UserType]):
    username: Annotated[str, Field(..., description="User's username", max_length=50)]
    email: Annotated[str, Field(..., description="User's email", max_length=255)]


class OrganizationSchema(TypedRecord[OrganizationType]):
    key: Annotated[str, Field(..., description="Organization's key", max_length=255)]


class MedicalRoleSchema(
    FullMedicalRoleMixin[MedicalRoleEnum],
    RecordIdentifier,
):
    pass


class OrganizationRoleSchema(
    FullOrganizationRoleMixin[OrganizationRoleEnum],
    RecordIdentifier,
):
    pass


class SystemRoleSchema(
    FullSystemRoleMixin[SystemRoleEnum],
    RecordIdentifier,
):
    pass


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
        list[MedicalRoleSchema] | None,
        Field(..., description="Principal's medical roles"),
    ]

    @property
    def active_medical_roles(self) -> ListOfMedicalRoles | None:
        if self.medical_roles is None:
            return None
        return [
            mr.medical_role
            for mr in self.medical_roles
            if mr.status is DataStatusEnum.ACTIVE
        ]

    organization_roles: Annotated[
        list[OrganizationRoleSchema] | None,
        Field(..., description="Principal's organization roles"),
    ]

    @property
    def active_organization_roles(self) -> ListOfOrganizationRoles | None:
        if not self.organization_roles:
            return None
        return [
            por.organization_role
            for por in self.organization_roles
            if por.status is DataStatusEnum.ACTIVE
        ]

    system_roles: Annotated[
        list[SystemRoleSchema] | None,
        Field(..., description="Principal's system roles"),
    ]

    @property
    def active_system_roles(self) -> ListOfSystemRoles | None:
        if not self.system_roles:
            return None
        return [
            sr.system_role
            for sr in self.system_roles
            if sr.status is DataStatusEnum.ACTIVE
        ]
