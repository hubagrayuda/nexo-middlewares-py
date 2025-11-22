from pydantic import BaseModel, Field
from typing import Annotated
from uuid import UUID
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
    SimpleOrganizationTypeMixin,
)
from nexo.enums.status import DataStatus as DataStatusEnum, SimpleDataStatusMixin
from nexo.enums.system import (
    SystemRole as SystemRoleEnum,
    FullSystemRoleMixin,
    ListOfSystemRoles,
)
from nexo.enums.user import UserType, SimpleUserTypeMixin
from nexo.schemas.mixins.identity import (
    DataIdentifier,
    Key,
    IntOrganizationId,
    IntUserId,
    UUIDOrganizationId,
    UUIDUserId,
)
from nexo.types.uuid import OptUUID


class MedicalRoleSchema(
    FullMedicalRoleMixin[MedicalRoleEnum],
    IntOrganizationId[int],
    IntUserId[int],
    SimpleDataStatusMixin[DataStatusEnum],
    DataIdentifier,
):
    pass


ListOfMedicalRoleSchemas = list[MedicalRoleSchema]


class OrganizationRoleSchema(
    FullOrganizationRoleMixin[OrganizationRoleEnum],
    IntOrganizationId[int],
    IntUserId[int],
    SimpleDataStatusMixin[DataStatusEnum],
    DataIdentifier,
):
    pass


ListOfOrganizationRoleSchemas = list[OrganizationRoleSchema]


class SystemRoleSchema(
    FullSystemRoleMixin[SystemRoleEnum],
    IntUserId[int],
    SimpleDataStatusMixin[DataStatusEnum],
    DataIdentifier,
):
    pass


ListOfSystemRoleSchemas = list[SystemRoleSchema]


class OrganizationSchema(
    Key[str],
    SimpleOrganizationTypeMixin[OrganizationType],
    SimpleDataStatusMixin[DataStatusEnum],
    DataIdentifier,
):
    key: Annotated[str, Field(..., description="Organization's key", max_length=255)]


OptOrganizationSchema = OrganizationSchema | None


class OrganizationSchemaMixin(BaseModel):
    organization: Annotated[OrganizationSchema, Field(..., description="Organization")]


class UserOrganizationSchema(
    OrganizationSchemaMixin,
    IntOrganizationId[int],
    IntUserId[int],
    SimpleDataStatusMixin[DataStatusEnum],
    DataIdentifier,
):
    pass


OptUserOrganizationSchema = UserOrganizationSchema | None
ListOfUserOrganizationSchemas = list[UserOrganizationSchema]


class UserSchema(
    SimpleUserTypeMixin[UserType], SimpleDataStatusMixin[DataStatusEnum], DataIdentifier
):
    username: Annotated[str, Field(..., description="User's username", max_length=50)]
    email: Annotated[str, Field(..., description="User's email", max_length=255)]
    medical_roles: Annotated[
        ListOfMedicalRoleSchemas, Field(..., description="User's medical roles")
    ]
    organization_roles: Annotated[
        ListOfOrganizationRoleSchemas,
        Field(..., description="User's organization roles"),
    ]
    organizations: Annotated[
        ListOfUserOrganizationSchemas, Field(..., description="User's organization")
    ]
    system_roles: Annotated[
        ListOfSystemRoleSchemas, Field(..., description="User's system roles")
    ]

    def get_active_medical_roles(self, organization_id: int) -> ListOfMedicalRoles:
        return [
            mr.medical_role
            for mr in self.medical_roles
            if mr.status is DataStatusEnum.ACTIVE
            and mr.organization_id == organization_id
        ]

    def get_active_organization_roles(
        self, organization_id: int
    ) -> ListOfOrganizationRoles:
        return [
            uor.organization_role
            for uor in self.organization_roles
            if uor.status is DataStatusEnum.ACTIVE
            and uor.organization_id == organization_id
        ]

    def get_active_system_roles(self) -> ListOfSystemRoles:
        return [
            sr.system_role
            for sr in self.system_roles
            if sr.status is DataStatusEnum.ACTIVE
        ]


OptUserSchema = UserSchema | None


class UserOrganizationIdSchema(UUIDOrganizationId[OptUUID], UUIDUserId[UUID]):
    pass
