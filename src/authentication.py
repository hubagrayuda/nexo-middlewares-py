from Crypto.PublicKey.RSA import RsaKey
from datetime import datetime, timezone
from fastapi.requests import HTTPConnection
from starlette.authentication import AuthenticationBackend, AuthenticationError
from typing import Tuple, overload
from uuid import UUID
from nexo.database.handlers import PostgreSQLHandler, RedisHandler
from nexo.enums.organization import OrganizationRole
from nexo.schemas.application import ApplicationContext, OptApplicationContext
from nexo.schemas.connection import ConnectionContext
from nexo.schemas.security.api_key import validate as validate_api_key
from nexo.schemas.security.authentication import (
    RequestCredentials,
    RequestUser,
    BaseAuthentication,
    BaseCredentials,
    BaseUser,
    is_authenticated,
    is_tenant,
)
from nexo.schemas.security.authorization import (
    BaseAuthorization,
    BearerTokenAuthorization,
    APIKeyAuthorization,
    is_bearer_token,
    is_api_key,
)
from nexo.schemas.security.impersonation import Impersonation
from nexo.schemas.security.token import Domain
from nexo.types.datetime import OptDatetime
from nexo.types.uuid import OptUUID
from .identity import IdentityProvider
from .models import Base
from .schemas import UserSchema, OrganizationSchema, OptOrganizationSchema


class Backend(AuthenticationBackend):
    def __init__(
        self,
        *,
        application_context: OptApplicationContext = None,
        database: PostgreSQLHandler[Base],
        cache: RedisHandler,
        public_key: RsaKey,
    ):
        super().__init__()
        self._application_context = (
            application_context
            if application_context is not None
            else ApplicationContext.new()
        )
        self._database = database
        self._cache = cache
        self._identity_provider = IdentityProvider(database=database, cache=cache)
        self._public_key = public_key

    @overload
    async def _get_credentials(
        self,
        user_id: UUID,
        organization_id: UUID,
        exp: OptDatetime = None,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[UserSchema, OrganizationSchema]: ...

    @overload
    async def _get_credentials(
        self,
        user_id: UUID,
        organization_id: None = None,
        exp: OptDatetime = None,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[UserSchema, None]: ...
    async def _get_credentials(
        self,
        user_id: UUID,
        organization_id: OptUUID = None,
        exp: OptDatetime = None,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[UserSchema, OptOrganizationSchema]:
        user = await self._identity_provider.get_user(
            user_id,
            exp,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        if organization_id is None:
            organization = None
        else:
            organization = await self._identity_provider.get_organization(
                organization_id,
                exp,
                operation_id=operation_id,
                connection_context=connection_context,
            )

        return user, organization

    def _build_authentication_component(
        self, user: UserSchema, organization: OptOrganizationSchema
    ) -> Tuple[RequestCredentials, RequestUser]:
        req_user = RequestUser(
            authenticated=True,
            organization=None if organization is None else organization.key,
            username=user.username,
            email=user.email,
        )
        if organization is None:
            domain = Domain.SYSTEM
            domain_roles = user.get_active_system_roles()
            scopes = ["authenticated", domain] + [
                f"{domain}:{role}" for role in domain_roles
            ]
            if not len(domain_roles) >= 1:
                raise ValueError("Can not find active system roles")
            req_credentials = RequestCredentials(
                domain=domain,
                user_id=user.id,
                user_uuid=user.uuid,
                user_type=user.type,
                domain_roles=domain_roles,
                scopes=scopes,
            )
        else:
            domain = Domain.TENANT
            domain_roles = user.get_active_organization_roles(organization.id)
            medical_roles = user.get_active_medical_roles(organization.id)
            scopes = (
                ["authenticated", domain]
                + [f"{domain}:{role}" for role in domain_roles]
                + [f"medical:{role}" for role in medical_roles]
            )
            if not len(domain_roles) >= 1:
                raise ValueError("Can not find active organization roles")
            req_credentials = RequestCredentials(
                domain=domain,
                user_id=user.id,
                user_uuid=user.uuid,
                user_type=user.type,
                organization_id=organization.id,
                organization_uuid=organization.uuid,
                organization_type=organization.type,
                domain_roles=domain_roles,
                medical_roles=medical_roles,
                scopes=scopes,
            )
        return req_credentials, req_user

    async def _authenticate_api_key(
        self,
        authorization: APIKeyAuthorization,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[RequestCredentials, RequestUser]:
        validate_api_key(
            authorization.credentials,
            self._application_context.name,
            self._application_context.environment,
        )
        user_organization_id = (
            await self._identity_provider.get_user_organization_id_from_api_key(
                api_key=authorization.credentials,
                operation_id=operation_id,
                connection_context=connection_context,
            )
        )

        user = await self._identity_provider.get_user(
            user_organization_id.user_id,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        organization = None
        organization_id = user_organization_id.organization_id
        if organization_id is not None:
            organization = await self._identity_provider.get_organization(
                organization_id,
                operation_id=operation_id,
                connection_context=connection_context,
            )

        user, organization = await self._get_credentials(
            user_organization_id.user_id,
            user_organization_id.organization_id,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        return self._build_authentication_component(user, organization)

    async def _authenticate_bearer_token(
        self,
        authorization: BearerTokenAuthorization,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[RequestCredentials, RequestUser]:
        token = authorization.parse_token(key=self._public_key)

        user, organization = await self._get_credentials(
            token.sub,
            token.o,
            datetime.fromtimestamp(token.exp, tz=timezone.utc),
            operation_id=operation_id,
            connection_context=connection_context,
        )

        return self._build_authentication_component(user, organization)

    async def _authenticate(
        self,
        authorization: BaseAuthorization,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[RequestCredentials, RequestUser]:
        if is_api_key(authorization):
            return await self._authenticate_api_key(
                authorization,
                operation_id=operation_id,
                connection_context=connection_context,
            )

        if is_bearer_token(authorization):
            return await self._authenticate_bearer_token(
                authorization,
                operation_id=operation_id,
                connection_context=connection_context,
            )

        raise AuthenticationError(f"Unknown authorization type: {type(authorization)}")

    async def _validate_impersonation(
        self,
        operation_id: UUID,
        connection_context: ConnectionContext,
        authentication: BaseAuthentication,
        impersonation: Impersonation,
    ):
        if not is_authenticated(authentication):
            raise AuthenticationError(
                "Can not perform impersonation if user is unauthenticated"
            )

        imp_user_id = impersonation.user_id
        imp_organization_id = impersonation.organization_id

        if imp_organization_id is None:
            raise AuthenticationError("Cannot perform system-level impersonation.")

        impersonated_user, impersonated_organization = await self._get_credentials(
            imp_user_id,
            imp_organization_id,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        imp_int_organization_id = impersonated_organization.id

        if is_tenant(authentication):
            if (
                authentication.credentials.organization.uuid
                != impersonated_organization.uuid
                != imp_organization_id
            ):
                raise AuthenticationError(
                    "Can not impersonate user from other organization"
                )

            role_scope = (
                (OrganizationRole.OWNER, f"{Domain.TENANT}:{OrganizationRole.OWNER}"),
                (
                    OrganizationRole.ADMINISTRATOR,
                    f"{Domain.TENANT}:{OrganizationRole.ADMINISTRATOR}",
                ),
            )

            valid_role_scope = [
                (
                    role in authentication.credentials.domain_roles
                    and scope in authentication.credentials.scopes
                )
                for role, scope in role_scope
            ]
            if not any(valid_role_scope):
                raise AuthenticationError(
                    "Insufficient tenant-level role and/or scope to perform impersonation"
                )

            if (
                OrganizationRole.OWNER
                in impersonated_user.get_active_organization_roles(
                    imp_int_organization_id
                )
            ):
                raise AuthenticationError("Can not impersonate organization's owner")

    async def authenticate(
        self, conn: HTTPConnection
    ) -> Tuple[RequestCredentials, RequestUser]:
        """Authentication flow"""
        operation_id = getattr(conn.state, "operation_id", None)
        if not operation_id or not isinstance(operation_id, UUID):
            raise AuthenticationError("Unable to determine operation_id")

        connection_context = ConnectionContext.from_connection(conn)
        authorization = BaseAuthorization.extract(conn=conn, auto_error=False)
        impersonation = Impersonation.extract(conn=conn)

        if authorization is None:
            if impersonation is None:
                return RequestCredentials(), RequestUser()
            else:
                raise AuthenticationError(
                    "Can not perform impersonation if user is unauthorized"
                )
        else:
            try:
                request_credentials, request_user = await self._authenticate(
                    authorization,
                    operation_id=operation_id,
                    connection_context=connection_context,
                )

                authentication = BaseAuthentication(
                    credentials=BaseCredentials.model_validate(
                        request_credentials, from_attributes=True
                    ),
                    user=BaseUser.model_validate(request_user, from_attributes=True),
                )

                if impersonation is not None:
                    await self._validate_impersonation(
                        operation_id=operation_id,
                        connection_context=connection_context,
                        authentication=authentication,
                        impersonation=impersonation,
                    )

                return request_credentials, request_user
            except Exception as e:
                raise AuthenticationError(
                    f"Exception occured while authenticating: {e}"
                ) from e
