from Crypto.PublicKey.RSA import RsaKey
from fastapi.requests import HTTPConnection
from starlette.authentication import AuthenticationBackend, AuthenticationError
from typing import Tuple
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
    is_personal,
    is_tenant,
    is_system,
)
from nexo.schemas.security.authorization import (
    BaseAuthorization,
    BearerTokenAuthorization,
    APIKeyAuthorization,
    is_bearer_token,
    is_api_key,
)
from nexo.schemas.security.enums import Domain
from nexo.schemas.security.impersonation import Impersonation
from .config import AuthenticationConfig
from .identity import IdentityProvider
from .models import Base
from .schemas import PrincipalSchema


class Backend(AuthenticationBackend):
    def __init__(
        self,
        *,
        application_context: OptApplicationContext = None,
        database: PostgreSQLHandler[Base],
        cache: RedisHandler,
        public_key: RsaKey,
        config: AuthenticationConfig,
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
        self._config = config

    def _build_authentication_component(
        self, principal: PrincipalSchema
    ) -> Tuple[RequestCredentials, RequestUser]:
        # Define Request Credentials
        scopes = ["authenticated", principal.domain]
        medical_roles = principal.active_medical_roles
        if medical_roles is not None:
            scopes += [f"medical:{role}" for role in medical_roles]
        if principal.domain is Domain.PERSONAL:
            # Define organization info
            organization_id = None
            organization_uuid = None
            organization_type = None

            # Define domain roles
            domain_roles = None

        elif principal.domain is Domain.SYSTEM:
            # Define organization info
            organization_id = None
            organization_uuid = None
            organization_type = None

            # Define domain roles
            domain_roles = principal.active_system_roles
            if domain_roles is None:
                raise ValueError("Can not find active system roles")

            # Update scopes
            scopes += [f"{principal.domain}:{role}" for role in domain_roles]

        elif principal.domain is Domain.TENANT:
            # Define organization info
            if principal.organization is None:
                raise ValueError("Can not find organization")
            organization_id = principal.organization.id
            organization_uuid = principal.organization.uuid
            organization_type = principal.organization.type

            # Define domain roles
            domain_roles = principal.active_organization_roles
            if domain_roles is None:
                raise ValueError("Can not find active organization roles")

            # Update scopes
            scopes += [f"{principal.domain}:{role}" for role in domain_roles]

        else:
            raise ValueError("Unable to determine request credentials")

        req_credentials = RequestCredentials(
            principal_id=principal.id,
            principal_uuid=principal.uuid,
            domain=principal.domain,
            user_id=principal.user.id,
            user_uuid=principal.user.uuid,
            user_type=principal.user.type,
            organization_id=organization_id,
            organization_uuid=organization_uuid,
            organization_type=organization_type,
            domain_roles=domain_roles,
            medical_roles=principal.active_medical_roles,
            scopes=scopes,
        )

        # Define Request User
        request_user = RequestUser(
            authenticated=True,
            organization=(
                None if principal.organization is None else principal.organization.key
            ),
            username=principal.user.username,
            email=principal.user.email,
        )

        return req_credentials, request_user

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
        principal = await self._identity_provider.get_principal(
            authorization.credentials,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        return self._build_authentication_component(principal)

    async def _authenticate_bearer_token(
        self,
        authorization: BearerTokenAuthorization,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> Tuple[RequestCredentials, RequestUser]:
        token = authorization.parse_token(key=self._public_key)
        principal = await self._identity_provider.get_principal(
            token.sub,
            operation_id=operation_id,
            connection_context=connection_context,
        )

        return self._build_authentication_component(principal)

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
                "Can not perform impersonation without authentication"
            )

        if is_personal(authentication):
            raise AuthenticationError(
                "Can not perform impersonation with personal authentication"
            )

        imp_user_id = impersonation.user_id
        imp_organization_id = impersonation.organization_id

        if imp_organization_id is None:
            if not is_system(authentication):
                raise AuthenticationError(
                    "Can not perform personal impersonation without system authentication"
                )
            return

        principal = await self._identity_provider.get_principal(
            (imp_user_id, imp_organization_id),
            operation_id=operation_id,
            connection_context=connection_context,
        )

        if principal.organization is None:
            raise AuthenticationError("Principal is not registered to the organization")

        if is_tenant(authentication):
            if (
                authentication.credentials.organization.uuid
                != imp_organization_id
                != principal.organization.uuid
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

            if principal.active_organization_roles is None:
                raise AuthenticationError(
                    "Principal did not have active organization roles"
                )

            if OrganizationRole.OWNER in principal.active_organization_roles:
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
                if self._config.strict:
                    raise AuthenticationError(
                        f"Exception occured while authenticating: {e}"
                    ) from e
                return RequestCredentials(), RequestUser()
