from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.authentication import AuthenticationError
from uuid import UUID
from nexo.crypto.hash.enums import Mode
from nexo.crypto.hash.sha256 import hash
from nexo.database.enums import CacheOrigin, CacheLayer, Connection
from nexo.database.handlers import PostgreSQLHandler, RedisHandler
from nexo.database.utils import build_cache_key
from nexo.enums.expiration import Expiration
from nexo.enums.status import DataStatus
from nexo.schemas.connection import ConnectionContext
from nexo.types.misc import StrOrUUID
from .models import (
    Base,
    Client,
    Organization,
    User,
    PrincipalMedicalRole,
    PrincipalOrganizationRole,
    PrincipalSystemRole,
    Principal,
    APIKey,
)
from .schemas import ClientSchema, PrincipalSchema


class IdentityProvider:
    def __init__(
        self,
        *,
        database: PostgreSQLHandler[Base],
        cache: RedisHandler,
    ) -> None:
        self._database = database
        self._cache = cache
        self._namespace = self._cache.config.build_namespace(
            "identity",
            origin=CacheOrigin.SERVICE,
            layer=CacheLayer.MIDDLEWARE,
        )

    async def get_client(
        self,
        id: UUID,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> ClientSchema:
        cache_key = build_cache_key("client", str(id), namespace=self._namespace)
        redis = self._cache.manager.client.get(Connection.ASYNC)
        redis_data = await redis.get(cache_key)
        if redis_data is not None:
            return ClientSchema.model_validate_json(redis_data)

        async with self._database.manager.session.get(
            Connection.ASYNC,
            operation_id=operation_id,
            connection_context=connection_context,
        ) as session:
            stmt = select(Client).where(
                Client.id == id, Client.status == DataStatus.ACTIVE
            )

            result = await session.execute(stmt)
            row = result.scalars().one_or_none()

            if row is None:
                raise ValueError(f"Client with ID of '{id}' is not found")

            client = ClientSchema.model_validate(row, from_attributes=True)

        await redis.set(cache_key, client.model_dump_json(), Expiration.EXP_1MO.value)

        return client

    async def get_principal(
        self,
        identifier: StrOrUUID,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> PrincipalSchema:

        # Determine lookup mode
        if isinstance(identifier, str):
            hashed_api_key = hash(Mode.DIGEST, message=identifier)
            cache_token = hashed_api_key
        elif isinstance(identifier, UUID):
            cache_token = str(identifier)

        # Cache
        cache_key = build_cache_key(
            "principal",
            cache_token,
            namespace=self._namespace,
        )
        redis = self._cache.manager.client.get(Connection.ASYNC)
        redis_data = await redis.get(cache_key)
        if redis_data is not None:
            return PrincipalSchema.model_validate_json(redis_data)

        async with self._database.manager.session.get(
            Connection.ASYNC,
            operation_id=operation_id,
            connection_context=connection_context,
        ) as session:

            stmt = (
                select(Principal)
                .options(
                    selectinload(Principal.user).selectinload(User.user_type),
                    selectinload(Principal.organization).selectinload(
                        Organization.organization_type
                    ),
                    selectinload(Principal.medical_roles).selectinload(
                        PrincipalMedicalRole.medical_role
                    ),
                    selectinload(Principal.organization_roles).selectinload(
                        PrincipalOrganizationRole.organization_role
                    ),
                    selectinload(Principal.system_roles).selectinload(
                        PrincipalSystemRole.system_role
                    ),
                )
                .where(Principal.status == DataStatus.ACTIVE)
            )

            if isinstance(identifier, str):
                stmt = stmt.where(
                    Principal.api_key.has(
                        (APIKey.status == DataStatus.ACTIVE)
                        & (APIKey.api_key == cache_token)
                    )
                )
            elif isinstance(identifier, UUID):
                stmt = stmt.where(Principal.uuid == identifier)

            result = await session.execute(stmt)
            row = result.scalars().one_or_none()

            if row is None:
                raise AuthenticationError(
                    "Can not find valid Principal for given identifier"
                )

            principal = PrincipalSchema.model_validate(row, from_attributes=True)
            await redis.set(
                cache_key,
                principal.model_dump_json(),
                Expiration.EXP_1MO.value,
            )

            return principal
