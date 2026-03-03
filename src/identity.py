from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.authentication import AuthenticationError
from typing import TypeGuard
from uuid import UUID
from nexo.crypto.hash.enums import Mode
from nexo.crypto.hash.sha256 import hash
from nexo.database.enums import CacheOrigin, CacheLayer, Connection
from nexo.database.handlers import PostgreSQLHandler, RedisHandler
from nexo.database.utils import build_cache_key
from nexo.enums.expiration import Expiration
from nexo.enums.status import DataStatus
from nexo.schemas.connection import ConnectionContext
from nexo.types.uuid import DoubleUUIDs
from .models import (
    Base,
    User as UserModel,
    Organization as OrganizationModel,
    Principal as PrincipalModel,
    APIKey as APIKeyModel,
)
from .schemas import PrincipalSchema


def is_double_uuid(value: object) -> TypeGuard[DoubleUUIDs]:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], UUID)
        and isinstance(value[1], UUID)
    )


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

    async def get_principal(
        self,
        identifier: str | DoubleUUIDs | UUID,
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
        elif is_double_uuid(identifier):
            user_uuid, organization_uuid = identifier
            cache_token = f"{user_uuid}:{organization_uuid}"
        else:
            raise TypeError("Invalid identifier type")

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
                select(PrincipalModel)
                .options(
                    selectinload(PrincipalModel.user),
                    selectinload(PrincipalModel.organization),
                    selectinload(PrincipalModel.medical_roles),
                    selectinload(PrincipalModel.organization_roles),
                    selectinload(PrincipalModel.system_roles),
                )
                .where(PrincipalModel.status == DataStatus.ACTIVE)
            )

            if isinstance(identifier, str):
                stmt = stmt.join(PrincipalModel.api_key).where(
                    APIKeyModel.status == DataStatus.ACTIVE,
                    APIKeyModel.api_key == cache_token,
                )
            elif isinstance(identifier, UUID):
                stmt = stmt.where(PrincipalModel.uuid == identifier)
            elif is_double_uuid(identifier):
                user_uuid, organization_uuid = identifier
                stmt = (
                    stmt.join(PrincipalModel.user)
                    .join(PrincipalModel.organization)
                    .where(
                        UserModel.uuid == user_uuid,
                        OrganizationModel.uuid == organization_uuid,
                    )
                )
            else:
                raise TypeError("Invalid identifier type")

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
