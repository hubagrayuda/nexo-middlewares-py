from datetime import datetime, timezone
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
from nexo.types.datetime import OptDatetime
from .models import (
    Base,
    User as UserModel,
    Organization as OrganizationModel,
    UserOrganization as UserOrganizationModel,
    APIKey as APIKeyModel,
)
from .schemas import (
    UserSchema,
    OrganizationSchema,
    UserOrganizationIdSchema,
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

    async def get_user(
        self,
        user_id: UUID,
        exp: OptDatetime = None,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> UserSchema:
        cache_key = build_cache_key("user", str(user_id), namespace=self._namespace)
        redis = self._cache.manager.client.get(Connection.ASYNC)
        redis_data = await redis.get(cache_key)
        if redis_data is not None:
            return UserSchema.model_validate_json(redis_data)

        async with self._database.manager.session.get(
            Connection.ASYNC,
            operation_id=operation_id,
            connection_context=connection_context,
        ) as session:
            stmt = (
                select(UserModel)
                .options(
                    selectinload(UserModel.medical_roles),
                    selectinload(UserModel.organization_roles),
                    selectinload(UserModel.organizations).selectinload(
                        UserOrganizationModel.organization
                    ),
                    selectinload(UserModel.system_roles),
                )
                .where(
                    UserModel.uuid == user_id,
                    UserModel.status == DataStatus.ACTIVE,
                )
            )

            # Execute and fetch results
            result = await session.execute(stmt)
            row = result.scalars().one_or_none()

            if row is None:
                raise AuthenticationError(
                    f"Can not find active User with ID: {user_id}"
                )

            data = UserSchema.model_validate(row, from_attributes=True)

        if exp is None:
            ex = Expiration.EXP_1WK.value
        else:
            now = datetime.now(tz=timezone.utc)
            if exp <= now:
                raise AuthenticationError("Cache expiry is less then now")
            ex = min(int((exp - now).total_seconds()), Expiration.EXP_1WK.value)
        await redis.set(cache_key, data.model_dump_json(), ex)

        return data

    async def get_organization(
        self,
        organization_id: UUID,
        exp: OptDatetime = None,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> OrganizationSchema:
        cache_key = build_cache_key(
            "organization", str(organization_id), namespace=self._namespace
        )
        redis = self._cache.manager.client.get(Connection.ASYNC)
        redis_data = await redis.get(cache_key)
        if redis_data is not None:
            return OrganizationSchema.model_validate_json(redis_data)

        async with self._database.manager.session.get(
            Connection.ASYNC,
            operation_id=operation_id,
            connection_context=connection_context,
        ) as session:
            stmt = select(OrganizationModel).where(
                OrganizationModel.uuid == organization_id,
                OrganizationModel.status == DataStatus.ACTIVE,
            )

            # Execute and fetch results
            result = await session.execute(stmt)
            row = result.scalars().one_or_none()

            if row is None:
                raise AuthenticationError(
                    f"Can not find active Organization with ID: {organization_id}"
                )

            data = OrganizationSchema.model_validate(row, from_attributes=True)

        if exp is None:
            ex = Expiration.EXP_1WK.value
        else:
            now = datetime.now(tz=timezone.utc)
            if exp <= now:
                raise AuthenticationError("Cache expiry is less then now")
            ex = min(int((exp - now).total_seconds()), Expiration.EXP_1WK.value)
        await redis.set(cache_key, data.model_dump_json(), ex)

        return data

    async def get_user_organization_id_from_api_key(
        self,
        api_key: str,
        *,
        operation_id: UUID,
        connection_context: ConnectionContext,
    ) -> UserOrganizationIdSchema:
        hashed_api_key = hash(Mode.DIGEST, message=api_key)

        cache_key = build_cache_key(
            "user_organization_id",
            hashed_api_key,
            namespace=self._namespace,
        )
        redis = self._cache.manager.client.get(Connection.ASYNC)
        redis_data = await redis.get(cache_key)
        if redis_data is not None:
            return UserOrganizationIdSchema.model_validate_json(redis_data)

        async with self._database.manager.session.get(
            Connection.ASYNC,
            operation_id=operation_id,
            connection_context=connection_context,
        ) as session:
            stmt = (
                select(APIKeyModel)
                .options(
                    selectinload(APIKeyModel.user),
                    selectinload(APIKeyModel.organization),
                )
                .where(
                    APIKeyModel.status == DataStatus.ACTIVE,
                    APIKeyModel.api_key == hashed_api_key,
                )
            )

            # Execute and fetch results
            result = await session.execute(stmt)
            row = result.scalars().one_or_none()

            if row is None:
                raise AuthenticationError(
                    "Can not find valid User-Organization combination for given API Key"
                )

            data = UserOrganizationIdSchema(
                user_id=row.user.uuid,
                organization_id=(
                    row.organization.uuid if row.organization is not None else None
                ),
            )

        await redis.set(cache_key, data.model_dump_json(), Expiration.EXP_1MO.value)

        return data
