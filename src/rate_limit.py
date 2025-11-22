import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import status, Request, Response
from fastapi.responses import JSONResponse
from uuid import UUID
from nexo.logging.enums import LogLevel
from nexo.logging.logger import Middleware
from nexo.schemas.application import ApplicationContext, OptApplicationContext
from nexo.schemas.connection import ConnectionContext
from nexo.schemas.exception.exc import InternalServerError
from nexo.schemas.google import ListOfPublisherHandlers
from nexo.schemas.mixins.identity import Keys
from nexo.schemas.operation.context import generate
from nexo.schemas.operation.enums import (
    OperationType,
    SystemOperationType,
    Origin,
    Layer,
    Target,
)
from nexo.schemas.operation.mixins import Timestamp
from nexo.schemas.operation.system import (
    SystemOperationAction,
    SuccessfulSystemOperation,
)
from nexo.schemas.response import SingleDataResponse, TooManyRequestsResponse
from nexo.schemas.security.authentication import BaseAuthentication
from nexo.types.datetime import ListOfDatetimes
from nexo.types.string import ListOfStrs
from nexo.types.uuid import OptUUID
from nexo.utils.exception import extract_details
from .config import RateLimiterConfig
from .types import CallNext


class RateLimiter:
    def __init__(
        self,
        config: RateLimiterConfig,
        logger: Middleware,
        publishers: ListOfPublisherHandlers = [],
        application_context: OptApplicationContext = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._publishers = publishers
        self._application_context = (
            application_context
            if application_context is not None
            else ApplicationContext.new()
        )

        self.operation_context = generate(
            origin=Origin.SERVICE,
            layer=Layer.MIDDLEWARE,
            target=Target.INTERNAL,
        )

        self._requests: dict[str, ListOfDatetimes] = defaultdict(list)
        self._last_seen: dict[str, datetime] = {}
        self._last_cleanup = datetime.now()
        self._lock = asyncio.Lock()

        # Background task management
        self._cleanup_task: asyncio.Task | None = None
        self._shutdown_event = asyncio.Event()

    def _generate_key(
        self,
        ip_address: str = "unknown",
        user_id: OptUUID = None,
        organization_id: OptUUID = None,
    ) -> str:
        """Generate a combination key from ip_address, user_id, and organization_id"""
        return f"{ip_address}|{str(user_id)}|{str(organization_id)}"

    async def _is_rate_limited(
        self,
        ip_address: str = "unknown",
        user_id: OptUUID = None,
        organization_id: OptUUID = None,
    ) -> bool:
        """
        Check if the combination of ip_address, user_id, and organization_id is rate limited.

        Args:
            ip_address: Client IP address (required)
            user_id: User ID (optional, can be None or integer >= 1)
            organization_id: Organization ID (optional, can be None or integer >= 1)

        Returns:
            True if rate limited, False otherwise
        """
        async with self._lock:
            now = datetime.now(tz=timezone.utc)

            rate_limit_key = self._generate_key(ip_address, user_id, organization_id)

            self._last_seen[rate_limit_key] = now

            # Remove old requests outside the window
            self._requests[rate_limit_key] = [
                timestamp
                for timestamp in self._requests[rate_limit_key]
                if (now - timestamp).total_seconds() <= self._config.window
            ]

            # Check rate limit
            if len(self._requests[rate_limit_key]) >= self._config.limit:
                return True

            # Record this request
            self._requests[rate_limit_key].append(now)
            return False

    async def dispatch(self, request: Request, call_next: CallNext[Response]):
        authentication: BaseAuthentication = BaseAuthentication.extract(request)
        user_id = (
            authentication.credentials.user.uuid
            if authentication.credentials.user is not None
            else None
        )
        organization_id = (
            authentication.credentials.organization.uuid
            if authentication.credentials.organization is not None
            else None
        )
        connection_context = ConnectionContext.from_connection(request)
        is_rate_limited = await self._is_rate_limited(
            ip_address=connection_context.ip_address,
            user_id=user_id,
            organization_id=organization_id,
        )
        if is_rate_limited:
            return JSONResponse(
                content=TooManyRequestsResponse().model_dump(mode="json"),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return await call_next(request)

    async def get_current_count(
        self,
        ip_address: str = "unknown",
        user_id: OptUUID = None,
        organization_id: OptUUID = None,
    ) -> int:
        """Get current request count for the combination key"""
        async with self._lock:
            now = datetime.now(tz=timezone.utc)
            rate_limit_key = self._generate_key(ip_address, user_id, organization_id)

            # Remove old requests and count current ones
            valid_requests = [
                timestamp
                for timestamp in self._requests[rate_limit_key]
                if (now - timestamp).total_seconds() <= self._config.window
            ]

            return len(valid_requests)

    async def get_remaining_requests(
        self,
        ip_address: str,
        user_id: OptUUID = None,
        organization_id: OptUUID = None,
    ) -> int:
        """Get remaining requests allowed for the combination key"""
        current_count = await self.get_current_count(
            ip_address, user_id, organization_id
        )
        return max(0, self._config.limit - current_count)

    async def get_reset_time(
        self,
        ip_address: str,
        user_id: OptUUID = None,
        organization_id: OptUUID = None,
    ) -> float:
        """Get time in seconds until the rate limit resets for the combination key"""
        async with self._lock:
            now = datetime.now(tz=timezone.utc)
            rate_limit_key = self._generate_key(ip_address, user_id, organization_id)

            valid_requests = [
                timestamp
                for timestamp in self._requests[rate_limit_key]
                if (now - timestamp).total_seconds() <= self._config.window
            ]

            if not valid_requests:
                return 0.0

            # Time until the oldest request expires
            oldest_request = min(valid_requests)
            reset_time = self._config.window - (now - oldest_request).total_seconds()
            return max(0.0, reset_time)

    async def cleanup_old_data(self, operation_id: UUID) -> None:
        """Clean up old request data to prevent memory growth."""
        async with self._lock:
            now = datetime.now(tz=timezone.utc)
            inactive_keys: ListOfStrs = []

            for key in list(self._requests.keys()):
                # Remove keys with empty request lists
                if not self._requests[key]:
                    inactive_keys.append(key)
                    continue

                # Remove keys that haven't been active recently
                last_active = self._last_seen.get(
                    key, datetime.min.replace(tzinfo=timezone.utc)
                )
                if (now - last_active).total_seconds() > self._config.idle_timeout:
                    inactive_keys.append(key)

            if len(inactive_keys) > 0:
                # Clean up inactive keys
                for key in inactive_keys:
                    self._requests.pop(key, None)
                    self._last_seen.pop(key, None)

                operation = SuccessfulSystemOperation[
                    SingleDataResponse[Keys[ListOfStrs], None]
                ](
                    application_context=self._application_context,
                    id=operation_id,
                    context=self.operation_context,
                    timestamp=Timestamp.completed_now(now),
                    summary=f"Successfully cleaned up {len(inactive_keys)} inactive keys in RateLimiter",
                    connection_context=None,
                    authentication=None,
                    authorization=None,
                    impersonation=None,
                    action=SystemOperationAction(
                        type=SystemOperationType.BACKGROUND_JOB, details=None
                    ),
                    response=SingleDataResponse[Keys[ListOfStrs], None](
                        data=Keys[ListOfStrs](keys=inactive_keys),
                        metadata=None,
                        other=None,
                    ),
                )
                operation.log(self._logger, LogLevel.INFO)
                operation.publish(self._logger, self._publishers)

    async def start_cleanup_task(self, operation_id: UUID):
        """Start the background cleanup task"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._shutdown_event.clear()  # Reset shutdown event
            self._cleanup_task = asyncio.create_task(
                self._background_cleanup(operation_id)
            )

    async def stop_cleanup_task(self):
        """Stop the background cleanup task"""
        self._shutdown_event.set()
        if self._cleanup_task and not self._cleanup_task.done():
            try:
                await asyncio.wait_for(self._cleanup_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass

    async def _background_cleanup(self, operation_id: UUID):
        """Background task that runs cleanup periodically"""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self._config.cleanup_interval)
                if not self._shutdown_event.is_set():
                    await self.cleanup_old_data(operation_id)
            except asyncio.CancelledError:
                break
            except Exception as e:
                details = extract_details(e)
                error = InternalServerError(
                    details=details,
                    operation_type=OperationType.SYSTEM,
                    application_context=self._application_context,
                    operation_id=operation_id,
                    operation_context=self.operation_context,
                    operation_action=SystemOperationAction(
                        type=SystemOperationType.BACKGROUND_JOB, details=None
                    ),
                    operation_timestamp=Timestamp.now(),
                    operation_summary="Exception raised when performing RateLimiter background cleanup",
                    connection_context=None,
                    authentication=None,
                    authorization=None,
                    impersonation=None,
                    response=None,
                )

                operation = error.operation
                operation.log(self._logger, LogLevel.ERROR)
                operation.publish(self._logger, self._publishers)
