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
from nexo.types.datetime import ListOfDatetimes
from nexo.types.string import ListOfStrs
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

    async def _is_rate_limited(self, ip: str = "unknown") -> bool:
        """
        Check if the ip is rate limited.

        Args:
            ip: Client IP address (required)

        Returns:
            True if rate limited, False otherwise
        """
        async with self._lock:
            now = datetime.now(tz=timezone.utc)

            self._last_seen[ip] = now

            # Remove old requests outside the window
            self._requests[ip] = [
                timestamp
                for timestamp in self._requests[ip]
                if (now - timestamp).total_seconds() <= self._config.window
            ]

            # Check rate limit
            if len(self._requests[ip]) >= self._config.limit:
                return True

            # Record this request
            self._requests[ip].append(now)
            return False

    async def dispatch(self, request: Request, call_next: CallNext[Response]):
        connection_context = ConnectionContext.from_connection(request)
        is_rate_limited = await self._is_rate_limited(connection_context.ip_address)
        if is_rate_limited:
            return JSONResponse(
                content=TooManyRequestsResponse().model_dump(mode="json"),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        return await call_next(request)

    async def get_current_count(self, ip: str = "unknown") -> int:
        """Get current request count for the IP Address"""
        async with self._lock:
            now = datetime.now(tz=timezone.utc)

            # Remove old requests and count current ones
            valid_requests = [
                timestamp
                for timestamp in self._requests[ip]
                if (now - timestamp).total_seconds() <= self._config.window
            ]

            return len(valid_requests)

    async def get_remaining_requests(self, ip: str) -> int:
        """Get remaining requests allowed for the IP Address"""
        current_count = await self.get_current_count(ip)
        return max(0, self._config.limit - current_count)

    async def get_reset_time(self, ip: str) -> float:
        """Get time in seconds until the rate limit resets for the IP Address"""
        async with self._lock:
            now = datetime.now(tz=timezone.utc)

            valid_requests = [
                timestamp
                for timestamp in self._requests[ip]
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
            inactive_ips: ListOfStrs = []

            for ip in list(self._requests.keys()):
                # Remove ips with empty request lists
                if not self._requests[ip]:
                    inactive_ips.append(ip)
                    continue

                # Remove ips that haven't been active recently
                last_active = self._last_seen.get(
                    ip, datetime.min.replace(tzinfo=timezone.utc)
                )
                if (now - last_active).total_seconds() > self._config.idle_timeout:
                    inactive_ips.append(ip)

            if len(inactive_ips) > 0:
                # Clean up inactive ips
                for ip in inactive_ips:
                    self._requests.pop(ip, None)
                    self._last_seen.pop(ip, None)

                operation = SuccessfulSystemOperation[
                    SingleDataResponse[Keys[ListOfStrs], None]
                ](
                    application_context=self._application_context,
                    id=operation_id,
                    context=self.operation_context,
                    timestamp=Timestamp.completed_now(now),
                    summary=f"Successfully cleaned up {len(inactive_ips)} inactive IP Address(s) in RateLimiter",
                    connection_context=None,
                    authentication=None,
                    authorization=None,
                    impersonation=None,
                    action=SystemOperationAction(
                        type=SystemOperationType.BACKGROUND_JOB, details=None
                    ),
                    response=SingleDataResponse[Keys[ListOfStrs], None](
                        data=Keys[ListOfStrs](keys=inactive_ips),
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
