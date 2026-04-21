from Crypto.PublicKey.RSA import RsaKey
from datetime import datetime, timezone
from fastapi import status, Request
from fastapi.responses import Response, JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from nexo.crypto.hash.enums import Mode
from nexo.crypto.hash.sha256 import hash
from nexo.crypto.signature import sign, verify
from nexo.database.handlers import PostgreSQLHandler, RedisHandler
from nexo.enums.connection import Header
from nexo.schemas.application import ApplicationSettings
from nexo.schemas.connection import ConnectionContext
from nexo.schemas.operation.extractor import extract_operation_id
from nexo.schemas.response import UnauthorizedResponse
from nexo.schemas.security.client import ClientContext
from nexo.types.string import ListOfStrs, ManyStrs
from nexo.utils.extractor import ResponseBodyExtractor
from .config import CoreConfig
from .identity import IdentityProvider
from .models import Base


class CoreMiddleware:
    def __init__(
        self,
        config: CoreConfig,
        *,
        settings: ApplicationSettings,
        private_key: RsaKey,
        database: PostgreSQLHandler[Base],
        cache: RedisHandler,
    ):
        self._config = config
        self._settings = settings
        self._private_key = private_key

        self._identity_provider = IdentityProvider(
            database=database,
            cache=cache,
        )

    async def _compute_request_body_hash(self, request: Request) -> str:
        """Safely reads the request body, hashes it, and re-injects it."""

        # 1. Fast fail if there is obviously no body
        content_length = request.headers.get("content-length")
        if not content_length or int(content_length) == 0:
            return "EMPTY-PAYLOAD"

        # 2. Check Content-Type
        content_type = request.headers.get(Header.CONTENT_TYPE.value, "")

        # Only hash JSON. Do NOT hash multipart/form-data (file uploads)
        if "application/json" not in content_type:
            return "UNHASHABLE-PAYLOAD"

        # 3. Now it is safe to read the body
        try:
            body_bytes = await request.body()
        except Exception:
            # Catch unexpected disconnects gracefully
            return "EMPTY-PAYLOAD"

        if not body_bytes:
            return "EMPTY-PAYLOAD"

        # 4. Re-inject the body so downstream endpoints can still read it!
        async def receive():
            return {"type": "http.request", "body": body_bytes}

        request._receive = receive

        # 5. Return the hash
        return hash(Mode.DIGEST, message=body_bytes).hex()

    async def _compute_response_body_hash(
        self, response: Response
    ) -> tuple[str, Response]:
        content_type = response.headers.get(Header.CONTENT_TYPE, "")

        # 1. Skip hashing for file streams to prevent memory overload
        if "application/json" not in content_type:
            return "UNHASHABLE-PAYLOAD", response

        # 2. Safely extract and reconstruct using your utility
        body_bytes, new_response = await ResponseBodyExtractor.async_extract(response)

        if not body_bytes:
            return "EMPTY-PAYLOAD", new_response

        # 3. Hash the extracted bytes
        body_hash = hash(Mode.DIGEST, message=body_bytes).hex()

        return body_hash, new_response

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        operation_id = extract_operation_id(conn=request)
        connection_context = ConnectionContext.from_connection(request)
        executed_at = connection_context.executed_at
        client_context = ClientContext.extract(request)
        if client_context is None:
            if self._config.strict_client:
                return JSONResponse(
                    content=UnauthorizedResponse(
                        other="Client context must be provided."
                    ).model_dump(),
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            client = None
        else:
            client = await self._identity_provider.get_client(
                client_context.client_id,
                operation_id=operation_id,
                connection_context=connection_context,
            )

            body_hash = await self._compute_request_body_hash(request)

            request_payload_components: ManyStrs = (
                client_context.executed_at.isoformat(),
                request.method,
                request.url.path,
                request.url.query,
                str(client.secret),
                body_hash,
            )
            payload = "|".join(request_payload_components)

            is_valid_signature = verify(
                client.rsa_public_key, payload, client_context.signature
            )

            if not is_valid_signature:
                return JSONResponse(
                    content=UnauthorizedResponse(
                        other="Invalid request signature."
                    ).model_dump(),
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        response = await call_next(request)

        completed_at = datetime.now(tz=timezone.utc)
        request.state.completed_at = completed_at

        duration = (completed_at - executed_at).total_seconds()
        request.state.duration = duration

        body_hash, response = await self._compute_response_body_hash(response)

        # Set simple headers first
        response.headers[Header.X_SERVER_ID.value] = str(self._settings.CLIENT_ID)
        if client is not None:
            response.headers[Header.X_CLIENT_ID.value] = str(client.id)
        response.headers[Header.X_OPERATION_ID.value] = str(operation_id)
        response.headers[Header.X_CONNECTION_ID.value] = str(connection_context.id)
        response.headers[Header.X_EXECUTED_AT.value] = executed_at.isoformat()
        response.headers[Header.X_COMPLETED_AT.value] = completed_at.isoformat()
        response.headers[Header.X_DURATION.value] = str(duration)

        # Build response signature
        response_payload_components: ListOfStrs = [
            str(operation_id),
            str(connection_context.id),
            executed_at.isoformat(),
            completed_at.isoformat(),
            str(duration),
            str(response.status_code),
            body_hash,
        ]
        if client is not None:
            response_payload_components.append(str(client.secret))

        payload = "|".join(response_payload_components)
        signature = sign(payload, self._private_key)
        response.headers[Header.X_SIGNATURE.value] = signature

        return response
