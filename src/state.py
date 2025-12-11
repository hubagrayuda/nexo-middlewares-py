from fastapi import status
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import Scope, Receive, Send, ASGIApp
from starlette.websockets import WebSocket
from uuid import uuid4
from nexo.enums.connection import Protocol
from nexo.logging.logger import Middleware
from nexo.schemas.operation.action.resource import ResourceOperationActionFactory
from nexo.schemas.operation.enums import IdSource
from nexo.schemas.operation.extractor import extract_operation_id
from nexo.schemas.response import InternalServerErrorResponse
from nexo.schemas.security.authorization import AuthorizationFactory
from nexo.schemas.security.impersonation import Impersonation
from nexo.utils.exception import extract_details


class StateMiddleware:
    def __init__(self, app: ASGIApp, logger: Middleware) -> None:
        self.app = app
        self.logger = logger

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only act on HTTP and WebSocket
        if scope["type"] not in Protocol:
            await self.app(scope, receive, send)
            return

        try:
            if scope["type"] == "http":
                conn = Request(scope, receive=receive)
            else:
                conn = WebSocket(scope, receive=receive, send=send)

            # --- Assign state values ---
            scope.setdefault("state", {})

            # Operation ID
            operation_id = extract_operation_id(
                IdSource.HEADER, conn=conn, generate=True
            )
            scope["state"]["operation_id"] = operation_id

            if isinstance(conn, Request):
                # Operation action
                operation_action = ResourceOperationActionFactory.extract(
                    request=conn, from_state=False, strict=False
                )
                scope["state"]["operation_action"] = operation_action

            # Connection ID
            scope["state"]["connection_id"] = uuid4()

            # Authorization
            authorization = AuthorizationFactory.extract(conn=conn, auto_error=False)
            scope["state"]["authorization"] = authorization

            # Impersonation
            impersonation = Impersonation.extract(conn)
            scope["state"]["impersonation"] = impersonation

        except Exception as e:
            exc_details = extract_details(e)
            self.logger.error(
                "Unexpected error while assigning connection state",
                exc_info=True,
                extra={"json_fields": {"exc_details": exc_details}},
            )

            # For HTTP, return JSON 500 response
            if scope["type"] == "http":
                response = JSONResponse(
                    content=InternalServerErrorResponse(
                        message="Unexpected error while assigning request state",
                        other=exc_details,
                    ).model_dump(mode="json"),
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
                await response(scope, receive, send)
                return

            # For WebSocket, gracefully close the connection
            if scope["type"] == "websocket":
                await send(
                    {
                        "type": "websocket.close",
                        "code": 1011,  # Internal error
                        "reason": "Unexpected error while assigning websocket state",
                    }
                )
                return

        # Hand off to next app
        await self.app(scope, receive, send)
