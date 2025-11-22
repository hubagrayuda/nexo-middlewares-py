from Crypto.PublicKey.RSA import RsaKey
from datetime import datetime
from fastapi import status, HTTPException, Request, Response
from nexo.crypto.signature import sign
from nexo.enums.connection import Header
from nexo.schemas.connection import ConnectionContext
from nexo.schemas.operation.extractor import extract_operation_id
from .types import CallNext


def add_header(*, private_key: RsaKey):
    async def dispatch(request: Request, call_next: CallNext[Response]):
        # Call next
        response = await call_next(request)

        operation_id = extract_operation_id(conn=request)
        connection_context = ConnectionContext.from_connection(request)

        # Set header
        response.headers[Header.X_OPERATION_ID.value] = str(operation_id)
        response.headers[Header.X_CONNECTION_ID.value] = str(connection_context.id)
        response.headers[Header.X_EXECUTED_AT.value] = (
            connection_context.executed_at.isoformat()
        )

        completed_at = request.state.completed_at
        if not isinstance(completed_at, datetime):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Completed At timestamp is not a datetime {completed_at}",
            )

        duration = request.state.duration
        if not isinstance(duration, float):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Duration is not a float {duration}",
            )

        response.headers[Header.X_COMPLETED_AT.value] = completed_at.isoformat()
        response.headers[Header.X_DURATION.value] = str(duration)

        message = (
            f"{str(operation_id)}|"
            f"{str(connection_context.id)}"
            f"{connection_context.method}|"
            f"{connection_context.url}|"
            f"{connection_context.executed_at.isoformat()}|"
            f"{completed_at.isoformat()}|"
            f"{str(duration)}|"
        )

        try:
            signature = sign(message=message, key=private_key)
            response.headers[Header.X_SIGNATURE] = signature
        except Exception:
            raise

        return response

    return dispatch
