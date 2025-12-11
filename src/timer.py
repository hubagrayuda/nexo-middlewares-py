from datetime import datetime, timezone
from fastapi import Request, Response
from .types import CallNext


async def time_request(request: Request, call_next: CallNext[Response]) -> Response:
    executed_at = datetime.now(tz=timezone.utc)

    response = await call_next(request)

    completed_at = datetime.now(tz=timezone.utc)
    request.state.completed_at = completed_at
    duration = (completed_at - executed_at).total_seconds()
    request.state.duration = duration

    return response
