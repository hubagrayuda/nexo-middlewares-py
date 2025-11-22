from datetime import datetime, timezone
from fastapi import status, HTTPException, Request, Response
from .types import CallNext


async def time_request(request: Request, call_next: CallNext[Response]) -> Response:
    executed_at = request.state.executed_at
    if not isinstance(executed_at, datetime):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Executed At timestamp is not a datetime {executed_at}",
        )

    response = await call_next(request)

    completed_at = datetime.now(tz=timezone.utc)
    request.state.completed_at = completed_at
    duration = (completed_at - executed_at).total_seconds()
    request.state.duration = duration

    return response
