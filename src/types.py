from fastapi import Request, Response
from typing import Awaitable, Callable, TypeVar


ResponseT = TypeVar("ResponseT", bound=Response)
CallNext = Callable[[Request], Awaitable[ResponseT]]
