from pydantic import BaseModel, Field
from typing import Annotated
from nexo.enums.connection import OptSeqOfMethods
from nexo.types.string import SeqOfStrs, OptSeqOfStrs
from .constants import (
    ALLOW_METHODS,
    ALLOW_HEADERS,
    EXPOSE_HEADERS,
)


class CORSConfig(BaseModel):
    allow_origins: Annotated[SeqOfStrs, Field([], description="Allowed origins")] = []
    allow_methods: Annotated[
        SeqOfStrs, Field(ALLOW_METHODS, description="Allowed methods")
    ] = ALLOW_METHODS
    allow_headers: Annotated[
        SeqOfStrs, Field(ALLOW_HEADERS, description="Allowed headers")
    ] = ALLOW_HEADERS
    allow_credentials: Annotated[bool, Field(True, description="Allow credentials")] = (
        True
    )
    expose_headers: Annotated[
        SeqOfStrs, Field(EXPOSE_HEADERS, description="Exposed headers")
    ] = EXPOSE_HEADERS


class LoggerConfig(BaseModel):
    max_size: Annotated[int, Field(10_000, description="Max log size (in bytes)")] = (
        10_000
    )


class RateLimiterConfig(BaseModel):
    limit: Annotated[
        int, Field(10, description="Request limit (per 'window' seconds)", ge=1)
    ] = 10
    window: Annotated[
        int, Field(1, description="Request limit window (seconds)", ge=1)
    ] = 1
    cleanup_interval: Annotated[
        int, Field(60, description="Interval for middleware cleanup (seconds)", ge=1)
    ] = 60
    idle_timeout: Annotated[
        int, Field(300, description="Idle timeout (seconds)", ge=1)
    ] = 300


class Rule(BaseModel):
    path: Annotated[str, Field(..., description="Path")]
    methods: Annotated[OptSeqOfMethods, Field(None, description="Methods")] = None
    ips: Annotated[OptSeqOfStrs, Field(None, description="IPs")] = None


ListOfRules = list[Rule]
OptListOfRules = ListOfRules | None


class SecurityConfig(BaseModel):
    rules: Annotated[OptListOfRules, Field(None, description="Rules")] = None


class MiddlewareConfig(BaseModel):
    cors: Annotated[
        CORSConfig,
        Field(CORSConfig(), description="CORS middleware's configurations"),
    ] = CORSConfig()
    logger: Annotated[
        LoggerConfig,
        Field(LoggerConfig(), description="Logger middleware's configurations"),
    ] = LoggerConfig()
    rate_limiter: Annotated[
        RateLimiterConfig,
        Field(
            RateLimiterConfig(),
            description="Rate limiter's configurations",
        ),
    ] = RateLimiterConfig()
    security: Annotated[
        SecurityConfig, Field(SecurityConfig(), description="Security's configurations")
    ] = SecurityConfig()


class MiddlewareConfigMixin(BaseModel):
    middleware: Annotated[
        MiddlewareConfig,
        Field(MiddlewareConfig(), description="Middleware config"),
    ] = MiddlewareConfig()
