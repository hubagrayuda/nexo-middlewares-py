import re
from fastapi import status, HTTPException, Request, Response
from urllib.parse import urlparse
from nexo.database.enums import CacheOrigin, CacheLayer
from nexo.database.handlers import RedisHandler
from nexo.database.utils import build_cache_key
from nexo.enums.connection import Method
from nexo.enums.expiration import Expiration
from nexo.schemas.connection import ConnectionContext
from .config import SecurityConfig
from .types import CallNext


def secure_request(
    *,
    config: SecurityConfig,
    cache: RedisHandler,
):
    namespace = cache.config.build_namespace(
        "security",
        origin=CacheOrigin.SERVICE,
        layer=CacheLayer.MIDDLEWARE,
    )

    async def dispatch(request: Request, call_next: CallNext[Response]):
        connection_context = ConnectionContext.from_connection(request)

        ip = connection_context.ip_address

        if connection_context.method is not None:
            try:
                method = Method(connection_context.method)
            except Exception:
                method = None
        else:
            method = None

        path = urlparse(connection_context.url).path

        cache_key = build_cache_key(
            f"{connection_context.ip_address}|{method}|{path}", namespace=namespace
        )

        cache_result = await cache.manager.client.async_client.get(cache_key)
        if cache_result is not None:
            allowed = cache_result == b"True" or cache_result == "True"
        else:
            if config.rules is None:
                allowed = True
            else:
                allowed = True  # default
                matched_any_path = False
                for rule in config.rules:
                    if not re.match(rule.path, path):
                        continue  # skip, do not override allowed

                    matched_any_path = True

                    # METHOD CHECK
                    if rule.methods is None or method is None:
                        method_ok = True
                    else:
                        method_ok = method in rule.methods

                    # IP CHECK (regex list)
                    if rule.ips is None:
                        ip_ok = True
                    else:
                        if ip == "unknown":
                            ip_ok = False  # cannot validate; deny
                        else:
                            ip_ok = any(
                                re.match(ip_pattern, ip) for ip_pattern in rule.ips
                            )

                    allowed = method_ok and ip_ok

                    # If this matching rule decides the request fails → stop.
                    if not allowed:
                        break

                # If no rule matched the path → allow
                if not matched_any_path:
                    allowed = True

        await cache.manager.client.async_client.set(
            cache_key, "True" if allowed else "False", ex=Expiration.EXP_1MO
        )

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request context did not pass security rule check",
            )

        # Call next
        return await call_next(request)

    return dispatch
