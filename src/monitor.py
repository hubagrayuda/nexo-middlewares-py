import json
from datetime import datetime
from fastapi import status, HTTPException, Request
from typing import Any
from starlette.middleware.base import RequestResponseEndpoint
from nexo.enums.connection import Header
from nexo.infra.request.monitor import RequestMonitor
from nexo.infra.request.schemas import Record
from nexo.logging.enums import LogLevel
from nexo.logging.logger import Middleware
from nexo.schemas.application import ApplicationContext, OptApplicationContext
from nexo.schemas.connection import ConnectionContext
from nexo.schemas.error import ErrorFactory
from nexo.schemas.google import ListOfPublisherHandlers
from nexo.schemas.operation.action.resource import ResourceOperationActionFactory
from nexo.schemas.operation.context import generate
from nexo.schemas.operation.enums import Origin, Layer, Target
from nexo.schemas.operation.extractor import extract_operation_id
from nexo.schemas.operation.mixins import Timestamp
from nexo.schemas.operation.request import (
    FailedRequestOperationFactory,
    SuccessfulRequestOperationFactory,
)
from nexo.schemas.pagination import OptAnyPagination
from nexo.schemas.response import (
    ResponseContext,
    AnyDataResponse,
    ErrorResponseFactory,
)
from nexo.schemas.security.authentication import BaseAuthentication
from nexo.schemas.security.authorization import BaseAuthorization
from nexo.schemas.security.impersonation import Impersonation
from nexo.utils.extractor import ResponseBodyExtractor
from .config import LoggerConfig


def monitor_request(
    config: LoggerConfig,
    logger: Middleware,
    monitor: RequestMonitor,
    publishers: ListOfPublisherHandlers = [],
    *,
    application_context: OptApplicationContext = None,
):
    application_context = (
        application_context
        if application_context is not None
        else ApplicationContext.new()
    )

    operation_context = generate(
        origin=Origin.SERVICE,
        layer=Layer.MIDDLEWARE,
        target=Target.INTERNAL,
    )

    async def dispatch(request: Request, call_next: RequestResponseEndpoint):
        response = await call_next(request)

        content_type = response.headers.get(Header.CONTENT_TYPE)

        if content_type is None or (
            content_type is not None and "application/json" not in content_type.lower()
        ):
            return response

        operation_id = extract_operation_id(conn=request)
        operation_action = ResourceOperationActionFactory.extract(
            request=request, strict=False
        )

        executed_at = getattr(request.state, "executed_at", None)
        if not isinstance(executed_at, datetime):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Executed At timestamp is not a datetime {executed_at}",
            )

        completed_at = getattr(request.state, "completed_at", None)
        if not isinstance(completed_at, datetime):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Completed At timestamp is not a datetime {completed_at}",
            )

        duration = getattr(request.state, "duration", None)
        if not isinstance(duration, float):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Duration is not a float {duration}",
            )

        # Add request record
        record = Record(
            requested_at=executed_at, status_code=response.status_code, latency=duration
        )
        await monitor.add_record(record)

        operation_timestamp = Timestamp(
            executed_at=executed_at, completed_at=completed_at, duration=duration
        )

        connection_context = ConnectionContext.from_connection(request)
        authentication: BaseAuthentication = BaseAuthentication.extract(request)
        authorization = BaseAuthorization.extract(request, auto_error=False)
        impersonation = Impersonation.extract(request)

        response_context = ResponseContext(
            status_code=response.status_code,
            media_type=response.media_type,
            headers=response.headers.items(),
        )

        response_body, final_response = await ResponseBodyExtractor.async_extract(
            response
        )
        try:
            json_dict = json.loads(response_body)
            if 200 <= final_response.status_code < 400:
                validated_response = AnyDataResponse[
                    Any, OptAnyPagination, Any
                ].model_validate(json_dict)
                operation = SuccessfulRequestOperationFactory.generate(
                    operation_action,
                    application_context=application_context,
                    id=operation_id,
                    context=operation_context,
                    timestamp=operation_timestamp,
                    summary="Successfully processed request",
                    connection_context=connection_context,
                    authentication=authentication,
                    authorization=authorization,
                    impersonation=impersonation,
                    response=validated_response,
                    response_context=response_context,
                )
                operation.log(logger, LogLevel.INFO)
                operation.publish(logger, publishers)
            elif 400 <= final_response.status_code <= 500:
                response_cls = ErrorResponseFactory.cls_from_code(
                    final_response.status_code
                )
                validated_response = response_cls.model_validate(json_dict)
                error_cls = ErrorFactory.cls_from_code(final_response.status_code)
                operation = FailedRequestOperationFactory[
                    error_cls, response_cls
                ].generate(
                    operation_action,
                    application_context=application_context,
                    id=operation_id,
                    context=operation_context,
                    timestamp=operation_timestamp,
                    summary="Failed processing request",
                    error=error_cls(),
                    connection_context=connection_context,
                    authentication=authentication,
                    authorization=authorization,
                    impersonation=impersonation,
                    response=validated_response,
                    response_context=response_context,
                )
                operation.log(logger, LogLevel.ERROR)
                operation.publish(logger, publishers)
        except Exception:
            decoded_body = response_body.decode(errors="replace")
            if len(decoded_body) > config.max_size:
                decoded_body = (
                    decoded_body[: config.max_size]
                    + f"... [truncated, {len(decoded_body)} bytes total]"
                )
            logger.info(
                f"Successfully processed request with status code {final_response.status_code} but response body can not be loaded to maleo response schema",
                extra={
                    "json_fields": {
                        "response": {
                            "body": decoded_body,
                            "headers": final_response.headers.items(),
                            "media_type": final_response.media_type,
                            "status_code": final_response.status_code,
                        }
                    }
                },
            )

        return final_response

    return dispatch
