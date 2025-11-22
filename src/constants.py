from nexo.enums.connection import Header, Method
from nexo.types.string import SeqOfStrs


ALLOW_METHODS: SeqOfStrs = (
    Method.GET.value,
    Method.POST.value,
    Method.PUT.value,
    Method.PATCH.value,
    Method.DELETE.value,
    Method.OPTIONS.value,
)

ALLOW_HEADERS: SeqOfStrs = (
    Header.ACCEPT.value,
    Header.ACCEPT_LANGUAGE.value,
    Header.AUTHORIZATION.value,
    Header.CONTENT_TYPE.value,
    Header.COOKIE.value,
    Header.X_API_KEY.value,
    Header.X_CLIENT_ID.value,
    Header.X_CLIENT_SECRET.value,
    Header.X_OPERATION_ID.value,
    Header.X_ORGANIZATION_ID.value,
    Header.X_SIGNATURE.value,
    Header.X_SPAN_ID.value,
    Header.X_TRACE_ID.value,
    Header.X_USER_ID.value,
)

EXPOSE_HEADERS: SeqOfStrs = (
    Header.LINK.value,
    Header.LOCATION.value,
    Header.RETRY_AFTER.value,
    Header.WWW_AUTHENTICATE.value,
    Header.X_CLIENT_ID.value,
    Header.X_CLIENT_SECRET.value,
    Header.X_COMPLETED_AT.value,
    Header.X_CONNECTION_ID.value,
    Header.X_DURATION.value,
    Header.X_EXECUTED_AT.value,
    Header.X_NEW_AUTHORIZATION.value,
    Header.X_OPERATION_ID.value,
    Header.X_ORGANIZATION_ID.value,
    Header.X_SIGNATURE.value,
    Header.X_SPAN_ID.value,
    Header.X_TRACE_ID.value,
    Header.X_USER_ID.value,
)
