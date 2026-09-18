"""Translate expected failures into stable JSON bodies."""

from collections.abc import Sequence

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.requests import Request

from sentinel.errors import (
    AlertNotFound,
    AlertValidationError,
    ConfigurationError,
    FieldIssue,
    InvestigationNotFound,
)
from sentinel.schemas.errors import (
    AlertNotFoundBody,
    FieldError,
    InvestigationNotFoundBody,
    NotConfiguredBody,
    ValidationErrorBody,
)
from sentinel.services.validation import issues_from_error_list


def _validation_response(issues: Sequence[FieldIssue]) -> JSONResponse:
    body = ValidationErrorBody(
        errors=[FieldError(code=issue.code, field=issue.field) for issue in issues]
    )
    return JSONResponse(status_code=422, content=body.model_dump(mode="json"))


def register_exception_handlers(application: FastAPI) -> None:
    """Replace FastAPI's default 422 so responses do not echo alert input."""

    @application.exception_handler(RequestValidationError)
    async def on_request_validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return _validation_response(list(issues_from_error_list(exc.errors(), drop_body=True)))

    @application.exception_handler(AlertValidationError)
    async def on_alert_validation(_request: Request, exc: AlertValidationError) -> JSONResponse:
        return _validation_response(list(exc.issues))

    @application.exception_handler(AlertNotFound)
    async def on_alert_not_found(_request: Request, _exc: AlertNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content=AlertNotFoundBody().model_dump(mode="json"))

    @application.exception_handler(InvestigationNotFound)
    async def on_investigation_not_found(
        _request: Request, _exc: InvestigationNotFound
    ) -> JSONResponse:
        body = InvestigationNotFoundBody().model_dump(mode="json")
        return JSONResponse(status_code=404, content=body)

    @application.exception_handler(ConfigurationError)
    async def on_not_configured(_request: Request, exc: ConfigurationError) -> JSONResponse:
        body = NotConfiguredBody(provider=exc.provider).model_dump(mode="json")
        return JSONResponse(status_code=503, content=body)
