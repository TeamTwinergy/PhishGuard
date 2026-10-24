from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import CORS_ORIGINS, MAX_BODY_BYTES
from .errors import ApiError, error_payload
from .routes.scan import router as scan_router

# Keep HTTP client logs quiet: they could otherwise include request details.
logging.getLogger("httpx").setLevel(logging.WARNING)

app = FastAPI(title="PhishGuard API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def guard(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse(error_payload("payload_too_large", "Request body is too large."), status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(ApiError)
async def api_error_handler(_: Request, exc: ApiError):
    return JSONResponse(error_payload(exc.code, exc.message), status_code=exc.status_code, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, __: RequestValidationError):
    # Deliberately generic: never echo the submitted URL back.
    return JSONResponse(
        error_payload("invalid_request", 'Send JSON like {"url": "https://..."} with a url of 1 to 4096 characters.'),
        status_code=422,
    )


@app.exception_handler(StarletteHTTPException)
async def http_handler(_: Request, exc: StarletteHTTPException):
    return JSONResponse(error_payload("http_error", str(exc.detail)), status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_handler(_: Request, __: Exception):
    return JSONResponse(error_payload("internal_error", "Something went wrong on our side."), status_code=500)


@app.get("/health")
def health():
    return {"status": "ok", "service": "phishguard-api", "version": app.version}


app.include_router(scan_router)
