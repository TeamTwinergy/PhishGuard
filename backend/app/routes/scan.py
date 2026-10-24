from __future__ import annotations

from fastapi import APIRouter, Depends

from ..errors import ApiError
from ..rate_limit import enforce_rate_limit
from ..scan_service import run_scan
from ..reputation import get_providers
from ..schemas import ErrorResponse, ProviderInfo, ScanRequest, ScanResponse
from ..url_parser import InvalidURLError

router = APIRouter(prefix="/api", tags=["scan"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    responses={422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def scan(payload: ScanRequest, _: None = Depends(enforce_rate_limit)):
    try:
        return run_scan(payload.url)
    except InvalidURLError as exc:
        raise ApiError(422, exc.code, exc.message)


@router.get("/providers", response_model=list[ProviderInfo])
def providers():
    """Which reputation providers are configured (never exposes keys)."""
    return [{"name": p.name, "configured": p.is_configured()} for p in get_providers()]
