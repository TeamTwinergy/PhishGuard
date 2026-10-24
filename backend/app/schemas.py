"""Validated request/response models (Pydantic v2)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class FindingModel(BaseModel):
    rule_id: str
    group: str
    title: str
    severity: Literal["low", "medium", "high"]
    weight: int
    evidence: str
    why_it_matters: str
    recommended_action: str


class ObservationModel(BaseModel):
    id: str
    title: str
    detail: str


class ScoreItem(BaseModel):
    rule_id: str
    group: str
    weight: int
    counted: bool
    note: str


class QueryParamModel(BaseModel):
    name: str
    value: str
    redacted: bool


class URLBreakdown(BaseModel):
    scheme: str
    scheme_assumed: bool
    hostname: str
    hostname_unicode: str
    is_ip: bool
    ip_address: Optional[str]
    port: Optional[int]
    registered_domain: Optional[str]
    suffix: Optional[str]
    subdomains: list[str]
    domain_parsing: Literal["heuristic", "not_applicable"]
    path: str
    query_params: list[QueryParamModel]
    fragment: Optional[str]
    has_userinfo: bool
    redacted_url: str
    normalization_notes: list[str]


class ReputationResult(BaseModel):
    provider: str
    status: Literal["match", "no_match", "not_checked", "error", "timeout", "rate_limited"]
    detail: Optional[str] = None
    threat_types: Optional[list[str]] = None


class ProviderInfo(BaseModel):
    name: str
    configured: bool


class SkippedCheck(BaseModel):
    check: str
    status: Literal["not_checked", "unavailable", "inconclusive"]
    reason: str


class ExplanationModel(BaseModel):
    source: Literal["deterministic", "ai"]
    summary: str
    evidence: list[str]
    limitations: list[str]
    next_steps: list[str]


class ScanResponse(BaseModel):
    scan_id: str
    scanned_at: datetime
    hostname: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_category: str
    thresholds: list[int]
    score_method: str
    findings: list[FindingModel]
    positive_observations: list[ObservationModel]
    score_breakdown: list[ScoreItem]
    url_breakdown: URLBreakdown
    reputation: list[ReputationResult]
    skipped_checks: list[SkippedCheck]
    explanation: ExplanationModel
    recommended_next_steps: list[str]


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
