"""Pydantic request/response schemas for the API."""

from datetime import datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field


# Request Schemas
class TargetCreate(BaseModel):
    """Schema for creating a new target."""

    name: str = Field(..., min_length=1, description="Target name")
    endpoint_url: str = Field(..., description="Target API endpoint URL")
    api_key: str = Field(..., description="API key for authentication")
    model_name: str = Field(..., description="Model identifier")
    provider: str = Field(
        ..., description="Provider type: openai, anthropic, or custom"
    )
    max_tokens: int = Field(default=2000, ge=1, le=128000)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    custom_headers: Optional[dict[str, str]] = Field(
        default=None, description="Custom HTTP headers"
    )
    request_template: Optional[str] = Field(
        default=None, description="Custom request template"
    )
    response_path: Optional[str] = Field(
        default=None, description="JSON path to response content"
    )


class TargetUpdate(BaseModel):
    """Schema for updating a target."""

    name: Optional[str] = None
    endpoint_url: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    provider: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    custom_headers: Optional[dict[str, str]] = None
    request_template: Optional[str] = None
    response_path: Optional[str] = None


class TestRunCreate(BaseModel):
    """Schema for creating a new test run."""

    target_id: str = Field(..., description="Target ID to test")
    attack_categories: Optional[list[str]] = Field(
        default=None, description="OWASP categories to test (None = all)"
    )
    test_mode: str = Field(
        default="single_turn", description="Test mode: single_turn or multi_turn"
    )
    max_concurrent: int = Field(default=5, ge=1, le=50)
    scorer_type: str = Field(
        default="composite", description="Scorer type: pattern, llm_judge, canary, composite"
    )
    canary_strings: Optional[list[str]] = Field(
        default=None, description="Canary strings for canary scorer"
    )


class TestRunFilters(BaseModel):
    """Schema for filtering test runs."""

    status: Optional[str] = None
    target_id: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None


# Response Schemas
class TargetResponse(BaseModel):
    """Response schema for a target."""

    id: str
    name: str
    endpoint_url: str
    model_name: str
    provider: str
    created_at: datetime

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class SummaryStats(BaseModel):
    """Summary statistics for a test run."""

    pass_count: int
    fail_count: int
    total: int
    pass_rate: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class TestRunResponse(BaseModel):
    """Response schema for a test run."""

    id: str
    target: TargetResponse
    status: str
    attack_categories: list[str]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary: Optional[SummaryStats] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class TestResultResponse(BaseModel):
    """Response schema for a test result (truncated)."""

    id: int
    test_run_id: str
    attack_name: str
    owasp_category: str
    owasp_category_description: str
    severity: str
    payload_content: str = Field(description="Truncated to 200 chars")
    target_response: str = Field(description="Truncated to 500 chars")
    success: bool
    confidence: float
    execution_time_ms: int
    created_at: datetime

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class TestResultDetail(BaseModel):
    """Response schema for detailed test result (full content)."""

    id: int
    test_run_id: str
    attack_name: str
    owasp_category: str
    owasp_category_description: str
    severity: str
    payload_content: str = Field(description="Full payload content")
    target_response: str = Field(description="Full target response")
    success: bool
    confidence: float
    execution_time_ms: int
    scorer_details: dict[str, Any]
    created_at: datetime

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class AttackModuleResponse(BaseModel):
    """Response schema for an attack module."""

    name: str
    description: str
    owasp_category: str
    owasp_category_code: str
    default_severity: str
    payload_count: int


class CategoryInfo(BaseModel):
    """Info about an OWASP category."""

    code: str
    name: str
    description: str


class FindingBySeverity(BaseModel):
    """Finding grouped by severity."""

    severity: str
    count: int
    examples: list[str] = Field(default_factory=list)


class CategoryFinding(BaseModel):
    """Finding info for a category."""

    category_code: str
    category_name: str
    category_description: str
    findings_by_severity: list[FindingBySeverity]
    recommendations: list[str]


class ReportResponse(BaseModel):
    """Response schema for a security assessment report."""

    test_run_id: str
    generated_at: datetime
    target_name: str
    summary: dict[str, Any]
    findings_by_category: list[CategoryFinding]
    risk_score: float = Field(ge=0, le=100, description="Overall risk score 0-100")
    recommendations: list[str]

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


class HealthResponse(BaseModel):
    """Response schema for health check endpoint."""

    status: str
    version: str
    timestamp: datetime

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
