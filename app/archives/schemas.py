from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.archives.redaction import POLICY_NONE


class SnapshotFreezeRequest(BaseModel):
    cutoff_event_id: int = Field(ge=1)
    policy_code: str = Field(default=POLICY_NONE)
    scope_start_id: int = Field(default=1, ge=1)
    chunk_size: int = Field(default=200, ge=1, le=5000)
    policy_params: dict[str, Any] = Field(default_factory=dict)


class ValueVerificationRequest(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    original: Any
