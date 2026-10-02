from __future__ import annotations

from pydantic import BaseModel, Field


class SnapshotCreate(BaseModel):
    end_event_id: int = Field(ge=1)
    redact_tokens: bool = True
    redact_contacts: bool = True
    redact_restricted_cases: bool = True
    restricted_case_ids: list[int] | None = Field(default=None, max_length=10_000)
    chunk_size: int = Field(default=200, ge=1, le=5_000)


class SnapshotGenerate(BaseModel):
    max_chunks: int | None = Field(default=None, ge=1, le=5_000)
