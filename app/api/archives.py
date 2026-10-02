from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.archives.redaction import ReviewAuthority
from app.archives.schemas import SnapshotFreezeRequest, ValueVerificationRequest
from app.archives.service import ArchiveService, FreezeRequest
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction

router = APIRouter(prefix="/api/audit-archives", tags=["审计归档"])


def _service() -> ArchiveService:
    return ArchiveService(get_connection())


def _review_authority(principal: Principal) -> ReviewAuthority:
    granted = principal.can("audit.archive.review")
    return ReviewAuthority(
        can_review_tokens=granted,
        can_review_contacts=granted,
        can_review_restricted=granted,
    )


@router.post("/freeze", status_code=201)
def freeze_snapshot(data: SnapshotFreezeRequest, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.archive.freeze")
    with transaction(immediate=True) as connection:
        snapshot = ArchiveService(connection).freeze(FreezeRequest(
            cutoff_event_id=data.cutoff_event_id,
            policy_code=data.policy_code,
            scope_start_id=data.scope_start_id,
            chunk_size=data.chunk_size,
            policy_params=data.policy_params,
            created_by=principal.username,
        ))
    return ArchiveService.public_view(snapshot)


@router.post("/{snapshot_id}/generate")
def generate_snapshot(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.archive.generate")
    service = _service()
    service.generate(snapshot_id, worker=f"api:{principal.username}")
    return service.progress(snapshot_id)


@router.get("")
def list_snapshots(
    status: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.archive.read")
    service = _service()
    pagination = Page(page, size)
    rows = [ArchiveService.public_view(row)
            for row in service.repository.list_snapshots(status=status, limit=size, offset=pagination.offset)]
    return page_result(total=service.repository.count_snapshots(status), page=pagination, rows=rows)


@router.get("/{snapshot_id}")
def snapshot_detail(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.archive.read")
    return ArchiveService.public_view(_service().get(snapshot_id))


@router.get("/{snapshot_id}/progress")
def snapshot_progress(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.archive.read")
    return _service().progress(snapshot_id)


@router.get("/{snapshot_id}/chunks/{seq}")
def snapshot_chunk(
    snapshot_id: int,
    seq: int,
    reveal: bool = Query(default=False),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.archive.read")
    if reveal:
        principal.require("audit.archive.review")
    return _service().chunk_events(
        snapshot_id, seq, authority=_review_authority(principal), reveal=reveal
    )


@router.post("/{snapshot_id}/verify")
def verify_snapshot(
    snapshot_id: int,
    deep: bool = Query(default=False),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.archive.verify")
    if deep:
        principal.require("audit.archive.review")
    return _service().verify_snapshot(snapshot_id, deep=deep)


@router.get("/{snapshot_id}/events/{audit_event_id}/provenance")
def event_provenance(
    snapshot_id: int,
    audit_event_id: int,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.archive.verify")
    return _service().provenance(
        snapshot_id, audit_event_id, can_review=principal.can("audit.archive.review")
    )


@router.post("/{snapshot_id}/events/{audit_event_id}/verify-value")
def verify_value(
    snapshot_id: int,
    audit_event_id: int,
    data: ValueVerificationRequest,
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.archive.review")
    return _service().verify_value(
        snapshot_id, audit_event_id, path=data.path, original=data.original
    )


@router.get("/{snapshot_id}/bundle")
def export_bundle(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.archive.verify")
    return _service().export_bundle(snapshot_id)
