from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.archives.schemas import SnapshotCreate, SnapshotGenerate
from app.archives.service import ArchiveService
from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection, transaction
from app.services.audit import AuditContext, AuditService

router = APIRouter(prefix="/api/audit/archives", tags=["审计归档"])


def _service() -> ArchiveService:
    return ArchiveService(get_connection())


@router.post("", status_code=201)
def freeze_snapshot(data: SnapshotCreate, principal: Principal = Depends(current_principal)) -> dict:
    """管理员选定截止事件与脱敏策略后冻结快照范围。"""
    principal.require("audit.archive")
    with transaction(immediate=True) as connection:
        snapshot = ArchiveService(connection).freeze(
            created_by=principal.user_id,
            created_by_name=principal.display_name,
            end_event_id=data.end_event_id,
            redact_tokens=data.redact_tokens,
            redact_contacts=data.redact_contacts,
            redact_restricted_cases=data.redact_restricted_cases,
            restricted_case_ids=data.restricted_case_ids,
            chunk_size=data.chunk_size,
        )
        AuditService(connection).record(
            AuditContext(principal.user_id, principal.display_name),
            action="audit.archive.freeze",
            resource_type="audit_archive",
            reagency_id=snapshot["id"],
            after={"fingerprint": snapshot["fingerprint"], "end_event_id": data.end_event_id},
        )
    return snapshot


@router.get("")
def list_snapshots(
    status: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.read")
    return _service().list_snapshots(status=status, limit=size, offset=(page - 1) * size)


@router.get("/{snapshot_id}")
def get_snapshot(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.read")
    return _service().get_snapshot(snapshot_id)


@router.post("/{snapshot_id}/generate")
def generate_snapshot(
    snapshot_id: int,
    data: SnapshotGenerate | None = None,
    principal: Principal = Depends(current_principal),
) -> dict:
    """按稳定游标续跑分块；已确认分块不会重复，完成后得到清单根摘要。"""
    principal.require("audit.archive")
    max_chunks = data.max_chunks if data else None
    result = _service().generate(snapshot_id, max_chunks=max_chunks)
    with transaction(immediate=True) as connection:
        AuditService(connection).record(
            AuditContext(principal.user_id, principal.display_name),
            action="audit.archive.generate",
            resource_type="audit_archive",
            reagency_id=snapshot_id,
            metadata={"status": result["status"], "confirmed_chunks": result["confirmed_chunks"]},
        )
    return result


@router.get("/{snapshot_id}/chunks")
def list_chunks(snapshot_id: int, principal: Principal = Depends(current_principal)) -> list[dict]:
    principal.require("audit.read")
    return _service().list_chunks(snapshot_id)


@router.get("/{snapshot_id}/verify")
def verify_snapshot(snapshot_id: int, principal: Principal = Depends(current_principal)) -> dict:
    """对照线上审计事件独立重算全部摘要，只读、不改业务状态。"""
    principal.require("audit.verify")
    return _service().verify(snapshot_id)


@router.get("/{snapshot_id}/events")
def list_snapshot_events(
    snapshot_id: int,
    reveal: bool = False,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.read")
    if reveal:
        # 查看规范化原值（含令牌/联系方式）属于归档管理权限。
        principal.require("audit.archive")
    return _service().events_page(snapshot_id, limit=size, offset=(page - 1) * size, reveal=reveal)


@router.get("/{snapshot_id}/events/{event_id}/trace")
def trace_snapshot_event(
    snapshot_id: int,
    event_id: int,
    reveal: bool = False,
    principal: Principal = Depends(current_principal),
) -> dict:
    """从快照条目追溯到线上原审计事件并比对摘要，不改变线上状态。"""
    principal.require("audit.read")
    if reveal:
        principal.require("audit.archive")
    return _service().trace_event(snapshot_id, event_id, reveal=reveal)


@router.get("/{snapshot_id}/export")
def export_snapshot_bundle(
    snapshot_id: int,
    profile: str = Query("redacted", pattern="^(manifest|redacted|canonical)$"),
    principal: Principal = Depends(current_principal),
) -> dict:
    """导出归档包：manifest 仅摘要、redacted 含脱敏视图、canonical 含原值。"""
    principal.require("audit.read")
    if profile == "canonical":
        principal.require("audit.archive")
    return _service().export_bundle(snapshot_id, profile=profile)
