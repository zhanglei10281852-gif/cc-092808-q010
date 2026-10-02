"""审计归档快照服务：冻结范围、分块生成、连续摘要、恢复与独立校验。

设计要点：
- 快照在创建时冻结"截止事件 + 脱敏策略 + 封存时刻"，指纹只依赖这些固化输入，
  因此同一快照重复执行得到相同标识；任一输入变化都会产生新指纹，只能新建版本。
- 每个分块是一个提交事务（恢复单元）。事件有独立摘要与块内连续摘要，分块摘要
  再与前一块串联，任何删除、插入、重排或字段变化都会在校验时暴露。
- 全部操作只读线上 ``audit_events``，不回写业务状态。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable

from app.archives.hashing import (
    ALGORITHM,
    GENESIS_DIGEST,
    canonical_json,
    chain_digest,
    constant_time_equals,
    digest,
    sign,
)
from app.archives.redaction import (
    build_redacted_view,
    freeze_policy,
    freeze_scope,
    iter_redaction_marks,
    normalize_event,
)
from app.archives.repository import ArchiveRepository
from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.privacy import sanitize_payload
from app.database import transaction as db_transaction

SNAPSHOT_SCHEMA = "audit-archive-snapshot/v1"
CHUNK_SCHEMA = "audit-archive-chunk/v1"
MANIFEST_SCHEMA = "audit-archive-manifest/v1"
BUNDLE_SCHEMA = "audit-archive-bundle/v1"

DEFAULT_CHUNK_SIZE = 200
MAX_CHUNK_SIZE = 5_000
VERIFY_EVENT_CAP = 1_000_000


class ArchiveService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ArchiveRepository(connection)

    # ------------------------------------------------------------------ 冻结
    def freeze(
        self,
        *,
        created_by: int | None,
        created_by_name: str,
        end_event_id: int,
        redact_tokens: bool,
        redact_contacts: bool,
        redact_restricted_cases: bool,
        restricted_case_ids: list[int] | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> dict[str, Any]:
        if end_event_id <= 0:
            raise ValidationError("截止事件 ID 必须为正整数")
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValidationError(f"分块大小必须在 1 到 {MAX_CHUNK_SIZE} 之间")
        end_row = self.repository.audit_event(end_event_id)
        if end_row is None:
            raise ValidationError("截止事件不存在，不能冻结快照范围")
        now = self.clock.now()
        frozen_at = to_storage(now)
        if restricted_case_ids is None:
            restricted_case_ids = self.repository.restricted_case_ids() if redact_restricted_cases else []
        restricted_case_ids = sorted(set(int(case_id) for case_id in restricted_case_ids))
        unknown = set(restricted_case_ids) - self.repository.case_ids_present(restricted_case_ids)
        if unknown:
            raise ValidationError(f"受限案件不存在：{sorted(unknown)}")
        policy = freeze_policy(
            redact_tokens=redact_tokens,
            redact_contacts=redact_contacts,
            redact_restricted_cases=redact_restricted_cases,
            restricted_case_ids=restricted_case_ids,
        )
        scope = freeze_scope(end_event_id=end_event_id, created_before=frozen_at)
        expected = self.repository.audit_count_in_range(scope["start_event_id"], end_event_id)
        fingerprint_input = {
            "schema": SNAPSHOT_SCHEMA,
            "scope": scope,
            "policy": policy,
            "chunk_size": chunk_size,
            "frozen_at": frozen_at,
            "created_by": created_by,
        }
        fingerprint = digest(fingerprint_input)
        existing = self.repository.snapshot_by_fingerprint(fingerprint)
        if existing is not None:
            raise ConflictError(
                "相同范围、策略与封存时刻的快照已存在；调整策略将创建新版本，不会覆盖旧归档",
                context={"snapshot_id": existing["id"], "snapshot_code": existing["snapshot_code"]},
            )
        snapshot_code = f"ARC-{frozen_at[:10].replace('-', '')}-{fingerprint[:12].upper()}"
        with db_transaction(immediate=True) as connection:
            snapshot = ArchiveRepository(connection).insert_snapshot(
                {
                    "snapshot_code": snapshot_code,
                    "scope": scope,
                    "policy": policy,
                    "fingerprint": fingerprint,
                    "chunk_size": chunk_size,
                    "start_event_id": scope["start_event_id"],
                    "end_event_id": end_event_id,
                    "expected_event_count": expected,
                    "status": "frozen",
                    "created_by": created_by,
                    "created_by_name": created_by_name,
                },
                frozen_at,
            )
        return self.get_snapshot(int(snapshot["id"]))

    # ------------------------------------------------------------ 读取视图
    @staticmethod
    def _load_json(raw: str | None, default: Any) -> Any:
        return json.loads(raw) if raw is not None else default

    def public_snapshot(self, row: dict[str, Any]) -> dict[str, Any]:
        coverage = self.repository.coverage(row["id"])
        return {
            "id": row["id"],
            "snapshot_code": row["snapshot_code"],
            "status": row["status"],
            "fingerprint": row["fingerprint"],
            "manifest_digest": row["manifest_digest"],
            "manifest_signature": row["manifest_signature"],
            "algorithm": ALGORITHM,
            "scope": self._load_json(row["scope_json"], {}),
            "policy": self._load_json(row["policy_json"], {}),
            "chunk_size": row["chunk_size"],
            "start_event_id": row["start_event_id"],
            "end_event_id": row["end_event_id"],
            "expected_event_count": row["expected_event_count"],
            "total_events": row["total_events"],
            "total_chunks": row["total_chunks"],
            "confirmed_chunks": int(coverage["chunks"] or 0),
            "confirmed_events": int(coverage["events"] or 0),
            "covered_from_event_id": coverage["first_id"],
            "covered_to_event_id": coverage["last_id"],
            "failure_reason": row["failure_reason"],
            "created_by": row["created_by"],
            "created_by_name": row["created_by_name"],
            "frozen_at": row["frozen_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def require_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        return self.repository.require_snapshot(snapshot_id)

    def get_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        return self.public_snapshot(self.require_snapshot(snapshot_id))

    def list_snapshots(self, *, status: str | None = None, limit: int, offset: int) -> dict[str, Any]:
        rows, total = self.repository.list_snapshots(status=status, limit=limit, offset=offset)
        return {
            "items": [self.public_snapshot(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def list_chunks(self, snapshot_id: int) -> list[dict[str, Any]]:
        self.require_snapshot(snapshot_id)
        return self.repository.list_chunks(snapshot_id)

    def events_page(self, snapshot_id: int, *, limit: int, offset: int, reveal: bool) -> dict[str, Any]:
        snapshot = self.require_snapshot(snapshot_id)
        rows = self.repository.list_archived_events(snapshot_id, limit=limit, offset=offset)
        items: list[dict[str, Any]] = []
        for row in rows:
            if reveal:
                payload = json.loads(row["canonical_json"])
            else:
                payload = json.loads(row["redacted_json"])
            items.append(
                {
                    "seq": row["seq"],
                    "event_id": row["event_id"],
                    "chunk_seq": row["chunk_seq"],
                    "event_digest": row["event_digest"],
                    "entry_digest": row["entry_digest"],
                    "restricted_case": bool(row["restricted_case"]),
                    "redaction_count": row["redaction_count"],
                    "payload": payload,
                }
            )
        return {
            "snapshot_code": snapshot["snapshot_code"],
            "total": self.repository.count_archived_events(snapshot_id),
            "limit": limit,
            "offset": offset,
            "reveal": reveal,
            "items": items,
        }

    # ------------------------------------------------------------ 分块生成
    def generate(
        self,
        snapshot_id: int,
        *,
        max_chunks: int | None = None,
        event_hook: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """从已确认分块之后继续生成，直到完成或失败。可安全重复执行。"""
        snapshot = self.require_snapshot(snapshot_id)
        if snapshot["status"] == "completed":
            return self.get_snapshot(snapshot_id)
        with db_transaction(immediate=True) as connection:
            ArchiveRepository(connection).update_status(
                snapshot_id, "generating", now=to_storage(self.clock.now())
            )
        produced = 0
        try:
            while True:
                # 每个分块独立提交：中断后已确认分块就是恢复点，不会重复或丢失。
                try:
                    with db_transaction(immediate=True) as connection:
                        chunk = self._generate_next_chunk(
                            ArchiveRepository(connection),
                            snapshot,
                            event_hook=event_hook,
                        )
                except sqlite3.IntegrityError as exc:
                    # 另一生成任务已确认同一分块（输出确定性一致），不覆盖其进度。
                    raise ConflictError("该快照已有生成任务在执行，请勿并发续跑") from exc
                if chunk is None:
                    break
                produced += 1
                if max_chunks is not None and produced >= max_chunks:
                    return self.get_snapshot(snapshot_id)
            self._finalize(snapshot)
        except Exception as exc:
            with db_transaction(immediate=True) as connection:
                current = ArchiveRepository(connection).require_snapshot(snapshot_id)
                if current["status"] != "completed":
                    ArchiveRepository(connection).update_status(
                        snapshot_id, "failed",
                        reason=f"{type(exc).__name__}: {exc}"[:1000],
                        now=to_storage(self.clock.now()),
                    )
            raise
        return self.get_snapshot(snapshot_id)

    def _generate_next_chunk(
        self,
        repo: ArchiveRepository,
        snapshot: dict[str, Any],
        *,
        event_hook: Callable[[dict[str, Any]], None] | None,
    ) -> dict[str, Any] | None:
        snapshot_id = int(snapshot["id"])
        end_event_id = int(snapshot["end_event_id"])
        chunk_size = int(snapshot["chunk_size"])
        secret = repo.archive_secret(to_storage(self.clock.now()))
        policy = self._load_json(snapshot["policy_json"], {})
        last = repo.last_chunk(snapshot_id)
        seq = 0 if last is None else int(last["seq"]) + 1
        start_id = 1 if last is None else int(last["end_event_id"]) + 1
        if start_id > end_event_id:
            return None
        rows = repo.audit_events_window(start_id, end_event_id, chunk_size)
        if not rows:
            return None
        previous_entry = GENESIS_DIGEST
        stored_rows: list[dict[str, Any]] = []
        first_digest = last_digest = ""
        prior_chunks = repo.list_chunks(snapshot_id)
        global_seq = sum(int(chunk["event_count"]) for chunk in prior_chunks)
        for offset, row in enumerate(rows):
            normalized = normalize_event(row)
            raw_bytes = canonical_json(normalized)
            event_digest = digest(normalized)
            view, points = build_redacted_view(normalized, policy, secret=secret)
            redacted_bytes = canonical_json(view)
            global_seq += 1
            entry_payload = {
                "seq": offset + 1,
                "event_id": normalized["id"],
                "event_digest": event_digest,
                "redacted_digest": digest(view),
                "redaction_count": len(points),
            }
            entry_digest = chain_digest(previous_entry, entry_payload)
            previous_entry = entry_digest
            first_digest = first_digest or event_digest
            last_digest = event_digest
            stored_rows.append(
                {
                    "event_id": normalized["id"],
                    "chunk_seq": seq,
                    "seq": global_seq,
                    "canonical_json": raw_bytes.decode("utf-8"),
                    "redacted_json": redacted_bytes.decode("utf-8"),
                    "event_digest": event_digest,
                    "entry_digest": entry_digest,
                    "restricted_case": bool(view["restricted_case"]),
                    "redaction_count": len(points),
                }
            )
            if event_hook is not None:
                event_hook(normalized)
        previous_chunk = GENESIS_DIGEST if last is None else str(last["chunk_digest"])
        chunk_payload = {
            "schema": CHUNK_SCHEMA,
            "seq": seq,
            "start_event_id": int(rows[0]["id"]),
            "end_event_id": int(rows[-1]["id"]),
            "event_count": len(rows),
            "first_event_digest": first_digest,
            "last_event_digest": last_digest,
            "event_entry_digest": previous_entry,
        }
        chunk_digest = chain_digest(previous_chunk, chunk_payload)
        repo.insert_events(snapshot_id, stored_rows)
        repo.insert_chunk(
            snapshot_id,
            {**chunk_payload, "chunk_digest": chunk_digest},
            to_storage(self.clock.now()),
        )
        return {**chunk_payload, "chunk_digest": chunk_digest}

    def _finalize(self, snapshot: dict[str, Any]) -> None:
        snapshot_id = int(snapshot["id"])
        with db_transaction(immediate=True) as connection:
            repo = ArchiveRepository(connection)
            secret = repo.archive_secret(to_storage(self.clock.now()))
            chunks = repo.list_chunks(snapshot_id)
            total_events = sum(int(chunk["event_count"]) for chunk in chunks)
            expected = int(snapshot["expected_event_count"])
            end_event_id = int(snapshot["end_event_id"])
            if total_events != expected:
                raise ConflictError(
                    f"归档事件数 {total_events} 与冻结范围预期 {expected} 不一致，范围可能被改动",
                    context={"total_events": total_events, "expected": expected},
                )
            coverage = repo.coverage(snapshot_id)
            if int(coverage["last_id"] or 0) != end_event_id:
                raise ConflictError("分块未覆盖到截止事件，归档不完整")
            last_digest_value = str(chunks[-1]["chunk_digest"]) if chunks else GENESIS_DIGEST
            manifest = {
                "schema": MANIFEST_SCHEMA,
                "snapshot_code": snapshot["snapshot_code"],
                "fingerprint": snapshot["fingerprint"],
                "total_events": total_events,
                "total_chunks": len(chunks),
                "last_chunk_digest": last_digest_value,
            }
            manifest_digest = digest(manifest)
            repo.complete_snapshot(
                snapshot_id,
                total_events=total_events,
                total_chunks=len(chunks),
                manifest_digest=manifest_digest,
                manifest_signature=sign(secret, snapshot["snapshot_code"], manifest_digest),
                now=to_storage(self.clock.now()),
            )

    # ---------------------------------------------------------------- 校验
    def verify(self, snapshot_id: int) -> dict[str, Any]:
        """对照线上审计事件重新计算全部摘要。只读，不改变任何业务状态。"""
        snapshot = self.require_snapshot(snapshot_id)
        scope = self._load_json(snapshot["scope_json"], {})
        policy = self._load_json(snapshot["policy_json"], {})
        start_id, end_id = int(scope["start_event_id"]), int(scope["end_event_id"])
        errors: list[str] = []
        checks: list[dict[str, Any]] = []

        def check(name: str, ok: bool, detail: str) -> bool:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
            if not ok:
                errors.append(f"{name}: {detail}")
            return bool(ok)

        fingerprint_input = {
            "schema": SNAPSHOT_SCHEMA,
            "scope": scope,
            "policy": policy,
            "chunk_size": int(snapshot["chunk_size"]),
            "frozen_at": snapshot["frozen_at"],
            "created_by": snapshot["created_by"],
        }
        check(
            "fingerprint",
            digest(fingerprint_input) == snapshot["fingerprint"],
            "快照指纹与固化的范围、策略和封存时刻一致",
        )

        chunks = self.repository.list_chunks(snapshot_id)
        stored_events: list[dict[str, Any]] = []
        while True:
            batch = self.repository.list_archived_events(
                snapshot_id, limit=VERIFY_EVENT_CAP, offset=len(stored_events)
            )
            stored_events.extend(batch)
            if len(batch) < VERIFY_EVENT_CAP:
                break
        by_id = {int(row["event_id"]): row for row in stored_events}

        live_count = self.repository.audit_count_in_range(start_id, end_id)
        check(
            "range_count",
            live_count == int(snapshot["expected_event_count"]) == len(stored_events),
            f"线上 {live_count} 条，冻结预期 {snapshot['expected_event_count']} 条，清单 {len(stored_events)} 条",
        )
        live_rows = self.repository.audit_events_window(start_id, end_id, live_count or 1)
        live_ids = {int(row["id"]) for row in live_rows}
        archived_ids = set(by_id)
        missing_from_live = sorted(archived_ids - live_ids)
        inserted_into_range = sorted(live_ids - archived_ids)
        check("no_deleted_events", not missing_from_live, f"线上已删除、清单仍登记的事件：{missing_from_live[:20]}")
        check("no_inserted_events", not inserted_into_range, f"冻结后插入覆盖区间的新事件：{inserted_into_range[:20]}")

        secret = self.repository.archive_secret(to_storage(self.clock.now()))
        field_mismatches: list[int] = []
        redaction_mismatches: list[int] = []
        for live_row in live_rows:
            normalized = normalize_event(live_row)
            stored = by_id.get(int(live_row["id"]))
            if stored is None:
                continue
            if digest(normalized) != stored["event_digest"]:
                field_mismatches.append(int(live_row["id"]))
                continue
            view, _points = build_redacted_view(normalized, policy, secret=secret)
            if canonical_json(view).decode("utf-8") != stored["redacted_json"]:
                redaction_mismatches.append(int(live_row["id"]))
        check("event_fields_unchanged", not field_mismatches, f"字段值变化的事件：{field_mismatches[:20]}")
        check("redaction_commits", not redaction_mismatches, f"脱敏视图或承诺不一致：{redaction_mismatches[:20]}")

        # 块内连续摘要 + 分块串联
        chunk_errors: list[str] = []
        previous_chunk = GENESIS_DIGEST
        expected_start: int | None = None
        global_offset = 0
        for index, chunk in enumerate(chunks):
            members = sorted(
                (row for row in stored_events if int(row["chunk_seq"]) == int(chunk["seq"])),
                key=lambda row: int(row["event_id"]),
            )
            previous_entry = GENESIS_DIGEST
            for offset, row in enumerate(members):
                payload = {
                    "seq": offset + 1,
                    "event_id": int(row["event_id"]),
                    "event_digest": row["event_digest"],
                    "redacted_digest": digest(json.loads(row["redacted_json"])),
                    "redaction_count": int(row["redaction_count"]),
                }
                previous_entry = chain_digest(previous_entry, payload)
                if row["entry_digest"] != previous_entry:
                    chunk_errors.append(f"事件 {row['event_id']} 的条目连续摘要与封存值不符")
                if int(row["seq"]) != global_offset + offset + 1:
                    chunk_errors.append(f"事件 {row['event_id']} 全局序号重排")
            global_offset += len(members)
            first_id = int(members[0]["event_id"]) if members else None
            last_id = int(members[-1]["event_id"]) if members else None
            if expected_start is not None and first_id != expected_start:
                chunk_errors.append(f"分块 {chunk['seq']} 边界不连续（应为 {expected_start}，实为 {first_id}）")
            expected_start = (last_id + 1) if last_id is not None else expected_start
            chunk_payload = {
                "schema": CHUNK_SCHEMA,
                "seq": int(chunk["seq"]),
                "start_event_id": first_id,
                "end_event_id": last_id,
                "event_count": len(members),
                "first_event_digest": members[0]["event_digest"] if members else None,
                "last_event_digest": members[-1]["event_digest"] if members else None,
                "event_entry_digest": previous_entry,
            }
            recomputed = chain_digest(previous_chunk, chunk_payload)
            if index != int(chunk["seq"]):
                chunk_errors.append(f"分块序号重排：第 {index} 块标记为 {chunk['seq']}")
            if recomputed != chunk["chunk_digest"]:
                chunk_errors.append(f"分块 {chunk['seq']} 摘要不匹配（重排/插入/删除/字段变化）")
            previous_chunk = str(chunk["chunk_digest"])
        check("chunk_chain", not chunk_errors, "；".join(chunk_errors) or "全部事件摘要与分块链连续一致")

        expected_chunks = int(snapshot["total_chunks"] or 0)
        check("chunk_count", len(chunks) == expected_chunks, f"分块数 {len(chunks)} / 登记 {expected_chunks}")
        manifest_ok = False
        if chunks:
            manifest = {
                "schema": MANIFEST_SCHEMA,
                "snapshot_code": snapshot["snapshot_code"],
                "fingerprint": snapshot["fingerprint"],
                "total_events": sum(int(c["event_count"]) for c in chunks),
                "total_chunks": len(chunks),
                "last_chunk_digest": str(chunks[-1]["chunk_digest"]),
            }
            manifest_ok = digest(manifest) == snapshot["manifest_digest"]
        check("manifest_root", manifest_ok, "清单根摘要与封存值一致")
        signature_ok = constant_time_equals(
            snapshot["manifest_signature"],
            sign(secret, snapshot["snapshot_code"], snapshot["manifest_digest"]) if snapshot["manifest_digest"] else None,
        )
        check("manifest_signature", signature_ok, "根摘要的封存签名有效（可识别整体重写）")
        check(
            "status_completed",
            snapshot["status"] == "completed",
            f"快照状态为 {snapshot['status']}" + (f"：{snapshot['failure_reason']}" if snapshot["failure_reason"] else ""),
        )

        coverage = self.repository.coverage(snapshot_id)
        return {
            "ok": not errors,
            "algorithm": ALGORITHM,
            "snapshot_id": snapshot_id,
            "snapshot_code": snapshot["snapshot_code"],
            "status": snapshot["status"],
            "fingerprint": snapshot["fingerprint"],
            "coverage": {
                "from_event_id": coverage["first_id"],
                "to_event_id": coverage["last_id"],
                "confirmed_chunks": int(coverage["chunks"] or 0),
                "confirmed_events": int(coverage["events"] or 0),
                "expected_events": int(snapshot["expected_event_count"]),
            },
            "checks": checks,
            "errors": errors,
        }

    # ---------------------------------------------------------------- 导出
    def export_bundle(self, snapshot_id: int, *, profile: str) -> dict[str, Any]:
        snapshot = self.require_snapshot(snapshot_id)
        if profile not in {"manifest", "redacted", "canonical"}:
            raise ValidationError("导出剖面只能是 manifest、redacted 或 canonical")
        chunks = self.repository.list_chunks(snapshot_id)
        stored: list[dict[str, Any]] = []
        while True:
            batch = self.repository.list_archived_events(
                snapshot_id, limit=VERIFY_EVENT_CAP, offset=len(stored)
            )
            stored.extend(batch)
            if len(batch) < VERIFY_EVENT_CAP:
                break
        events: list[dict[str, Any]] = []
        for row in sorted(stored, key=lambda item: int(item["event_id"])):
            entry = {
                "seq": row["seq"],
                "event_id": row["event_id"],
                "chunk_seq": row["chunk_seq"],
                "event_digest": row["event_digest"],
                "redacted_digest": digest(json.loads(row["redacted_json"])),
                "entry_digest": row["entry_digest"],
                "redaction_count": row["redaction_count"],
                "restricted_case": bool(row["restricted_case"]),
            }
            if profile in {"redacted", "canonical"}:
                view = json.loads(row["redacted_json"])
                entry["redacted"] = view
                entry["marks"] = list(iter_redaction_marks(view))
            if profile == "canonical":
                entry["canonical"] = json.loads(row["canonical_json"])
            events.append(entry)
        return {
            "schema": BUNDLE_SCHEMA,
            "algorithm": ALGORITHM,
            "profile": profile,
            "snapshot": {
                "snapshot_code": snapshot["snapshot_code"],
                "status": snapshot["status"],
                "fingerprint": snapshot["fingerprint"],
                "manifest_digest": snapshot["manifest_digest"],
                "manifest_signature": snapshot["manifest_signature"],
                "scope": self._load_json(snapshot["scope_json"], {}),
                "policy": self._load_json(snapshot["policy_json"], {}),
                "chunk_size": snapshot["chunk_size"],
                "start_event_id": snapshot["start_event_id"],
                "end_event_id": snapshot["end_event_id"],
                "total_events": snapshot["total_events"],
                "total_chunks": snapshot["total_chunks"],
                "frozen_at": snapshot["frozen_at"],
                "created_by": snapshot["created_by"],
            },
            "chunks": chunks,
            "events": events,
        }

    @staticmethod
    def verify_bundle(bundle: dict[str, Any], *, secret: str | None = None) -> dict[str, Any]:
        """对导出包做独立校验：不依赖数据库，只信任包内根摘要的重算结果。"""
        errors: list[str] = []
        checks: list[dict[str, Any]] = []

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
            if not ok:
                errors.append(f"{name}: {detail}")

        if bundle.get("schema") != BUNDLE_SCHEMA:
            raise ValidationError("不是受支持的归档导出包")
        header = bundle.get("snapshot") or {}
        scope, policy = header.get("scope") or {}, header.get("policy") or {}
        fingerprint_input = {
            "schema": SNAPSHOT_SCHEMA,
            "scope": scope,
            "policy": policy,
            "chunk_size": header.get("chunk_size"),
            "frozen_at": header.get("frozen_at"),
            "created_by": header.get("created_by"),
        }
        check("fingerprint", digest(fingerprint_input) == header.get("fingerprint"), "指纹与范围/策略一致")

        events = bundle.get("events") or []
        chunks = bundle.get("chunks") or []
        # 数组顺序是导出包的规范内容，受位置型连续摘要保护：必须全局按 event_id 升序。
        ordered_ids = [int(item["event_id"]) for item in events]
        if ordered_ids != sorted(ordered_ids) or len(set(ordered_ids)) != len(ordered_ids):
            errors.append("事件清单未按 event_id 严格升序（存在重排或重复标识）")
        by_seq: dict[int, list[dict[str, Any]]] = {}
        for item in events:
            by_seq.setdefault(int(item["chunk_seq"]), []).append(item)
        previous_chunk = GENESIS_DIGEST
        for index, chunk in enumerate(sorted(chunks, key=lambda c: int(c["seq"]))):
            members = by_seq.get(int(chunk["seq"]), [])
            previous_entry = GENESIS_DIGEST
            marks_ok = True
            for offset, item in enumerate(members):
                canonical = item.get("canonical")
                if canonical is not None and digest(canonical) != item["event_digest"]:
                    errors.append(f"事件 {item['event_id']} 原值摘要不匹配（字段已变化）")
                redacted = item.get("redacted")
                if redacted is not None:
                    redacted_digest = digest(redacted)
                    actual_marks = list(iter_redaction_marks(redacted))
                    if item.get("redaction_count") != len(actual_marks):
                        marks_ok = False
                    if secret is not None and canonical is not None:
                        # 持有封存密钥与原值时，可独立验证脱敏结果与每个承诺点。
                        view, _ = build_redacted_view(canonical, policy, secret=secret)
                        if canonical_json(view) != canonical_json(redacted):
                            errors.append(f"事件 {item['event_id']} 脱敏结果或承诺与策略不符")
                    for mark in actual_marks:
                        if not str(mark.get("commit") or ""):
                            marks_ok = False
                else:
                    redacted_digest = item.get("redacted_digest")
                payload = {
                    "seq": offset + 1,
                    "event_id": int(item["event_id"]),
                    "event_digest": item["event_digest"],
                    "redacted_digest": redacted_digest,
                    "redaction_count": int(item.get("redaction_count") or 0),
                }
                previous_entry = chain_digest(previous_entry, payload)
                if item.get("entry_digest") != previous_entry:
                    errors.append(f"事件 {item['event_id']} 连续摘要断裂（插入/删除/重排）")
            check(f"chunk_{chunk['seq']}_marks", marks_ok, f"分块 {chunk['seq']} 脱敏承诺齐全")
            chunk_payload = {
                "schema": CHUNK_SCHEMA,
                "seq": int(chunk["seq"]),
                "start_event_id": int(members[0]["event_id"]) if members else None,
                "end_event_id": int(members[-1]["event_id"]) if members else None,
                "event_count": len(members),
                "first_event_digest": members[0]["event_digest"] if members else None,
                "last_event_digest": members[-1]["event_digest"] if members else None,
                "event_entry_digest": previous_entry,
            }
            recomputed = chain_digest(previous_chunk, chunk_payload)
            check(
                f"chunk_{chunk['seq']}_digest",
                recomputed == chunk.get("chunk_digest"),
                f"分块 {chunk['seq']} 摘要一致",
            )
            if index != int(chunk["seq"]):
                errors.append(f"分块序号重排：位置 {index} 标记 {chunk['seq']}")
            previous_chunk = str(chunk.get("chunk_digest") or "")
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "snapshot_code": header.get("snapshot_code"),
            "fingerprint": header.get("fingerprint"),
            "total_events": len(events),
            "total_chunks": len(chunks),
            "last_chunk_digest": str(chunks[-1]["chunk_digest"]) if chunks else GENESIS_DIGEST,
        }
        check("manifest_root", digest(manifest) == header.get("manifest_digest"), "清单根摘要一致")
        if secret is not None:
            signature_ok = constant_time_equals(
                header.get("manifest_signature"),
                sign(secret, header.get("snapshot_code"), header.get("manifest_digest")),
            )
            check("manifest_signature", signature_ok, "根摘要的封存签名有效（可识别整体重写）")
        return {
            "ok": not errors,
            "algorithm": ALGORITHM,
            "snapshot_code": header.get("snapshot_code"),
            "profile": bundle.get("profile"),
            "events": len(events),
            "chunks": len(chunks),
            "checks": checks,
            "errors": errors,
            "secret_verified": secret is not None,
        }

    # ------------------------------------------------------ 回溯线上原事件
    def trace_event(self, snapshot_id: int, event_id: int, *, reveal: bool) -> dict[str, Any]:
        snapshot = self.require_snapshot(snapshot_id)
        archived = self.repository.archived_event(snapshot_id, event_id)
        if archived is None:
            raise NotFoundError("该事件不在快照范围内")
        live_row = self.repository.audit_event(event_id)
        live_digest = digest(normalize_event(live_row)) if live_row else None
        live_payload: Any = None
        if live_row is not None:
            normalized = normalize_event(live_row)
            live_payload = normalized if reveal else sanitize_payload(normalized)
        return {
            "snapshot_code": snapshot["snapshot_code"],
            "event_id": event_id,
            "archived": {
                "seq": archived["seq"],
                "chunk_seq": archived["chunk_seq"],
                "event_digest": archived["event_digest"],
                "entry_digest": archived["entry_digest"],
            },
            "live_exists": live_row is not None,
            "digest_match": live_digest == archived["event_digest"] if live_row else False,
            "live_event": live_payload,
            "read_only": True,
        }
