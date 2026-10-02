from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.archives.hasher import FORMAT_VERSION, GENESIS, chain_digest, digest_payload
from app.archives.redaction import (
    POLICIES,
    POLICY_NONE,
    POLICY_STRICT,
    ReviewAuthority,
    apply_policy,
    build_restricted_envelope,
    reveal_for_review,
    verify_envelope,
)
from app.archives.repository import ArchiveRepository
from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.services.audit import AuditContext, AuditService


@dataclass(frozen=True, slots=True)
class FreezeRequest:
    cutoff_event_id: int
    policy_code: str = POLICY_NONE
    scope_start_id: int = 1
    chunk_size: int = 200
    policy_params: dict[str, Any] | None = None
    created_by: str = "cli"


class ArchiveService:
    """冻结范围、按稳定游标分块生成连续摘要、支持恢复与独立校验。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.repository = ArchiveRepository(connection)
        self.clock = clock or SystemClock()
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 冻结

    def freeze(self, request: FreezeRequest) -> dict[str, Any]:
        if request.policy_code not in POLICIES:
            raise ValidationError(f"未知的脱敏策略：{request.policy_code}", context={"allowed": list(POLICIES)})
        if request.cutoff_event_id < 1:
            raise ValidationError("截止事件标识必须为正整数")
        if request.scope_start_id < 1:
            raise ValidationError("范围起始标识必须为正整数")
        if request.scope_start_id > request.cutoff_event_id:
            raise ValidationError("范围起始标识不能晚于截止事件标识")
        if not 1 <= request.chunk_size <= 5000:
            raise ValidationError("分块大小必须在 1 到 5000 之间")
        if not self.repository.event_exists(request.cutoff_event_id):
            raise NotFoundError("截止事件不存在", context={"cutoff_event_id": request.cutoff_event_id})

        params = request.policy_params or {}
        params_hash = digest_payload([(key, params[key]) for key in sorted(params)])
        series_key = f"audit:{request.scope_start_id}-{request.cutoff_event_id}"
        now = to_storage(self.clock.now())

        # 同一冻结范围 + 完全相同的策略/参数/分块：幂等返回既有快照，保证重复执行标识一致。
        compatible = self.repository.find_compatible(
            series_key=series_key, policy_code=request.policy_code,
            policy_params_hash=params_hash, chunk_size=request.chunk_size,
        )
        if compatible is not None:
            return compatible

        version = self.repository.latest_version(series_key) + 1
        anchor_ids = self.repository.anchor_ids(
            start_id=request.scope_start_id, end_id=request.cutoff_event_id
        )
        if not anchor_ids:
            raise ValidationError("冻结区间内没有审计事件")
        code = f"ARCH-{request.scope_start_id:08d}-{request.cutoff_event_id:08d}-V{version:03d}"
        snapshot = self.repository.create_snapshot({
            "snapshot_code": code,
            "series_key": series_key,
            "version": version,
            "scope_start_id": request.scope_start_id,
            "scope_end_id": request.cutoff_event_id,
            "cutoff_event_id": request.cutoff_event_id,
            "policy_code": request.policy_code,
            "policy_params_hash": params_hash,
            "chunk_size": request.chunk_size,
            "anchor_ids": anchor_ids,
            "anchor_count": len(anchor_ids),
            "freeze_max_event_id": self.repository.max_event_id(),
            "envelope_secret_hex": secrets.token_bytes(32).hex(),
            "created_by": request.created_by,
            "created_at": now,
            "frozen_at": now,
            "updated_at": now,
        })
        self.audit.record(
            AuditContext(None, request.created_by),
            action="audit.archive.freeze",
            resource_type="archive_snapshot",
            reagency_id=snapshot["id"],
            after={"snapshot_code": code, "version": version, "anchor_count": len(anchor_ids),
                   "policy": request.policy_code, "cutoff_event_id": request.cutoff_event_id},
        )
        return snapshot

    # ------------------------------------------------------------------ 生成

    def generate(self, snapshot_id: int, *, worker: str = "generator") -> dict[str, Any]:
        """分块生成清单，已确认分块直接跳过，可在中断或失败后恢复。

        每个分块独立提交：后续分块失败或进程中断时，已确认分块仍然落库，
        再次调用时从下一个未确认分块续跑，且摘要与首次完全一致。
        """
        snapshot = self.repository.require_snapshot(snapshot_id)
        if snapshot["status"] == "completed":
            return snapshot
        anchors = json.loads(snapshot["anchor_ids_json"])
        chunk_size = int(snapshot["chunk_size"])
        secret = bytes.fromhex(snapshot["envelope_secret_hex"])
        policy = snapshot["policy_code"]

        with _chunk_transaction(self.connection):
            self.repository.lock_for_generation(snapshot_id, worker, to_storage(self.clock.now()))

        total = len(anchors)
        seq = 1
        offset = 0
        while offset < total:
            block = anchors[offset:offset + chunk_size]
            self._generate_chunk(snapshot, seq, block, secret=secret, policy=policy)
            offset += chunk_size
            seq += 1

        return self._finalize(snapshot_id, anchors=anchors)

    def _generate_chunk(
        self, snapshot: dict[str, Any], seq: int, block: list[int], *,
        secret: bytes, policy: str,
    ) -> None:
        snapshot_id = int(snapshot["id"])
        existing = self.repository.get_chunk_by_seq(snapshot_id, seq)
        if existing is not None and existing["status"] == "confirmed":
            return  # 已确认分块不重算，续跑结果与首次一致

        if seq > 1:
            previous_chunk = self.repository.get_chunk_by_seq(snapshot_id, seq - 1)
            if previous_chunk is None or previous_chunk["status"] != "confirmed":
                raise ConflictError(f"分块 {seq - 1} 尚未确认，无法生成分块 {seq}")
        prev_chunk_digest = (
            previous_chunk["chunk_digest"] if seq > 1 and previous_chunk is not None else GENESIS
        )

        chunk_id: int | None = None
        try:
            with _chunk_transaction(self.connection):
                now = to_storage(self.clock.now())
                chunk_id = self.repository.ensure_chunk(
                    snapshot_id, seq, start_event_id=block[0], created_at=now
                )
                current = self.repository.get_chunk(chunk_id)
                if current is not None and current["status"] in {"pending", "failed"}:
                    self.repository.reset_chunk_events(chunk_id)

                first_digest = last_digest = None
                running_event_digest = prev_chunk_digest
                position = 0
                for event_id in block:
                    event = self.repository.get_event(event_id)
                    if event is None:
                        raise RuntimeError(f"冻结锚点事件 {event_id} 在审计库中已不存在，无法生成完整清单")
                    normalized = ArchiveRepository.canonical_event(event)
                    event_digest = digest_payload(normalized)
                    if policy == POLICY_STRICT and self.repository.is_restricted_event(event):
                        redacted = self._wrap_restricted(normalized, secret)
                    else:
                        redacted = apply_policy(normalized, policy, secret)
                    body_digest = digest_payload(redacted)
                    running_event_digest = chain_digest(running_event_digest, {
                        "position": position,
                        "audit_event_id": event_id,
                        "event_digest": event_digest,
                        "body_digest": body_digest,
                    })
                    self.repository.insert_chunk_event(
                        chunk_id, position, event_id, event_digest, redacted,
                        restricted=bool(redacted.get("_restricted")) if isinstance(redacted, dict) else False,
                    )
                    first_digest = first_digest or event_digest
                    last_digest = event_digest
                    position += 1

                chunk_digest = chain_digest(running_event_digest, {
                    "seq": seq,
                    "start_event_id": block[0],
                    "end_event_id": block[-1],
                    "event_count": len(block),
                })
                self.repository.confirm_chunk(
                    chunk_id,
                    end_event_id=block[-1],
                    event_count=len(block),
                    first_event_digest=first_digest,
                    last_event_digest=last_digest,
                    prev_chunk_digest=prev_chunk_digest,
                    chunk_digest=chunk_digest,
                    now=to_storage(self.clock.now()),
                )
        except Exception as exc:  # noqa: BLE001 - 失败原因独立落库，供运维与 API 展示
            reason = f"分块 {seq} 生成失败：{exc}"
            with _chunk_transaction(self.connection):
                now = to_storage(self.clock.now())
                if chunk_id is not None:
                    self.repository.fail_chunk(chunk_id, reason, now)
                self.repository.mark_snapshot_failed(snapshot_id, reason, now)
            raise ConflictError(reason) from exc

    def _finalize(self, snapshot_id: int, *, anchors: list[int]) -> dict[str, Any]:
        with _chunk_transaction(self.connection):
            chunks = self.repository.list_chunks(snapshot_id)
            if any(chunk["status"] != "confirmed" for chunk in chunks):
                reason = "仍有分块未确认，快照未完成"
                self.repository.mark_snapshot_failed(snapshot_id, reason, to_storage(self.clock.now()))
                raise ConflictError(reason)
            confirmed_ids = [int(row["audit_event_id"]) for chunk in chunks
                             for row in self.repository.list_chunk_events(int(chunk["id"]))]
            if confirmed_ids != anchors:
                reason = "分块覆盖区间与冻结锚点不一致"
                self.repository.mark_snapshot_failed(snapshot_id, reason, to_storage(self.clock.now()))
                raise ConflictError(reason)
            manifest_hash = self._compute_manifest(chunks)
            first_digest = chunks[0]["first_event_digest"]
            last_digest = chunks[-1]["last_event_digest"]
            self.repository.mark_snapshot_completed(
                snapshot_id,
                manifest_hash=manifest_hash,
                first_event_digest=first_digest,
                last_event_digest=last_digest,
                now=to_storage(self.clock.now()),
            )
            completed = self.repository.require_snapshot(snapshot_id)
            self.audit.record(
                AuditContext(None, completed["created_by"]),
                action="audit.archive.complete",
                resource_type="archive_snapshot",
                reagency_id=snapshot_id,
                after={"snapshot_code": completed["snapshot_code"], "manifest_hash": manifest_hash,
                       "anchor_count": completed["anchor_count"]},
            )
        return completed

    def _compute_manifest(self, chunks: list[dict[str, Any]]) -> str:
        snapshot = self.repository.require_snapshot(int(chunks[0]["snapshot_id"]))
        digest = GENESIS
        digest = chain_digest(digest, {
            "format": FORMAT_VERSION,
            "scope_start_id": snapshot["scope_start_id"],
            "scope_end_id": snapshot["scope_end_id"],
            "cutoff_event_id": snapshot["cutoff_event_id"],
            "policy_code": snapshot["policy_code"],
            "policy_params_hash": snapshot["policy_params_hash"],
            "chunk_size": snapshot["chunk_size"],
            "anchor_count": snapshot["anchor_count"],
            "freeze_max_event_id": snapshot["freeze_max_event_id"],
        })
        for chunk in chunks:
            digest = chain_digest(digest, {
                "seq": chunk["seq"],
                "start_event_id": chunk["start_event_id"],
                "end_event_id": chunk["end_event_id"],
                "event_count": chunk["event_count"],
                "prev_chunk_digest": chunk["prev_chunk_digest"],
                "chunk_digest": chunk["chunk_digest"],
            })
        return digest

    @staticmethod
    def _wrap_restricted(normalized: dict[str, Any], secret: bytes) -> dict[str, Any]:
        return {
            "_restricted": True,
            "audit_event_id": normalized["id"],
            "summary": build_restricted_envelope(normalized, secret),
        }

    # ------------------------------------------------------------------ 查询

    @staticmethod
    def public_view(snapshot: dict[str, Any]) -> dict[str, Any]:
        """对外序列化：绝不暴露脱敏信封密钥。"""
        view = dict(snapshot)
        view.pop("envelope_secret_hex", None)
        view.pop("anchor_ids_json", None)
        return view

    def get(self, snapshot_id: int) -> dict[str, Any]:
        return self.repository.require_snapshot(snapshot_id)

    def get_by_code(self, code: str) -> dict[str, Any]:
        snapshot = self.repository.get_by_code(code)
        if snapshot is None:
            raise NotFoundError("归档快照不存在", context={"code": code})
        return snapshot

    def progress(self, snapshot_id: int) -> dict[str, Any]:
        snapshot = self.repository.require_snapshot(snapshot_id)
        chunks = self.repository.list_chunks(snapshot_id)
        anchor_count = int(snapshot["anchor_count"])
        confirmed_events = self.repository.count_confirmed_events(snapshot_id)
        confirmed_chunks = sum(1 for chunk in chunks if chunk["status"] == "confirmed")
        failed = next((chunk for chunk in chunks if chunk["status"] == "failed"), None)
        coverage: list[dict[str, Any]] = [
            {"seq": chunk["seq"], "status": chunk["status"],
             "start_event_id": chunk["start_event_id"], "end_event_id": chunk["end_event_id"],
             "event_count": chunk["event_count"],
             "failure_reason": chunk["failure_reason"]}
            for chunk in chunks
        ]
        return {
            "snapshot_id": snapshot_id,
            "snapshot_code": snapshot["snapshot_code"],
            "version": snapshot["version"],
            "status": snapshot["status"],
            "policy_code": snapshot["policy_code"],
            "scope": {"start_event_id": snapshot["scope_start_id"], "end_event_id": snapshot["scope_end_id"]},
            "cutoff_event_id": snapshot["cutoff_event_id"],
            "anchor_count": anchor_count,
            "chunk_size": int(snapshot["chunk_size"]),
            "total_chunks": (anchor_count + int(snapshot["chunk_size"]) - 1) // int(snapshot["chunk_size"]),
            "confirmed_chunks": confirmed_chunks,
            "confirmed_events": confirmed_events,
            "percent": round(confirmed_events * 100 / anchor_count, 2) if anchor_count else 0.0,
            "manifest_hash": snapshot["manifest_hash"],
            "failure_reason": snapshot["failure_reason"] or (failed["failure_reason"] if failed else None),
            "frozen_at": snapshot["frozen_at"],
            "completed_at": snapshot["completed_at"],
            "chunks": coverage,
        }

    def chunk_events(self, snapshot_id: int, seq: int, *, authority: ReviewAuthority | None = None,
                     reveal: bool = False) -> dict[str, Any]:
        snapshot = self.repository.require_snapshot(snapshot_id)
        chunk = self.repository.get_chunk_by_seq(snapshot_id, seq)
        if chunk is None:
            raise NotFoundError("分块不存在", context={"seq": seq})
        events: list[dict[str, Any]] = []
        for row in self.repository.list_chunk_events(int(chunk["id"])):
            body = json.loads(row["redacted_json"])
            if reveal and authority is not None:
                body = reveal_for_review(body, authority)
            events.append({
                "position": row["position"],
                "audit_event_id": row["audit_event_id"],
                "event_digest": row["event_digest"],
                "is_restricted": bool(row["is_restricted"]),
                "body": body,
            })
        return {
            "snapshot_code": snapshot["snapshot_code"],
            "seq": seq,
            "chunk_digest": chunk["chunk_digest"],
            "prev_chunk_digest": chunk["prev_chunk_digest"],
            "events": events,
        }

    def provenance(self, snapshot_id: int, audit_event_id: int, *, can_review: bool) -> dict[str, Any]:
        """从归档事件追溯到线上原审计事件，不修改任何业务状态。"""
        snapshot = self.repository.require_snapshot(snapshot_id)
        located = self.connection.execute(
            "SELECT ce.*, c.seq FROM archive_chunk_events ce "
            "JOIN archive_chunks c ON c.id=ce.chunk_id "
            "WHERE c.snapshot_id=? AND ce.audit_event_id=?",
            (snapshot_id, audit_event_id),
        ).fetchall()
        if not located:
            raise NotFoundError("该审计事件不在此快照覆盖区间内", context={"audit_event_id": audit_event_id})
        record = dict(located[0])
        live = self.repository.get_event(audit_event_id)
        result: dict[str, Any] = {
            "snapshot_code": snapshot["snapshot_code"],
            "seq": record["seq"],
            "position": record["position"],
            "audit_event_id": audit_event_id,
            "archived_event_digest": record["event_digest"],
            "live_event_present": live is not None,
        }
        if live is not None:
            live_digest = digest_payload(ArchiveRepository.canonical_event(live))
            result["live_event_digest"] = live_digest
            result["unchanged"] = live_digest == record["event_digest"]
            if can_review:
                result["original_event"] = ArchiveRepository.canonical_event(live)
        return result

    # ------------------------------------------------------------------ 校验

    def verify_snapshot(self, snapshot_id: int, *, deep: bool = False) -> dict[str, Any]:
        """独立重算全部摘要并报告覆盖区间；deep 时回溯线上原值比对。"""
        snapshot = self.repository.require_snapshot(snapshot_id)
        anchors = json.loads(snapshot["anchor_ids_json"])
        chunks = self.repository.list_chunks(snapshot_id)
        problems: list[str] = []

        expected_seq = 1
        prev_digest = GENESIS
        event_index = 0
        running = GENESIS
        running = chain_digest(running, {
            "format": FORMAT_VERSION,
            "scope_start_id": snapshot["scope_start_id"],
            "scope_end_id": snapshot["scope_end_id"],
            "cutoff_event_id": snapshot["cutoff_event_id"],
            "policy_code": snapshot["policy_code"],
            "policy_params_hash": snapshot["policy_params_hash"],
            "chunk_size": snapshot["chunk_size"],
            "anchor_count": snapshot["anchor_count"],
            "freeze_max_event_id": snapshot["freeze_max_event_id"],
        })

        for chunk in chunks:
            seq = int(chunk["seq"])
            if seq != expected_seq:
                problems.append(f"分块序号不连续：期望 {expected_seq}，实际 {seq}")
            if chunk["prev_chunk_digest"] != prev_digest:
                problems.append(f"分块 {seq} 的前序摘要与上一块不匹配")
            rows = self.repository.list_chunk_events(int(chunk["id"]))
            if not rows:
                problems.append(f"分块 {seq} 没有任何事件")
                expected_seq += 1
                continue
            derived_start = int(rows[0]["audit_event_id"])
            derived_end = int(rows[-1]["audit_event_id"])
            derived_count = len(rows)
            if derived_start != int(chunk["start_event_id"]):
                problems.append(f"分块 {seq} 登记起始事件 {chunk['start_event_id']} 与清单 {derived_start} 不一致")
            if derived_end != int(chunk["end_event_id"]):
                problems.append(f"分块 {seq} 登记截止事件 {chunk['end_event_id']} 与清单 {derived_end} 不一致")
            if derived_count != int(chunk["event_count"]):
                problems.append(f"分块 {seq} 事件数 {derived_count} 与登记 {chunk['event_count']} 不一致")
            chain_running = prev_digest
            first_digest = last_digest = None
            for position, row in enumerate(rows):
                if int(row["position"]) != position:
                    problems.append(f"分块 {seq} 位置 {position} 重排或缺失")
                expected_event_id = anchors[event_index] if event_index < len(anchors) else None
                if int(row["audit_event_id"]) != expected_event_id:
                    problems.append(
                        f"分块 {seq} 位置 {position} 事件标识 {row['audit_event_id']} 与锚点 {expected_event_id} 不一致"
                    )
                body = json.loads(row["redacted_json"])
                body_digest = digest_payload(body)
                chain_running = chain_digest(chain_running, {
                    "position": position,
                    "audit_event_id": int(row["audit_event_id"]),
                    "event_digest": row["event_digest"],
                    "body_digest": body_digest,
                })
                if deep:
                    live = self.repository.get_event(int(row["audit_event_id"]))
                    if live is None:
                        problems.append(f"事件 {row['audit_event_id']} 已从审计库删除")
                    else:
                        live_digest = digest_payload(ArchiveRepository.canonical_event(live))
                        if live_digest != row["event_digest"]:
                            problems.append(f"事件 {row['audit_event_id']} 原审计字段已变化")
                first_digest = first_digest or row["event_digest"]
                last_digest = row["event_digest"]
                event_index += 1
            chunk_digest = chain_digest(chain_running, {
                "seq": seq,
                "start_event_id": derived_start,
                "end_event_id": derived_end,
                "event_count": derived_count,
            })
            if chunk_digest != chunk["chunk_digest"]:
                problems.append(f"分块 {seq} 摘要重算不一致")
            if first_digest != chunk["first_event_digest"] or last_digest != chunk["last_event_digest"]:
                problems.append(f"分块 {seq} 首尾事件摘要登记有误")
            running = chain_digest(running, {
                "seq": seq,
                "start_event_id": derived_start,
                "end_event_id": derived_end,
                "event_count": derived_count,
                "prev_chunk_digest": chunk["prev_chunk_digest"],
                "chunk_digest": chunk["chunk_digest"],
            })
            prev_digest = chunk["chunk_digest"]
            expected_seq += 1

        if event_index != len(anchors):
            problems.append(f"已归档事件数 {event_index} 与冻结锚点数 {len(anchors)} 不一致")

        manifest_ok = running == snapshot["manifest_hash"]
        if not manifest_ok:
            problems.append("清单根摘要重算不一致，快照头或分块链被改动")
        if snapshot["status"] != "completed":
            problems.append(f"快照状态为 {snapshot['status']}，并非完成态")

        # 冻结后线上审计库相对锚点的漂移（只报告，不改动）。
        current_ids = set(self.repository.anchor_ids(
            start_id=int(snapshot["scope_start_id"]), end_id=int(snapshot["scope_end_id"])
        ))
        missing_from_live = [event_id for event_id in anchors if event_id not in current_ids]
        if missing_from_live:
            problems.append("冻结锚点事件已从线上删除：" + ",".join(map(str, missing_from_live[:20])))

        return {
            "snapshot_id": snapshot_id,
            "snapshot_code": snapshot["snapshot_code"],
            "status": snapshot["status"],
            "valid": not problems,
            "deep": deep,
            "manifest_hash": snapshot["manifest_hash"],
            "manifest_recomputed": running,
            "events_verified": event_index,
            "anchor_count": len(anchors),
            "chunks_verified": len(chunks),
            "missing_from_live": missing_from_live,
            "problems": problems,
        }

    def verify_value(self, snapshot_id: int, audit_event_id: int, *, path: str, original: Any) -> dict[str, Any]:
        """有权复核者提交原值与路径，验证其与脱敏信封一致。"""
        snapshot = self.repository.require_snapshot(snapshot_id)
        secret = bytes.fromhex(snapshot["envelope_secret_hex"])
        row = self.connection.execute(
            "SELECT redacted_json FROM archive_chunk_events ce JOIN archive_chunks c ON c.id=ce.chunk_id "
            "WHERE c.snapshot_id=? AND ce.audit_event_id=?",
            (snapshot_id, audit_event_id),
        ).fetchone()
        if row is None:
            raise NotFoundError("该审计事件不在此快照内")
        body = json.loads(row["redacted_json"])
        envelope = _walk_path(body, path)
        if not isinstance(envelope, dict) or "_redacted" not in envelope:
            raise ValidationError("指定路径不是脱敏信封")
        matched = verify_envelope(envelope, str(envelope["category"]), original, secret)
        return {
            "snapshot_code": snapshot["snapshot_code"],
            "audit_event_id": audit_event_id,
            "path": path,
            "category": envelope["category"],
            "masked": envelope["masked"],
            "verified": matched,
        }

    # ------------------------------------------------------------------ 导出

    def export_bundle(self, snapshot_id: int) -> dict[str, Any]:
        snapshot = self.repository.require_snapshot(snapshot_id)
        if snapshot["status"] != "completed":
            raise ConflictError("只有完成态快照可以导出归档包")
        chunks = [self.chunk_events(snapshot_id, int(chunk["seq"]))
                  for chunk in self.repository.list_chunks(snapshot_id)]
        return {
            "format": FORMAT_VERSION,
            "snapshot": {
                "code": snapshot["snapshot_code"],
                "version": snapshot["version"],
                "series_key": snapshot["series_key"],
                "policy_code": snapshot["policy_code"],
                "policy_params_hash": snapshot["policy_params_hash"],
                "scope_start_id": snapshot["scope_start_id"],
                "scope_end_id": snapshot["scope_end_id"],
                "cutoff_event_id": snapshot["cutoff_event_id"],
                "chunk_size": snapshot["chunk_size"],
                "anchor_count": snapshot["anchor_count"],
                "anchor_ids": json.loads(snapshot["anchor_ids_json"]),
                "freeze_max_event_id": snapshot["freeze_max_event_id"],
                "frozen_at": snapshot["frozen_at"],
                "completed_at": snapshot["completed_at"],
            },
            "manifest_hash": snapshot["manifest_hash"],
            "chunks": chunks,
        }

    @staticmethod
    def verify_bundle(bundle: dict[str, Any], *, expected_manifest_hash: str | None = None) -> dict[str, Any]:
        """离线独立校验导出包：无需数据库或密钥即可发现删除、插入、重排、字段变化。

        篡改者若重新计算整条链，其新根摘要必然与可信渠道（API/运维打印并留档的
        manifest_hash）不同。传入 expected_manifest_hash 即可连这种整体重算一并识破。
        """
        problems: list[str] = []
        try:
            header = bundle["snapshot"]
            anchors = list(header["anchor_ids"])
            chunks = list(bundle["chunks"])
        except (KeyError, TypeError) as exc:
            return {"valid": False, "problems": [f"归档包结构损坏：{exc}"], "events_verified": 0}

        running = GENESIS
        running = chain_digest(running, {
            "format": bundle.get("format", FORMAT_VERSION),
            "scope_start_id": header["scope_start_id"],
            "scope_end_id": header["scope_end_id"],
            "cutoff_event_id": header["cutoff_event_id"],
            "policy_code": header["policy_code"],
            "policy_params_hash": header["policy_params_hash"],
            "chunk_size": header["chunk_size"],
            "anchor_count": header["anchor_count"],
            "freeze_max_event_id": header["freeze_max_event_id"],
        })

        prev_digest = GENESIS
        expected_seq = 1
        event_index = 0
        for chunk in chunks:
            seq = int(chunk["seq"])
            events = chunk["events"]
            if seq != expected_seq:
                problems.append(f"分块序号不连续：期望 {expected_seq}，实际 {seq}")
            if chunk["prev_chunk_digest"] != prev_digest:
                problems.append(f"分块 {seq} 的前序摘要链接断裂")
            chain_running = prev_digest
            derived_ids: list[int] = []
            for position, event in enumerate(events):
                if int(event["position"]) != position:
                    problems.append(f"分块 {seq} 位置 {position} 重排或缺失")
                event_id = int(event["audit_event_id"])
                derived_ids.append(event_id)
                expected_id = anchors[event_index] if event_index < len(anchors) else None
                if event_id != expected_id:
                    problems.append(f"分块 {seq} 位置 {position} 事件 {event_id} 与锚点 {expected_id} 不一致")
                # event_digest 是原值摘要；body 是脱敏文本。两者都纳入连续摘要。
                chain_running = chain_digest(chain_running, {
                    "position": position,
                    "audit_event_id": event_id,
                    "event_digest": event["event_digest"],
                    "body_digest": digest_payload(event["body"]),
                })
                event_index += 1
            if not derived_ids:
                problems.append(f"分块 {seq} 为空")
                expected_seq += 1
                continue
            chunk_digest = chain_digest(chain_running, {
                "seq": seq,
                "start_event_id": derived_ids[0],
                "end_event_id": derived_ids[-1],
                "event_count": len(derived_ids),
            })
            if chunk_digest != chunk["chunk_digest"]:
                problems.append(f"分块 {seq} 摘要重算不一致")
            running = chain_digest(running, {
                "seq": seq,
                "start_event_id": derived_ids[0],
                "end_event_id": derived_ids[-1],
                "event_count": len(derived_ids),
                "prev_chunk_digest": chunk["prev_chunk_digest"],
                "chunk_digest": chunk["chunk_digest"],
            })
            prev_digest = chunk["chunk_digest"]
            expected_seq += 1

        flattened = [int(e["audit_event_id"]) for ch in chunks for e in ch["events"]]
        if flattened != anchors:
            problems.append("清单事件序列与冻结锚点序列不一致")
        if event_index != int(header["anchor_count"]):
            problems.append(f"事件数 {event_index} 与锚点数 {header['anchor_count']} 不一致")
        if running != bundle.get("manifest_hash"):
            problems.append("清单根摘要不一致：归档包头或分块被改动")
        if expected_manifest_hash is not None and running != expected_manifest_hash:
            problems.append("根摘要与可信留档不一致：归档包可能被整体替换或重算")
        return {
            "valid": not problems,
            "snapshot_code": header.get("code"),
            "events_verified": event_index,
            "chunks_verified": len(chunks),
            "manifest_hash": bundle.get("manifest_hash"),
            "manifest_recomputed": running,
            "root_matches_record": (
                expected_manifest_hash is None or running == expected_manifest_hash
            ),
            "problems": problems,
        }


def _walk_path(body: Any, path: str) -> Any:
    current = body
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ValidationError(f"脱敏路径不存在：{path}")
    return current


class _chunk_transaction:
    """每个分块独立提交；连接已在事务中时用保存点，保证中断只丢当前块。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.nested = connection.in_transaction

    def __enter__(self) -> sqlite3.Connection:
        if self.nested:
            self.marker = f"chunk_{id(self)}"
            self.connection.execute(f"SAVEPOINT {self.marker}")
        else:
            self.connection.execute("BEGIN IMMEDIATE")
        return self.connection

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            if self.nested:
                self.connection.execute(f"RELEASE SAVEPOINT {self.marker}")
            else:
                self.connection.commit()
        else:
            if self.nested:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {self.marker}")
                self.connection.execute(f"RELEASE SAVEPOINT {self.marker}")
            else:
                self.connection.rollback()
