from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.archives.hasher import canonical_json
from app.repositories.base import rows_dict

# 规范化快照事件时固定的字段顺序与取值（取自 audit_events，绝不把派生数据混入摘要）。
EVENT_FIELDS = (
    "id", "actor_user_id", "actor_name", "action", "resource_type", "reagency_id",
    "outcome", "before_json", "after_json", "metadata_json", "correlation_id", "created_at",
)


class ArchiveRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    # ---- 审计事件读取（稳定游标：主键 id 升序，无偏移） ----

    def max_event_id(self) -> int:
        return int(self.connection.execute("SELECT COALESCE(MAX(id),0) FROM audit_events").fetchone()[0])

    def event_exists(self, event_id: int) -> bool:
        return self.connection.execute("SELECT 1 FROM audit_events WHERE id=?", (event_id,)).fetchone() is not None

    def fetch_events(self, *, start_id: int, end_id: int, after_id: int, limit: int) -> list[dict[str, Any]]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM audit_events WHERE id BETWEEN ? AND ? AND id>? ORDER BY id ASC LIMIT ?",
            (start_id, end_id, after_id, limit),
        ).fetchall())

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone()
        return dict(row) if row is not None else None

    def anchor_ids(self, *, start_id: int, end_id: int) -> list[int]:
        rows = self.connection.execute(
            "SELECT id FROM audit_events WHERE id BETWEEN ? AND ? ORDER BY id ASC", (start_id, end_id)
        ).fetchall()
        return [int(row[0]) for row in rows]

    def is_restricted_event(self, event: dict[str, Any]) -> bool:
        """受限案件：事件关联的案件当前处于 restricted 状态。"""
        resource_type = str(event.get("resource_type") or "")
        reagency = event.get("reagency_id")
        if resource_type != "forensic_case" or reagency is None:
            return False
        try:
            case_id = int(reagency)
        except (TypeError, ValueError):
            return False
        row = self.connection.execute(
            "SELECT status FROM forensic_cases WHERE id=?", (case_id,)
        ).fetchone()
        return row is not None and str(row["status"]) == "restricted"

    # ---- 规范化 ----

    @staticmethod
    def canonical_event(event: dict[str, Any]) -> dict[str, Any]:
        """把审计行规范化为稳定对象：JSON 列解析回对象，键集合固定。"""
        normalized: dict[str, Any] = {}
        for field in EVENT_FIELDS:
            value = event.get(field)
            if field.endswith("_json"):
                normalized[field[:-5]] = (
                    json.loads(value) if value is not None else ({} if field == "metadata_json" else None)
                )
            else:
                normalized[field] = value
        return normalized

    # ---- 快照 ----

    def create_snapshot(self, values: dict[str, Any]) -> dict[str, Any]:
        try:
            cursor = self.connection.execute(
                "INSERT INTO archive_snapshots(snapshot_code,series_key,version,scope_start_id,scope_end_id,"
                "cutoff_event_id,policy_code,policy_params_hash,chunk_size,status,anchor_ids_json,anchor_count,"
                "freeze_max_event_id,envelope_secret_hex,created_by,created_at,frozen_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'frozen',?,?,?,?,?,?,?,?)",
                (
                    values["snapshot_code"], values["series_key"], values["version"],
                    values["scope_start_id"], values["scope_end_id"], values["cutoff_event_id"],
                    values["policy_code"], values["policy_params_hash"], values["chunk_size"],
                    json.dumps(values["anchor_ids"], separators=(",", ":")), values["anchor_count"],
                    values["freeze_max_event_id"], values["envelope_secret_hex"],
                    values["created_by"], values["created_at"], values["frozen_at"], values["updated_at"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            from app.core.errors import ConflictError

            raise ConflictError("同一范围的归档版本并发冲突，请重试") from exc
        return self.require_snapshot(int(cursor.lastrowid))

    def require_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM archive_snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if row is None:
            from app.core.errors import NotFoundError

            raise NotFoundError("归档快照不存在")
        return dict(row)

    def find_snapshot(self, *, series_key: str, version: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM archive_snapshots WHERE series_key=? AND version=?", (series_key, version)
        ).fetchone()
        return dict(row) if row is not None else None

    def get_by_code(self, code: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM archive_snapshots WHERE snapshot_code=?", (code,)).fetchone()
        return dict(row) if row is not None else None

    def list_snapshots(self, *, status: str | None, limit: int, offset: int) -> list[dict[str, Any]]:
        if status:
            rows = self.connection.execute(
                "SELECT * FROM archive_snapshots WHERE status=? ORDER BY id DESC LIMIT ? OFFSET ?",
                (status, limit, offset),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM archive_snapshots ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return rows_dict(rows)

    def count_snapshots(self, status: str | None = None) -> int:
        if status:
            return int(self.connection.execute(
                "SELECT COUNT(*) FROM archive_snapshots WHERE status=?", (status,)
            ).fetchone()[0])
        return int(self.connection.execute("SELECT COUNT(*) FROM archive_snapshots").fetchone()[0])

    def latest_version(self, series_key: str) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(version),0) FROM archive_snapshots WHERE series_key=?", (series_key,)
        ).fetchone()
        return int(row[0])

    def find_compatible(
        self, *, series_key: str, policy_code: str, policy_params_hash: str, chunk_size: int
    ) -> dict[str, Any] | None:
        """同范围 + 同策略 + 同参数 + 同分块大小的既有快照（冻结幂等的依据）。"""
        row = self.connection.execute(
            "SELECT * FROM archive_snapshots WHERE series_key=? AND policy_code=? "
            "AND policy_params_hash=? AND chunk_size=? ORDER BY version DESC LIMIT 1",
            (series_key, policy_code, policy_params_hash, chunk_size),
        ).fetchone()
        return dict(row) if row is not None else None

    def lock_for_generation(self, snapshot_id: int, worker: str, now: str) -> bool:
        cursor = self.connection.execute(
            "UPDATE archive_snapshots SET status='generating',locked_at=?,locked_by=?,failure_reason=NULL,updated_at=? "
            "WHERE id=? AND status IN ('frozen','failed','generating')",
            (now, now, worker, snapshot_id),
        )
        return cursor.rowcount == 1

    def touch_snapshot(self, snapshot_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE archive_snapshots SET updated_at=? WHERE id=?", (now, snapshot_id)
        )

    def mark_snapshot_failed(self, snapshot_id: int, reason: str, now: str) -> None:
        self.connection.execute(
            "UPDATE archive_snapshots SET status='failed',failure_reason=?,updated_at=? WHERE id=?",
            (reason[:2000], now, snapshot_id),
        )

    def mark_snapshot_completed(
        self, snapshot_id: int, *, manifest_hash: str, first_event_digest: str, last_event_digest: str, now: str
    ) -> None:
        self.connection.execute(
            "UPDATE archive_snapshots SET status='completed',manifest_hash=?,first_event_digest=?,last_event_digest=?,"
            "confirmed_chunks=(SELECT COUNT(*) FROM archive_chunks WHERE snapshot_id=? AND status='confirmed'),"
            "confirmed_events=(SELECT COALESCE(SUM(event_count),0) FROM archive_chunks "
            "WHERE snapshot_id=? AND status='confirmed'),"
            "failure_reason=NULL,completed_at=?,updated_at=? WHERE id=?",
            (manifest_hash, first_event_digest, last_event_digest, snapshot_id, snapshot_id, now, now, snapshot_id),
        )

    # ---- 分块 ----

    def ensure_chunk(self, snapshot_id: int, seq: int, *, start_event_id: int, created_at: str) -> int:
        self.connection.execute(
            "INSERT INTO archive_chunks(snapshot_id,seq,start_event_id,end_event_id,event_count,"
            "prev_chunk_digest,status,created_at,updated_at) "
            "VALUES(?,?,?,? ,0,?,'pending',?,?) "
            "ON CONFLICT(snapshot_id,seq) DO NOTHING",
            (snapshot_id, seq, start_event_id, start_event_id, _prev_digest_for(self.connection, snapshot_id, seq),
             created_at, created_at),
        )
        row = self.connection.execute(
            "SELECT id FROM archive_chunks WHERE snapshot_id=? AND seq=?", (snapshot_id, seq)
        ).fetchone()
        return int(row[0])

    def get_chunk(self, chunk_id: int) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM archive_chunks WHERE id=?", (chunk_id,)).fetchone()
        return dict(row) if row is not None else None

    def get_chunk_by_seq(self, snapshot_id: int, seq: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM archive_chunks WHERE snapshot_id=? AND seq=?", (snapshot_id, seq)
        ).fetchone()
        return dict(row) if row is not None else None

    def list_chunks(self, snapshot_id: int) -> list[dict[str, Any]]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM archive_chunks WHERE snapshot_id=? ORDER BY seq ASC", (snapshot_id,)
        ).fetchall())

    def last_confirmed_chunk(self, snapshot_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM archive_chunks WHERE snapshot_id=? AND status='confirmed' ORDER BY seq DESC LIMIT 1",
            (snapshot_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def pending_chunks_exist(self, snapshot_id: int) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM archive_chunks WHERE snapshot_id=? AND status!='confirmed' LIMIT 1", (snapshot_id,)
        ).fetchone() is not None

    def insert_chunk_event(
        self, chunk_id: int, position: int, audit_event_id: int, event_digest: str,
        redacted: Any, restricted: bool,
    ) -> None:
        self.connection.execute(
            "INSERT INTO archive_chunk_events(chunk_id,position,audit_event_id,event_digest,redacted_json,is_restricted) "
            "VALUES(?,?,?,?,?,?)",
            (chunk_id, position, audit_event_id, event_digest,
             json.dumps(redacted, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
             1 if restricted else 0),
        )

    def list_chunk_events(self, chunk_id: int) -> list[dict[str, Any]]:
        return rows_dict(self.connection.execute(
            "SELECT * FROM archive_chunk_events WHERE chunk_id=? ORDER BY position ASC", (chunk_id,)
        ).fetchall())

    def confirm_chunk(
        self, chunk_id: int, *, end_event_id: int, event_count: int, first_event_digest: str,
        last_event_digest: str, prev_chunk_digest: str, chunk_digest: str, now: str,
    ) -> None:
        self.connection.execute(
            "UPDATE archive_chunks SET end_event_id=?,event_count=?,first_event_digest=?,last_event_digest=?,"
            "prev_chunk_digest=?,chunk_digest=?,status='confirmed',failure_reason=NULL,updated_at=? WHERE id=?",
            (end_event_id, event_count, first_event_digest, last_event_digest,
             prev_chunk_digest, chunk_digest, now, chunk_id),
        )

    def fail_chunk(self, chunk_id: int, reason: str, now: str) -> None:
        self.connection.execute(
            "UPDATE archive_chunks SET status='failed',failure_reason=?,updated_at=? WHERE id=?",
            (reason[:2000], now, chunk_id),
        )

    def count_confirmed_events(self, snapshot_id: int) -> int:
        return int(self.connection.execute(
            "SELECT COALESCE(SUM(event_count),0) FROM archive_chunks WHERE snapshot_id=? AND status='confirmed'",
            (snapshot_id,),
        ).fetchone()[0])

    def count_confirmed_chunks(self, snapshot_id: int) -> int:
        return int(self.connection.execute(
            "SELECT COUNT(*) FROM archive_chunks WHERE snapshot_id=? AND status='confirmed'", (snapshot_id,)
        ).fetchone()[0])

    def reset_chunk_events(self, chunk_id: int) -> None:
        """失败分块重跑前清空其事件，保留分块行以便续跑。"""
        self.connection.execute("DELETE FROM archive_chunk_events WHERE chunk_id=?", (chunk_id,))
        self.connection.execute(
            "UPDATE archive_chunks SET status='pending',failure_reason=NULL,"
            "event_count=0,first_event_digest=NULL,last_event_digest=NULL,chunk_digest=NULL WHERE id=?",
            (chunk_id,),
        )

    @staticmethod
    def redacted_bytes(row: dict[str, Any]) -> bytes:
        return canonical_json(json.loads(row["redacted_json"]))


def _prev_digest_for(connection: sqlite3.Connection, snapshot_id: int, seq: int) -> str:
    from app.archives.hasher import GENESIS

    if seq <= 1:
        return GENESIS
    row = connection.execute(
        "SELECT chunk_digest FROM archive_chunks WHERE snapshot_id=? AND seq=?", (snapshot_id, seq - 1)
    ).fetchone()
    return str(row["chunk_digest"]) if row is not None and row["chunk_digest"] else GENESIS
