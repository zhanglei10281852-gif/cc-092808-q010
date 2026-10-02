"""归档快照的持久化访问：快照、分块、事件清单与封存密钥。"""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any, Iterable

from app.repositories.base import rows_dict

ARCHIVE_SECRET_NAME = "audit_archive_hmac_v1"


class ArchiveRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    # ---- 封存密钥（仅用于脱敏承诺，不参与公开指纹）----
    def archive_secret(self, now: str) -> str:
        row = self.connection.execute(
            "SELECT value FROM app_secrets WHERE name=?", (ARCHIVE_SECRET_NAME,)
        ).fetchone()
        if row is not None:
            return str(row["value"])
        value = secrets.token_hex(32)
        self.connection.execute(
            "INSERT OR IGNORE INTO app_secrets(name,value,created_at) VALUES(?,?,?)",
            (ARCHIVE_SECRET_NAME, value, now),
        )
        row = self.connection.execute(
            "SELECT value FROM app_secrets WHERE name=?", (ARCHIVE_SECRET_NAME,)
        ).fetchone()
        return str(row["value"])

    # ---- 快照 ----
    def insert_snapshot(self, fields: dict[str, Any], now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO audit_archive_snapshots(snapshot_code,scope_json,policy_json,fingerprint,"
            "chunk_size,start_event_id,end_event_id,expected_event_count,status,created_by,"
            "created_by_name,frozen_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                fields["snapshot_code"],
                json.dumps(fields["scope"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                json.dumps(fields["policy"], ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                fields["fingerprint"],
                fields["chunk_size"],
                fields["start_event_id"],
                fields["end_event_id"],
                fields["expected_event_count"],
                fields["status"],
                fields["created_by"],
                fields["created_by_name"],
                now,
                now,
                now,
            ),
        )
        return self.require_snapshot(int(cursor.lastrowid))

    def require_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM audit_archive_snapshots WHERE id=?", (snapshot_id,)
        ).fetchone()
        if row is None:
            from app.core.errors import NotFoundError

            raise NotFoundError("归档快照不存在")
        return dict(row)

    def snapshot_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM audit_archive_snapshots WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        return dict(row) if row is not None else None

    def list_snapshots(self, *, status: str | None, limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        where = " WHERE status=?" if status else ""
        params: tuple[Any, ...] = (status,) if status else ()
        total = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_archive_snapshots" + where, params
            ).fetchone()[0]
        )
        rows = rows_dict(
            self.connection.execute(
                "SELECT * FROM audit_archive_snapshots" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        )
        return rows, total

    def update_status(self, snapshot_id: int, status: str, *, reason: str | None = None, now: str) -> None:
        self.connection.execute(
            "UPDATE audit_archive_snapshots SET status=?,failure_reason=?,updated_at=? WHERE id=?",
            (status, reason, now, snapshot_id),
        )

    def complete_snapshot(
        self,
        snapshot_id: int,
        *,
        total_events: int,
        total_chunks: int,
        manifest_digest: str,
        manifest_signature: str,
        now: str,
    ) -> None:
        self.connection.execute(
            "UPDATE audit_archive_snapshots SET status='completed',total_events=?,total_chunks=?,"
            "manifest_digest=?,manifest_signature=?,failure_reason=NULL,updated_at=? WHERE id=?",
            (total_events, total_chunks, manifest_digest, manifest_signature, now, snapshot_id),
        )

    # ---- 分块 ----
    def last_chunk(self, snapshot_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM audit_archive_chunks WHERE snapshot_id=? ORDER BY seq DESC LIMIT 1",
            (snapshot_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def chunk_exists(self, snapshot_id: int, seq: int) -> bool:
        return self.connection.execute(
            "SELECT 1 FROM audit_archive_chunks WHERE snapshot_id=? AND seq=?", (snapshot_id, seq)
        ).fetchone() is not None

    def insert_chunk(self, snapshot_id: int, chunk: dict[str, Any], now: str) -> None:
        self.connection.execute(
            "INSERT INTO audit_archive_chunks(snapshot_id,seq,start_event_id,end_event_id,event_count,"
            "first_event_digest,last_event_digest,event_entry_digest,chunk_digest,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                snapshot_id,
                chunk["seq"],
                chunk["start_event_id"],
                chunk["end_event_id"],
                chunk["event_count"],
                chunk["first_event_digest"],
                chunk["last_event_digest"],
                chunk["event_entry_digest"],
                chunk["chunk_digest"],
                now,
            ),
        )

    def list_chunks(self, snapshot_id: int) -> list[dict[str, Any]]:
        return rows_dict(
            self.connection.execute(
                "SELECT * FROM audit_archive_chunks WHERE snapshot_id=? ORDER BY seq", (snapshot_id,)
            ).fetchall()
        )

    # ---- 事件清单 ----
    def insert_events(self, snapshot_id: int, rows: Iterable[dict[str, Any]]) -> None:
        self.connection.executemany(
            "INSERT INTO audit_archive_events(snapshot_id,event_id,chunk_seq,seq,canonical_json,"
            "redacted_json,event_digest,entry_digest,restricted_case,redaction_count) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    snapshot_id,
                    item["event_id"],
                    item["chunk_seq"],
                    item["seq"],
                    item["canonical_json"],
                    item["redacted_json"],
                    item["event_digest"],
                    item["entry_digest"],
                    1 if item["restricted_case"] else 0,
                    item["redaction_count"],
                )
                for item in rows
            ],
        )

    def list_archived_events(self, snapshot_id: int, *, limit: int, offset: int) -> list[dict[str, Any]]:
        return rows_dict(
            self.connection.execute(
                "SELECT * FROM audit_archive_events WHERE snapshot_id=? ORDER BY event_id LIMIT ? OFFSET ?",
                (snapshot_id, limit, offset),
            ).fetchall()
        )

    def count_archived_events(self, snapshot_id: int) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_archive_events WHERE snapshot_id=?", (snapshot_id,)
            ).fetchone()[0]
        )

    def archived_event(self, snapshot_id: int, event_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM audit_archive_events WHERE snapshot_id=? AND event_id=?",
            (snapshot_id, event_id),
        ).fetchone()
        return dict(row) if row is not None else None

    def coverage(self, snapshot_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT COUNT(*) AS chunks, MIN(start_event_id) AS first_id, "
            "MAX(end_event_id) AS last_id, COALESCE(SUM(event_count),0) AS events "
            "FROM audit_archive_chunks WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        return dict(row)

    # ---- 线上审计事件（只读）----
    def max_audit_event_id(self) -> int:
        row = self.connection.execute("SELECT MAX(id) AS m FROM audit_events").fetchone()
        return int(row["m"] or 0)

    def audit_event(self, event_id: int) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone()
        return dict(row) if row is not None else None

    def audit_events_window(self, start_id: int, end_id: int, limit: int) -> list[dict[str, Any]]:
        return rows_dict(
            self.connection.execute(
                "SELECT * FROM audit_events WHERE id BETWEEN ? AND ? ORDER BY id LIMIT ?",
                (start_id, end_id, limit),
            ).fetchall()
        )

    def audit_count_in_range(self, start_id: int, end_id: int) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE id BETWEEN ? AND ?", (start_id, end_id)
            ).fetchone()[0]
        )

    def case_ids_present(self, case_ids: list[int]) -> set[int]:
        if not case_ids:
            return set()
        marks = ",".join("?" for _ in case_ids)
        return {
            int(row[0])
            for row in self.connection.execute(
                f"SELECT id FROM forensic_cases WHERE id IN ({marks})", tuple(case_ids)
            ).fetchall()
        }

    def restricted_case_ids(self) -> list[int]:
        return [
            int(row[0])
            for row in self.connection.execute(
                "SELECT id FROM forensic_cases WHERE status='restricted' ORDER BY id"
            ).fetchall()
        ]
