from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db, transaction
from app.forensics.service import ForensicService
from app.archives.service import ArchiveService, FreezeRequest


def init_command() -> dict:
    init_db()
    return {"database": str(database_path()), "initialized": True}


def check_command() -> dict:
    init_db()
    connection = get_connection()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    required = {
        "forensic_cases", "specimens", "storage_locations", "examinations",
        "review_schedules", "quality_alerts", "outbox_events",
        "archive_snapshots", "archive_chunks", "archive_chunk_events",
    }
    actual = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    return {
        "database": str(database_path()),
        "integrity": integrity,
        "foreign_key_errors": len(foreign_keys),
        "required_tables_present": required.issubset(actual),
        "table_count": len(actual),
    }


def smoke_command() -> dict:
    from app.main import app

    init_db()
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
    if root.status_code != 200 or health.status_code != 200:
        raise RuntimeError("HTTP 冒烟检查失败")
    return {"root": root.json(), "health": health.json(), "status": "ok"}


def demo_command() -> dict:
    init_db()
    service = ForensicService(get_connection())
    suffix = get_connection().execute("SELECT COUNT(*) FROM forensic_cases").fetchone()[0] + 1
    with transaction(immediate=True):
        source = service.forensic_cases.create_agency({
            "agency_code": f"DEMO-{suffix:04d}",
            "agency_name": "示范公安分局",
            "jurisdiction_code": "CN",
            "contact_address": "示范区法医物证受理中心",
            "licensed_on": "2026-09-01",
            "accreditation_no": None,
            "restrictions": {},
        })
        forensic_case = service.forensic_cases.create_forensic_case({
            "case_no": f"CASE-DEMO-{suffix:04d}",
            "case_name": "示范区身份关系鉴定",
            "discipline": "法医物证",
            "entrusted_matter": "亲缘关系鉴定",
            "agency_id": source["id"],
            "case_source": "委托",
            "accepted_on": "2026-09-20",
            "passport": {"commission_document": "DEMO-2026"},
            "created_by": "cli",
        })
        accepted = service.forensic_cases.transition(forensic_case["id"], {
            "target_status": "accepted", "reason": "资料齐全", "expected_version": 1, "actor": "cli"
        })
        location = service.custody.create_location({
            "location_code": f"DEMO-VAULT-{suffix:04d}", "facility": "检材保管室", "room": "冷藏区",
            "rack": "R1", "shelf": "S1", "capacity_units": 5000,
            "reference_value": -18, "humidity_percent": 30,
        })
        specimen = service.custody.create_specimen({
            "specimen_no": f"SP-DEMO-{suffix:04d}", "case_id": accepted["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 5, "integrity_percent": 100,
            "packaging": "独立封袋，封识完整", "sealed_on": "2026-09-21", "created_by": "cli",
        })
        placement = service.custody.place_specimen({
            "specimen_id": specimen["id"], "location_id": location["id"], "quantity": 5,
            "container_code": f"BOX-DEMO-{suffix:04d}", "idempotency_key": f"demo-place-{suffix:08d}", "actor": "cli",
        })
    return {
        "case_no": accepted["case_no"],
        "specimen_no": specimen["specimen_no"],
        "location": location["location_code"],
        "placement_id": placement["placement"]["id"],
        "dashboard": service.dashboard(),
    }


def export_command(path: str) -> dict:
    init_db()
    service = ForensicService(get_connection())
    items, total = service.repository.list_forensic_cases(status=None, crop=None, limit=10_000, offset=0)
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(target), "count": total}


def _public_archive(snapshot: dict) -> dict:
    view = dict(snapshot)
    view.pop("envelope_secret_hex", None)
    view.pop("anchor_ids_json", None)
    return view


def archive_freeze_command(args: argparse.Namespace) -> dict:
    init_db()
    with transaction(immediate=True) as connection:
        snapshot = ArchiveService(connection).freeze(FreezeRequest(
            cutoff_event_id=args.cutoff_event_id,
            policy_code=args.policy,
            scope_start_id=args.start_event_id,
            chunk_size=args.chunk_size,
            created_by="cli",
        ))
    return _public_archive(snapshot)


def archive_generate_command(args: argparse.Namespace) -> dict:
    init_db()
    service = ArchiveService(get_connection())
    service.generate(args.snapshot_id, worker="cli")
    return service.progress(args.snapshot_id)


def archive_progress_command(args: argparse.Namespace) -> dict:
    init_db()
    return ArchiveService(get_connection()).progress(args.snapshot_id)


def archive_verify_command(args: argparse.Namespace) -> dict:
    init_db()
    return ArchiveService(get_connection()).verify_snapshot(args.snapshot_id, deep=args.deep)


def archive_export_command(args: argparse.Namespace) -> dict:
    init_db()
    service = ArchiveService(get_connection())
    bundle = service.export_bundle(args.snapshot_id)
    target = Path(args.path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "path": str(target),
        "snapshot_code": bundle["snapshot"]["code"],
        "manifest_hash": bundle["manifest_hash"],
        "events": bundle["snapshot"]["anchor_count"],
        "chunks": len(bundle["chunks"]),
    }


def archive_verify_bundle_command(args: argparse.Namespace) -> dict:
    """离线校验导出包：不连数据库，可选传入可信根摘要识破整体重算。"""
    target = Path(args.path).expanduser().resolve()
    bundle = json.loads(target.read_text(encoding="utf-8"))
    return ArchiveService.verify_bundle(bundle, expected_manifest_hash=args.manifest_hash)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="司法鉴定机构运维命令")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行 HTTP 冒烟检查")
    subparsers.add_parser("demo", help="写入一组示范入库数据")
    export = subparsers.add_parser("export-forensic_cases", help="导出案件档案")
    export.add_argument("path")

    archive_freeze = subparsers.add_parser("archive-freeze", help="冻结审计归档快照范围")
    archive_freeze.add_argument("cutoff_event_id", type=int)
    archive_freeze.add_argument("--start-event-id", type=int, default=1)
    archive_freeze.add_argument("--policy", choices=["none", "standard", "strict"], default="none")
    archive_freeze.add_argument("--chunk-size", type=int, default=200)

    archive_generate = subparsers.add_parser("archive-generate", help="分块生成归档清单（可续跑）")
    archive_generate.add_argument("snapshot_id", type=int)

    archive_progress = subparsers.add_parser("archive-progress", help="查看归档进度与覆盖区间")
    archive_progress.add_argument("snapshot_id", type=int)

    archive_verify = subparsers.add_parser("archive-verify", help="独立校验归档完整性")
    archive_verify.add_argument("snapshot_id", type=int)
    archive_verify.add_argument("--deep", action="store_true", help="回溯线上审计事件原值比对")

    archive_export = subparsers.add_parser("archive-export", help="导出可离线校验的归档包")
    archive_export.add_argument("snapshot_id", type=int)
    archive_export.add_argument("path")

    archive_check = subparsers.add_parser("archive-verify-bundle", help="离线校验归档包（不连数据库）")
    archive_check.add_argument("path")
    archive_check.add_argument("--manifest-hash", default=None, help="可信留档的清单根摘要")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "init-db":
            result = init_command()
        elif args.command == "check-db":
            result = check_command()
        elif args.command == "smoke":
            result = smoke_command()
        elif args.command == "demo":
            result = demo_command()
        elif args.command == "archive-freeze":
            result = archive_freeze_command(args)
        elif args.command == "archive-generate":
            result = archive_generate_command(args)
        elif args.command == "archive-progress":
            result = archive_progress_command(args)
        elif args.command == "archive-verify":
            result = archive_verify_command(args)
        elif args.command == "archive-export":
            result = archive_export_command(args)
        elif args.command == "archive-verify-bundle":
            result = archive_verify_bundle_command(args)
        else:
            result = export_command(args.path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (sqlite3.Error, RuntimeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
