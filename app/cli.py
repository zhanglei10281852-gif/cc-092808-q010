from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.archives.repository import ARCHIVE_SECRET_NAME
from app.archives.service import ArchiveService
from app.core.clock import to_storage, utc_now
from app.core.errors import DomainError
from app.database import database_path, get_connection, init_db, transaction
from app.forensics.service import ForensicService


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
        "audit_archive_snapshots", "audit_archive_chunks", "audit_archive_events", "app_secrets",
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


def _archive_service() -> ArchiveService:
    init_db()
    return ArchiveService(get_connection())


def archive_freeze_command(args: argparse.Namespace) -> dict:
    restricted_case_ids = (
        [int(part) for part in args.restricted_case_ids.split(",") if part]
        if args.restricted_case_ids
        else None
    )
    snapshot = _archive_service().freeze(
        created_by=None,
        created_by_name="cli",
        end_event_id=args.end_event_id,
        redact_tokens=not args.no_redact_tokens,
        redact_contacts=not args.no_redact_contacts,
        redact_restricted_cases=not args.no_redact_restricted_cases,
        restricted_case_ids=restricted_case_ids,
        chunk_size=args.chunk_size,
    )
    return snapshot


def archive_generate_command(args: argparse.Namespace) -> dict:
    return _archive_service().generate(args.snapshot_id, max_chunks=args.max_chunks)


def archive_list_command(args: argparse.Namespace) -> dict:
    return _archive_service().list_snapshots(status=args.status, limit=args.limit, offset=args.offset)


def archive_show_command(args: argparse.Namespace) -> dict:
    service = _archive_service()
    snapshot = service.get_snapshot(args.snapshot_id)
    snapshot["chunks"] = service.list_chunks(args.snapshot_id)
    return snapshot


def archive_verify_command(args: argparse.Namespace) -> dict:
    return _archive_service().verify(args.snapshot_id)


def archive_export_command(args: argparse.Namespace) -> dict:
    service = _archive_service()
    bundle = service.export_bundle(args.snapshot_id, profile=args.profile)
    target = Path(args.path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(target), "profile": args.profile, "events": len(bundle["events"]), "chunks": len(bundle["chunks"])}


def archive_verify_file_command(args: argparse.Namespace) -> dict:
    bundle = json.loads(Path(args.path).expanduser().resolve().read_text(encoding="utf-8"))
    secret: str | None = None
    if args.secret_env:
        secret = os.environ.get(args.secret_env)
    elif args.with_database_secret:
        init_db()
        secret = ArchiveService(get_connection()).repository.archive_secret(to_storage(utc_now()))
    return ArchiveService.verify_bundle(bundle, secret=secret)


def archive_secret_command(args: argparse.Namespace) -> dict:
    del args
    init_db()
    secret = ArchiveService(get_connection()).repository.archive_secret(to_storage(utc_now()))
    if os.getenv("FORENSICS_CLI_REVEAL_SECRET") != "1":
        return {"name": ARCHIVE_SECRET_NAME, "hint": "确认在安全渠道后设置 FORENSICS_CLI_REVEAL_SECRET=1 再执行"}
    return {"name": ARCHIVE_SECRET_NAME, "secret": secret}



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="司法鉴定机构运维命令")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行 HTTP 冒烟检查")
    subparsers.add_parser("demo", help="写入一组示范入库数据")
    export = subparsers.add_parser("export-forensic_cases", help="导出案件档案")
    export.add_argument("path")

    archives = subparsers.add_parser("archive", help="审计归档快照管理")
    archive_sub = archives.add_subparsers(dest="archive_command", required=True)

    freeze = archive_sub.add_parser("freeze", help="按截止事件与脱敏策略冻结快照")
    freeze.add_argument("end_event_id", type=int)
    freeze.add_argument("--chunk-size", type=int, default=200)
    freeze.add_argument("--restricted-case-ids", default="", help="逗号分隔的受限案件 ID，缺省取全部 restricted 案件")
    freeze.add_argument("--no-redact-tokens", action="store_true")
    freeze.add_argument("--no-redact-contacts", action="store_true")
    freeze.add_argument("--no-redact-restricted-cases", action="store_true")

    generate = archive_sub.add_parser("generate", help="生成或续跑分块清单")
    generate.add_argument("snapshot_id", type=int)
    generate.add_argument("--max-chunks", type=int, default=None)

    listed = archive_sub.add_parser("list", help="查看归档快照进度")
    listed.add_argument("--status", choices=["frozen", "generating", "completed", "failed"], default=None)
    listed.add_argument("--limit", type=int, default=20)
    listed.add_argument("--offset", type=int, default=0)

    show = archive_sub.add_parser("show", help="查看快照覆盖区间、失败原因与分块")
    show.add_argument("snapshot_id", type=int)

    verify = archive_sub.add_parser("verify", help="对照线上事件独立校验快照完整性")
    verify.add_argument("snapshot_id", type=int)

    export_archive = archive_sub.add_parser("export", help="导出归档包")
    export_archive.add_argument("snapshot_id", type=int)
    export_archive.add_argument("path")
    export_archive.add_argument("--profile", choices=["manifest", "redacted", "canonical"], default="redacted")

    verify_file = archive_sub.add_parser("verify-file", help="离线校验导出的归档包")
    verify_file.add_argument("path")
    secret_group = verify_file.add_mutually_exclusive_group()
    secret_group.add_argument("--secret-env", default="", help="封存密钥所在环境变量名")
    secret_group.add_argument("--with-database-secret", action="store_true")

    archive_sub.add_parser("secret", help="查看脱敏承诺封存密钥名称（默认不显示值）")
    return parser


ARCHIVE_COMMANDS = {
    "freeze": archive_freeze_command,
    "generate": archive_generate_command,
    "list": archive_list_command,
    "show": archive_show_command,
    "verify": archive_verify_command,
    "export": archive_export_command,
    "verify-file": archive_verify_file_command,
    "secret": archive_secret_command,
}


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
        elif args.command == "archive":
            result = ARCHIVE_COMMANDS[args.archive_command](args)
        else:
            result = export_command(args.path)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.command == "archive" and args.archive_command == "verify" and not result["ok"]:
            return 2
        if args.command == "archive" and args.archive_command == "verify-file" and not result["ok"]:
            return 2
        return 0
    except DomainError as exc:
        print(json.dumps({"error": str(exc), "code": exc.code, "context": exc.context}, ensure_ascii=False))
        return 1
    except (sqlite3.Error, RuntimeError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
