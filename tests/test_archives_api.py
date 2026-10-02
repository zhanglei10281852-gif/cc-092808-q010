from __future__ import annotations

import json
import sys

from app.database import get_connection


def latest_event_id() -> int:
    value = get_connection().execute("SELECT MAX(id) FROM audit_events").fetchone()[0]
    return int(value) if value is not None else 0


def make_auditor(client, admin_headers: dict, username: str = "auditor1") -> dict:
    created = client.post("/api/users", headers=admin_headers, json={
        "username": username, "password": "Auditor!23456", "display_name": "审计员甲",
        "role_codes": ["auditor"],
    })
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={
        "username": username, "password": "Auditor!23456", "client_label": "tests",
    })
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}}


def freeze_and_generate(client, headers: dict, end_event_id: int, **overrides) -> dict:
    payload = {
        "end_event_id": end_event_id,
        "redact_tokens": True,
        "redact_contacts": True,
        "redact_restricted_cases": True,
        "chunk_size": 2,
    }
    payload.update(overrides)
    frozen = client.post("/api/audit/archives", headers=headers, json=payload)
    assert frozen.status_code == 201, frozen.text
    snapshot = frozen.json()
    generated = client.post(f"/api/audit/archives/{snapshot['id']}/generate", headers=headers, json={})
    assert generated.status_code == 200, generated.text
    return generated.json()


def test_archive_lifecycle_over_http(client, admin):
    headers = admin["headers"]
    end_event_id = latest_event_id()
    snapshot = freeze_and_generate(client, headers, end_event_id)
    assert snapshot["status"] == "completed"
    assert snapshot["total_events"] == snapshot["expected_event_count"]
    assert snapshot["covered_to_event_id"] == end_event_id
    snapshot_id = snapshot["id"]

    listing = client.get("/api/audit/archives", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["total"] >= 1

    chunks = client.get(f"/api/audit/archives/{snapshot_id}/chunks", headers=headers)
    assert chunks.status_code == 200
    assert len(chunks.json()) == snapshot["total_chunks"]

    verify = client.get(f"/api/audit/archives/{snapshot_id}/verify", headers=headers)
    assert verify.status_code == 200
    assert verify.json()["ok"] is True
    assert verify.json()["coverage"]["to_event_id"] == end_event_id

    events = client.get(f"/api/audit/archives/{snapshot_id}/events?size=3", headers=headers)
    assert events.status_code == 200
    body = events.json()
    assert body["total"] == snapshot["total_events"]
    assert len(body["items"]) == min(3, body["total"])
    first_payload = json.dumps(body["items"][0]["payload"], ensure_ascii=False)
    assert "Admin!23456" not in first_payload

    trace = client.get(
        f"/api/audit/archives/{snapshot_id}/events/{body['items'][0]['event_id']}/trace",
        headers=headers,
    )
    assert trace.status_code == 200
    assert trace.json()["digest_match"] is True
    assert trace.json()["read_only"] is True

    exported = client.get(f"/api/audit/archives/{snapshot_id}/export?profile=redacted", headers=headers)
    assert exported.status_code == 200
    bundle = exported.json()
    assert bundle["snapshot"]["fingerprint"] == snapshot["fingerprint"]


def test_auditor_can_verify_but_not_freeze_or_reveal(client, admin):
    admin_headers = admin["headers"]
    end_event_id = latest_event_id()
    snapshot = freeze_and_generate(client, admin_headers, end_event_id, chunk_size=5)
    auditor = make_auditor(client, admin_headers)

    assert client.post("/api/audit/archives", headers=auditor["headers"], json={
        "end_event_id": end_event_id,
    }).status_code == 403
    assert client.post(
        f"/api/audit/archives/{snapshot['id']}/generate", headers=auditor["headers"], json={}
    ).status_code == 403

    verify = client.get(f"/api/audit/archives/{snapshot['id']}/verify", headers=auditor["headers"])
    assert verify.status_code == 200
    assert verify.json()["ok"] is True

    assert client.get(
        f"/api/audit/archives/{snapshot['id']}/events?reveal=true", headers=auditor["headers"]
    ).status_code == 403
    assert client.get(
        f"/api/audit/archives/{snapshot['id']}/export?profile=canonical", headers=auditor["headers"]
    ).status_code == 403
    assert client.get(
        f"/api/audit/archives/{snapshot['id']}/export?profile=redacted", headers=auditor["headers"]
    ).status_code == 200


def test_unauthenticated_access_rejected(client):
    assert client.get("/api/audit/archives").status_code == 401


def test_policy_change_creates_distinct_snapshot_over_http(client, admin):
    headers = admin["headers"]
    end_event_id = latest_event_id()
    first = freeze_and_generate(client, headers, end_event_id, redact_contacts=True)
    duplicate = client.post("/api/audit/archives", headers=headers, json={
        "end_event_id": end_event_id, "redact_tokens": True, "redact_contacts": True,
        "redact_restricted_cases": True, "chunk_size": 2,
    })
    # 同一秒内重复冻结相同输入会冲突（幂等保护），改策略则得到新版本。
    assert duplicate.status_code in (201, 409)
    second = client.post("/api/audit/archives", headers=headers, json={
        "end_event_id": end_event_id, "redact_tokens": True, "redact_contacts": False,
        "redact_restricted_cases": True, "chunk_size": 2,
    })
    assert second.status_code == 201, second.text
    assert second.json()["fingerprint"] != first["fingerprint"]
    assert first["status"] == "completed"


def test_cli_archive_commands(client, tmp_path, monkeypatch, admin):
    import contextlib
    import io

    from app import cli as cli_module

    del admin  # 引导管理员以产生至少一条审计事件
    end_event_id = latest_event_id()
    assert end_event_id >= 1

    def run_cli(*argv: str) -> tuple[int, dict]:
        monkeypatch.setattr(sys, "argv", ["app.cli", *argv])
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            try:
                code = cli_module.main()
            except SystemExit as exc:
                code = exc.code
        lines = [line for line in buffer.getvalue().strip().splitlines() if line]
        return code, json.loads("\n".join(lines))

    code, frozen = run_cli("archive", "freeze", str(end_event_id), "--chunk-size", "1")
    assert code == 0
    assert frozen["expected_event_count"] >= 1
    snapshot_id = frozen["id"]

    code, generated = run_cli("archive", "generate", str(snapshot_id))
    assert code == 0 and generated["status"] == "completed"

    code, shown = run_cli("archive", "show", str(snapshot_id))
    assert code == 0 and shown["status"] == "completed"
    assert len(shown["chunks"]) == generated["total_chunks"]

    code, listed = run_cli("archive", "list")
    assert code == 0 and listed["total"] >= 1

    code, verified = run_cli("archive", "verify", str(snapshot_id))
    assert code == 0 and verified["ok"] is True

    target = tmp_path / "bundle.json"
    code, exported = run_cli("archive", "export", str(snapshot_id), str(target), "--profile", "redacted")
    assert code == 0 and exported["events"] >= 1
    assert target.exists()

    code, offline = run_cli("archive", "verify-file", str(target))
    assert code == 0 and offline["ok"] is True

    # 篡改导出包后离线校验应失败并返回非零退出码。
    bundle = json.loads(target.read_text(encoding="utf-8"))
    bundle["events"][0]["entry_digest"] = "0" * 64
    target.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    code, failed = run_cli("archive", "verify-file", str(target))
    assert code == 2 and failed["ok"] is False
