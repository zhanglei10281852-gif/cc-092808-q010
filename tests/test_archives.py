from __future__ import annotations

import copy
import json

import pytest

from app.archives.service import ArchiveService, FreezeRequest
from app.database import get_connection, transaction


def _login(client, username, password):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password, "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def rich_admin(client, admin):
    """管理员 + 一名带联系方式的用户（产生含联系方式的审计事件）。"""
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": "contact.user",
            "password": "Contact!23456",
            "display_name": "联系人",
            "email": "zhangsan@example.com",
            "phone": "13812345678",
            "role_codes": [],
        },
    )
    assert response.status_code == 201, response.text
    return admin


@pytest.fixture()
def auditor(client, admin):
    client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "archive.auditor", "name": "归档审计员",
              "permission_codes": ["audit.read", "audit.archive.read", "audit.archive.verify"]},
    )
    client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": "auditor.gal", "password": "Auditor!23456",
              "display_name": "审计员", "role_codes": ["archive.auditor"]},
    )
    return _login(client, "auditor.gal", "Auditor!23456")


def _max_event_id() -> int:
    return int(get_connection().execute("SELECT MAX(id) FROM audit_events").fetchone()[0])


def _freeze(client, headers, *, policy="none", chunk_size=2, cutoff=None):
    cutoff = cutoff if cutoff is not None else _max_event_id()
    response = client.post(
        "/api/audit-archives/freeze",
        headers=headers,
        json={"cutoff_event_id": cutoff, "policy_code": policy, "chunk_size": chunk_size},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _generate(client, headers, snapshot_id):
    response = client.post(f"/api/audit-archives/{snapshot_id}/generate", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------- 基本链路

def test_freeze_generate_verify_full_flow(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=2)
    progress = _generate(client, rich_admin["headers"], snapshot["id"])
    assert progress["status"] == "completed"
    assert progress["percent"] == 100.0
    assert progress["confirmed_events"] == snapshot["anchor_count"]
    assert progress["manifest_hash"]
    # 覆盖区间首尾相连
    intervals = [(c["start_event_id"], c["end_event_id"]) for c in progress["chunks"]]
    assert intervals[0][0] == snapshot["scope_start_id"]
    assert intervals[-1][1] == snapshot["scope_end_id"]

    verify = client.post(f"/api/audit-archives/{snapshot['id']}/verify", headers=rich_admin["headers"])
    assert verify.status_code == 200
    body = verify.json()
    assert body["valid"] is True
    assert body["events_verified"] == snapshot["anchor_count"]
    assert body["problems"] == []


def test_freeze_rejects_unknown_cutoff(client, rich_admin):
    response = client.post(
        "/api/audit-archives/freeze",
        headers=rich_admin["headers"],
        json={"cutoff_event_id": 999_999, "policy_code": "none"},
    )
    assert response.status_code == 404


def test_snapshot_view_never_exposes_secret(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"])
    serialized = json.dumps(snapshot)
    assert "envelope_secret" not in serialized
    detail = client.get(f"/api/audit-archives/{snapshot['id']}", headers=rich_admin["headers"]).json()
    assert "envelope_secret_hex" not in detail


# ------------------------------------------------------- 确定性与策略版本管理

def test_identical_freeze_is_idempotent_and_deterministic(client, rich_admin):
    cutoff = _max_event_id()  # 冻结动作自身也会写审计，故先固定截止事件
    first = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=2, cutoff=cutoff)
    completed = _generate(client, rich_admin["headers"], first["id"])
    # 用完全相同的截止事件与参数再次冻结：返回同一归档，标识不变。
    again = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=2, cutoff=cutoff)
    assert again["id"] == first["id"]
    # 已完成的快照重复执行得到相同标识（根摘要）。
    regenerated = _generate(client, rich_admin["headers"], first["id"])
    assert regenerated["manifest_hash"] == completed["manifest_hash"]


def test_policy_change_creates_new_version_without_overwriting(client, rich_admin):
    cutoff = _max_event_id()
    v1 = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=2, cutoff=cutoff)
    _generate(client, rich_admin["headers"], v1["id"])
    v2 = _freeze(client, rich_admin["headers"], policy="strict", chunk_size=2, cutoff=cutoff)
    assert v2["id"] != v1["id"]
    assert v2["version"] == v1["version"] + 1
    _generate(client, rich_admin["headers"], v2["id"])
    # 旧归档保留且仍可校验
    old = client.post(f"/api/audit-archives/{v1['id']}/verify", headers=rich_admin["headers"]).json()
    assert old["valid"] is True
    listing = client.get("/api/audit-archives?size=100", headers=rich_admin["headers"]).json()
    codes = {row["snapshot_code"] for row in listing["data"]}
    assert v1["snapshot_code"] in codes and v2["snapshot_code"] in codes


def test_chunk_size_change_is_a_new_version(client, rich_admin):
    cutoff = _max_event_id()
    v1 = _freeze(client, rich_admin["headers"], chunk_size=2, cutoff=cutoff)
    v2 = _freeze(client, rich_admin["headers"], chunk_size=3, cutoff=cutoff)
    assert v2["version"] == v1["version"] + 1


# ---------------------------------------------------------------- 断点续跑

def test_generation_resumes_from_confirmed_chunks(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=1)
    total_chunks = snapshot["anchor_count"]
    assert total_chunks >= 2

    # 在另一个连接里只生成第一块（模拟导出中断）。
    service = ArchiveService(get_connection())
    fresh = service.get(snapshot["id"])
    anchors = json.loads(fresh["anchor_ids_json"])
    secret = bytes.fromhex(fresh["envelope_secret_hex"])
    service._generate_chunk(fresh, 1, anchors[0:1], secret=secret, policy="none")
    partial = client.get(f"/api/audit-archives/{snapshot['id']}/progress", headers=rich_admin["headers"]).json()
    assert partial["confirmed_chunks"] == 1
    assert partial["status"] == "frozen"

    # 通过 API 续跑：从第二块继续，结果完整且一致。
    done = _generate(client, rich_admin["headers"], snapshot["id"])
    assert done["status"] == "completed"
    assert done["confirmed_chunks"] == total_chunks
    verify = client.post(f"/api/audit-archives/{snapshot['id']}/verify", headers=rich_admin["headers"]).json()
    assert verify["valid"] is True


# ----------------------------------------------------------------- 脱敏与复核

def test_standard_policy_redacts_contacts_but_keeps_envelopes(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=5)
    _generate(client, rich_admin["headers"], snapshot["id"])
    bundle = client.get(f"/api/audit-archives/{snapshot['id']}/bundle", headers=rich_admin["headers"]).json()
    blob = json.dumps(bundle, ensure_ascii=False)
    assert "zhangsan@example.com" not in blob
    assert "13812345678" not in blob
    assert "z***@example.com" in blob
    assert "138****5678" in blob

    # 找到 contact 信封并验证原值
    target = None
    for chunk in bundle["chunks"]:
        for event in chunk["events"]:
            for key, value in (event["body"].get("after") or {}).items():
                if isinstance(value, dict) and value.get("category") == "contact":
                    target = (event["audit_event_id"], f"after.{key}", key)
    assert target is not None
    event_id, path, key = target
    original = "zhangsan@example.com" if key == "email" else "13812345678"
    ok = client.post(
        f"/api/audit-archives/{snapshot['id']}/events/{event_id}/verify-value",
        headers=rich_admin["headers"], json={"path": path, "original": original},
    )
    assert ok.status_code == 200 and ok.json()["verified"] is True
    bad = client.post(
        f"/api/audit-archives/{snapshot['id']}/events/{event_id}/verify-value",
        headers=rich_admin["headers"], json={"path": path, "original": "intruder@evil.com"},
    )
    assert bad.json()["verified"] is False


def test_review_endpoints_require_review_permission(client, rich_admin, auditor):
    snapshot = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=5)
    _generate(client, rich_admin["headers"], snapshot["id"])
    # 审计员可读、可校验，但不能看掩码信封的复核证据，也不能验原值
    reveal = client.get(
        f"/api/audit-archives/{snapshot['id']}/chunks/1?reveal=true", headers=auditor
    )
    assert reveal.status_code == 403
    deep = client.post(f"/api/audit-archives/{snapshot['id']}/verify?deep=true", headers=auditor)
    assert deep.status_code == 403
    # 普通校验允许
    shallow = client.post(f"/api/audit-archives/{snapshot['id']}/verify", headers=auditor)
    assert shallow.status_code == 200 and shallow.json()["valid"] is True


def test_freeze_and_generate_require_admin_permissions(client, rich_admin, auditor):
    response = client.post(
        "/api/audit-archives/freeze",
        headers=auditor,
        json={"cutoff_event_id": _max_event_id(), "policy_code": "none"},
    )
    assert response.status_code == 403


# ------------------------------------------------------------- 篡改检测（在线）

def test_field_change_detected_by_deep_verify(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=2)
    _generate(client, rich_admin["headers"], snapshot["id"])
    connection = get_connection()
    connection.execute("UPDATE audit_events SET actor_name='被篡改' WHERE id=1")
    connection.commit()
    verify = client.post(
        f"/api/audit-archives/{snapshot['id']}/verify?deep=true", headers=rich_admin["headers"]
    ).json()
    assert verify["valid"] is False
    assert any("字段已变化" in problem for problem in verify["problems"])


def test_deleted_event_detected(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=2)
    _generate(client, rich_admin["headers"], snapshot["id"])
    connection = get_connection()
    connection.execute("DELETE FROM audit_events WHERE id=1")
    connection.commit()
    verify = client.post(
        f"/api/audit-archives/{snapshot['id']}/verify?deep=true", headers=rich_admin["headers"]
    ).json()
    assert verify["valid"] is False
    assert any("删除" in problem for problem in verify["problems"])


def test_generation_fails_when_frozen_event_missing(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=2)
    connection = get_connection()
    connection.execute("DELETE FROM audit_events WHERE id=1")
    connection.commit()
    response = client.post(f"/api/audit-archives/{snapshot['id']}/generate", headers=rich_admin["headers"])
    assert response.status_code == 409
    progress = client.get(f"/api/audit-archives/{snapshot['id']}/progress", headers=rich_admin["headers"]).json()
    assert progress["status"] == "failed"
    assert progress["failure_reason"]


# ----------------------------------------------------------- 篡改检测（离线包）

def test_offline_bundle_verify_detects_tampering(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="standard", chunk_size=2)
    _generate(client, rich_admin["headers"], snapshot["id"])
    bundle = client.get(f"/api/audit-archives/{snapshot['id']}/bundle", headers=rich_admin["headers"]).json()
    root = bundle["manifest_hash"]

    assert ArchiveService.verify_bundle(copy.deepcopy(bundle))["valid"] is True

    # 字段变化
    tampered = copy.deepcopy(bundle)
    tampered["chunks"][0]["events"][0]["body"]["actor_name"] = "中间人"
    assert ArchiveService.verify_bundle(tampered)["valid"] is False

    # 重排
    reordered = copy.deepcopy(bundle)
    events = reordered["chunks"][-1]["events"]
    if len(events) >= 2:
        events[-1], events[-2] = events[-2], events[-1]
        events[-1]["position"], events[-2]["position"] = events[-2]["position"], events[-1]["position"]
        assert ArchiveService.verify_bundle(reordered)["valid"] is False

    # 插入一条伪造事件（沿用结构）
    inserted = copy.deepcopy(bundle)
    clone = copy.deepcopy(inserted["chunks"][0]["events"][0])
    clone["position"] = 999
    inserted["chunks"][0]["events"].append(clone)
    assert ArchiveService.verify_bundle(inserted)["valid"] is False

    # 可信根摘要不匹配（整体替换）
    assert ArchiveService.verify_bundle(bundle, expected_manifest_hash="0" * 64)["valid"] is False
    assert ArchiveService.verify_bundle(bundle, expected_manifest_hash=root)["valid"] is True


def test_offline_bundle_verify_cli(tmp_path, client, rich_admin):
    import argparse

    from app.cli import archive_verify_bundle_command

    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=2)
    _generate(client, rich_admin["headers"], snapshot["id"])
    root = client.get(f"/api/audit-archives/{snapshot['id']}/bundle", headers=rich_admin["headers"]).json()["manifest_hash"]
    out = tmp_path / "bundle.json"
    from app.archives.service import ArchiveService as AS
    out.write_text(json.dumps(AS(get_connection()).export_bundle(snapshot["id"]), ensure_ascii=False), encoding="utf-8")

    result = archive_verify_bundle_command(argparse.Namespace(path=str(out), manifest_hash=root))
    assert result["valid"] is True
    assert result["root_matches_record"] is True


# ---------------------------------------------------------------- 溯源

def test_provenance_links_back_to_live_event(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=2)
    _generate(client, rich_admin["headers"], snapshot["id"])
    provenance = client.get(
        f"/api/audit-archives/{snapshot['id']}/events/1/provenance", headers=rich_admin["headers"]
    )
    assert provenance.status_code == 200
    body = provenance.json()
    assert body["audit_event_id"] == 1
    assert body["live_event_present"] is True
    assert body["unchanged"] is True
    assert body["original_event"]["id"] == 1


# ------------------------------------------------------------ 脱敏原语（单元）

def test_token_envelope_hides_value_and_proof_needs_secret():
    from app.archives.redaction import POLICY_STANDARD, apply_policy, verify_envelope

    secret = b"0" * 32
    event = {"id": 1, "metadata": {"token": "super-secret-token-value", "note": "ok"}}
    masked = apply_policy(event, POLICY_STANDARD, secret)
    envelope = masked["metadata"]["token"]
    assert envelope["masked"] == "***"
    assert "super-secret-token-value" not in json.dumps(envelope)
    # 无密钥无法离线猜测：证据是 HMAC，不是明文 SHA-256
    assert "proof" in envelope
    assert verify_envelope(envelope, "token", "super-secret-token-value", secret) is True
    assert verify_envelope(envelope, "token", "guessed-token", secret) is False
    assert verify_envelope(envelope, "token", "super-secret-token-value", b"1" * 32) is False
    # none 策略不动字段
    assert apply_policy(event, "none", secret) == event


def test_failed_snapshot_can_resume_and_complete(client, rich_admin):
    snapshot = _freeze(client, rich_admin["headers"], policy="none", chunk_size=1)
    connection = get_connection()
    # 删掉第一块覆盖的事件，首次生成必然失败
    connection.execute("DELETE FROM audit_events WHERE id=1")
    connection.commit()
    failed = client.post(f"/api/audit-archives/{snapshot['id']}/generate", headers=rich_admin["headers"])
    assert failed.status_code == 409
    # 恢复事件后（模拟纠正数据源），同一快照可重跑成功
    connection.execute(
        "INSERT INTO audit_events(id,actor_name,action,resource_type,outcome,metadata_json,created_at) "
        "VALUES(1,'系统管理员','system.bootstrap','user','success','{}','2026-01-01T00:00:00+00:00')"
    )
    connection.commit()
    progress = _generate(client, rich_admin["headers"], snapshot["id"])
    assert progress["status"] == "completed"
    verify = client.post(f"/api/audit-archives/{snapshot['id']}/verify", headers=rich_admin["headers"]).json()
    assert verify["valid"] is True
