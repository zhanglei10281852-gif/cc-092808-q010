from __future__ import annotations

import json

import pytest

from app.archives.hashing import chain_digest, constant_time_equals, digest, sign
from app.archives.service import ArchiveService
from app.core.clock import FrozenClock
from app.core.errors import ConflictError
from app.database import get_connection, transaction
from app.services.audit import AuditContext, AuditService


def insert_raw_audit(action: str, **overrides) -> int:
    """绕过写入时脱敏，直接落库一条审计事件，用于覆盖历史/外部来源数据。"""
    fields = {
        "actor_user_id": None,
        "actor_name": "tester",
        "action": action,
        "resource_type": "user",
        "reagency_id": None,
        "outcome": "success",
        "before": None,
        "after": None,
        "metadata": {},
        "correlation_id": None,
    }
    fields.update(overrides)
    cursor = get_connection().execute(
        "INSERT INTO audit_events(actor_user_id,actor_name,action,resource_type,reagency_id,outcome,"
        "before_json,after_json,metadata_json,correlation_id,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            fields["actor_user_id"], fields["actor_name"], fields["action"], fields["resource_type"],
            None if fields["reagency_id"] is None else str(fields["reagency_id"]), fields["outcome"],
            json.dumps(fields["before"], ensure_ascii=False, sort_keys=True) if fields["before"] is not None else None,
            json.dumps(fields["after"], ensure_ascii=False, sort_keys=True) if fields["after"] is not None else None,
            json.dumps(fields["metadata"] or {}, ensure_ascii=False, sort_keys=True),
            fields["correlation_id"], "2026-10-01T08:00:00+00:00",
        ),
    )
    return int(cursor.lastrowid)


def seed_events(count: int) -> list[int]:
    ids = []
    with transaction(immediate=True):
        for index in range(count):
            ids.append(
                insert_raw_audit(
                    "user.update",
                    reagency_id=index + 1,
                    after={"email": "ops@example.com", "phone": "13800138000", "token": "abc"},
                    metadata={"memo": f"请回电 13900139000 {index}"},
                )
            )
    return ids


def make_service(clock: FrozenClock | None = None) -> ArchiveService:
    return ArchiveService(get_connection(), clock)


def completed_snapshot(service: ArchiveService, end_id: int, *, chunk_size: int = 2, **policy) -> dict:
    snapshot = service.freeze(
        created_by=None, created_by_name="tester", end_event_id=end_id,
        redact_tokens=policy.get("redact_tokens", True),
        redact_contacts=policy.get("redact_contacts", True),
        redact_restricted_cases=policy.get("redact_restricted_cases", True),
        restricted_case_ids=policy.get("restricted_case_ids", []),
        chunk_size=chunk_size,
    )
    return service.generate(snapshot["id"])


def test_freeze_requires_existing_cutoff_event(client):
    service = make_service()
    with pytest.raises(Exception):
        service.freeze(
            created_by=None, created_by_name="tester", end_event_id=999,
            redact_tokens=True, redact_contacts=True, redact_restricted_cases=True,
        )


def test_generation_recovery_and_coverage(client):
    ids = seed_events(7)
    service = make_service()
    snapshot = service.freeze(
        created_by=None, created_by_name="tester", end_event_id=ids[-1],
        redact_tokens=True, redact_contacts=True, redact_restricted_cases=True,
        restricted_case_ids=[], chunk_size=2,
    )
    assert snapshot["status"] == "frozen"
    assert snapshot["expected_event_count"] == 7

    seen = {"count": 0}

    def hook(event):
        seen["count"] += 1
        if seen["count"] == 5:
            raise RuntimeError("模拟导出中断")

    with pytest.raises(RuntimeError):
        service.generate(snapshot["id"], event_hook=hook)
    failed = service.get_snapshot(snapshot["id"])
    assert failed["status"] == "failed"
    assert "模拟导出中断" in failed["failure_reason"]
    assert failed["confirmed_chunks"] == 2
    assert failed["confirmed_events"] == 4
    assert failed["covered_from_event_id"] == ids[0]
    assert failed["covered_to_event_id"] == ids[3]

    # 从中断点续跑：已确认分块不重复，最终覆盖到截止事件。
    completed = service.generate(snapshot["id"])
    assert completed["status"] == "completed"
    assert completed["total_chunks"] == 4
    assert completed["total_events"] == 7
    assert completed["covered_to_event_id"] == ids[-1]

    # 重复执行是幂等的，标识与根摘要保持不变。
    again = service.generate(snapshot["id"])
    assert again["fingerprint"] == completed["fingerprint"]
    assert again["manifest_digest"] == completed["manifest_digest"]

    verify = service.verify(snapshot["id"])
    assert verify["ok"] is True
    assert verify["coverage"] == {
        "from_event_id": ids[0], "to_event_id": ids[-1],
        "confirmed_chunks": 4, "confirmed_events": 7, "expected_events": 7,
    }
    assert get_connection().execute(
        "SELECT COUNT(*) FROM audit_archive_events WHERE snapshot_id=?", (snapshot["id"],)
    ).fetchone()[0] == 7


def test_verify_detects_field_change_and_delete(client):
    ids = seed_events(5)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1])
    connection = get_connection()

    connection.execute("UPDATE audit_events SET action='tampered' WHERE id=?", (ids[1],))
    connection.commit()
    result = service.verify(snapshot["id"])
    assert result["ok"] is False
    failed_names = {check["name"] for check in result["checks"] if not check["ok"]}
    # 字段变化由逐条事件重算检查捕获；分块链仍与封存的事件摘要自洽。
    assert "event_fields_unchanged" in failed_names
    assert "chunk_chain" not in failed_names

    connection.execute("UPDATE audit_events SET action='user.update' WHERE id=?", (ids[1],))
    connection.commit()
    assert service.verify(snapshot["id"])["ok"] is True

    connection.execute("DELETE FROM audit_events WHERE id=?", (ids[2],))
    connection.commit()
    deleted = service.verify(snapshot["id"])
    assert deleted["ok"] is False
    failed_names = {check["name"] for check in deleted["checks"] if not check["ok"]}
    assert {"range_count", "no_deleted_events"} <= failed_names


def test_verify_detects_chunk_tamper_and_redaction_change(client):
    ids = seed_events(4)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1], chunk_size=2)
    connection = get_connection()
    real_digest = next(
        c for c in service.list_chunks(snapshot["id"]) if c["seq"] == 0
    )["chunk_digest"]

    connection.execute(
        "UPDATE audit_archive_chunks SET chunk_digest=? WHERE snapshot_id=? AND seq=0",
        ("0" * 64, snapshot["id"]),
    )
    connection.commit()
    result = service.verify(snapshot["id"])
    assert result["ok"] is False
    assert any(not c["ok"] and c["name"] == "chunk_chain" for c in result["checks"])

    # 还原分块摘要后，篡改脱敏视图也应暴露。
    connection.execute(
        "UPDATE audit_archive_chunks SET chunk_digest=? WHERE snapshot_id=? AND seq=0",
        (real_digest, snapshot["id"]),
    )
    row = connection.execute(
        "SELECT redacted_json FROM audit_archive_events WHERE snapshot_id=? AND event_id=?",
        (snapshot["id"], ids[0]),
    ).fetchone()
    tampered_view = json.loads(row["redacted_json"])
    tampered_view["action"] = "rewritten"
    connection.execute(
        "UPDATE audit_archive_events SET redacted_json=? WHERE snapshot_id=? AND event_id=?",
        (json.dumps(tampered_view, ensure_ascii=False, sort_keys=True), snapshot["id"], ids[0]),
    )
    connection.commit()
    redaction_result = service.verify(snapshot["id"])
    assert redaction_result["ok"] is False
    assert any(not c["ok"] and c["name"] == "redaction_commits" for c in redaction_result["checks"])


def test_policy_change_creates_new_version_never_overwrites(client):
    ids = seed_events(3)
    from datetime import UTC, datetime
    frozen = FrozenClock(datetime(2026, 10, 1, 9, 0, tzinfo=UTC))
    first_service = ArchiveService(get_connection(), frozen)
    first = completed_snapshot(first_service, ids[-1], redact_contacts=True)

    # 同一冻结时刻重复冻结相同输入会被拒绝（不产生重复归档）。
    with pytest.raises(ConflictError):
        first_service.freeze(
            created_by=None, created_by_name="tester", end_event_id=ids[-1],
            redact_tokens=True, redact_contacts=True, redact_restricted_cases=True,
            restricted_case_ids=[], chunk_size=2,
        )

    # 策略变化必须产生新指纹、新版本，旧归档保持 completed 且可继续校验。
    frozen.advance(minutes=1)
    second = first_service.freeze(
        created_by=None, created_by_name="tester", end_event_id=ids[-1],
        redact_tokens=True, redact_contacts=False, redact_restricted_cases=True,
        restricted_case_ids=[], chunk_size=2,
    )
    assert second["fingerprint"] != first["fingerprint"]
    second_done = first_service.generate(second["id"])
    assert second_done["status"] == "completed"
    listing = first_service.list_snapshots(limit=10, offset=0)
    assert listing["total"] == 2
    assert first_service.get_snapshot(first["id"])["status"] == "completed"


def test_redaction_views_and_commitments(client):
    ids = seed_events(2)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1], chunk_size=5)
    masked = service.events_page(snapshot["id"], limit=10, offset=0, reveal=False)
    first = masked["items"][0]["payload"]
    assert first["after"]["token"]["redacted"] is True
    assert first["after"]["token"]["commit"]
    assert first["after"]["phone"]["masked"] == "138****8000"
    assert first["after"]["email"]["masked"] == "o***@example.com"
    assert first["metadata"]["memo"]["masked"].startswith("请回电 139****9000")
    assert "secret" not in json.dumps(first)
    assert "13800138000" not in json.dumps(first, ensure_ascii=False)

    revealed = service.events_page(snapshot["id"], limit=10, offset=0, reveal=True)
    assert revealed["items"][0]["payload"]["after"]["token"] == "abc"
    assert revealed["items"][0]["payload"]["after"]["phone"] == "13800138000"


def test_restricted_case_fields_are_wrapped(client):
    from app.forensics.service import ForensicService
    with transaction(immediate=True) as connection:
        forensics = ForensicService(connection)
        agency = forensics.forensic_cases.create_agency({
            "agency_code": "RES-1", "agency_name": "保密委", "jurisdiction_code": "CN",
            "contact_address": "", "restrictions": {},
        })
        case = forensics.forensic_cases.create_forensic_case({
            "case_no": "RES-CASE-1", "case_name": "受限案件", "discipline": "法医物证",
            "entrusted_matter": "", "agency_id": agency["id"], "case_source": "移送",
            "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员",
        })
        case = forensics.forensic_cases.transition(case["id"], {
            "target_status": "quarantine", "reason": "待审", "expected_version": 1, "actor": "审核员",
        })
        case = forensics.forensic_cases.transition(case["id"], {
            "target_status": "restricted", "reason": "敏感案件", "expected_version": 2, "actor": "审核员",
        })
        AuditService(connection).record(
            AuditContext(None, "tester"), action="case.view", resource_type="forensic_case",
            reagency_id=case["id"], after={"case_no": "RES-CASE-1", "phone": "13800138000"},
        )
        event_id = connection.execute("SELECT MAX(id) FROM audit_events").fetchone()[0]

    service = make_service()
    snapshot = completed_snapshot(
        service, event_id, chunk_size=10,
        redact_restricted_cases=True, restricted_case_ids=None,
    )
    page = service.events_page(snapshot["id"], limit=10, offset=0, reveal=False)
    entry = next(item for item in page["items"] if item["event_id"] == event_id)
    assert entry["restricted_case"] is True
    payload = entry["payload"]
    assert payload["reagency_id"]["redacted"] is True
    assert payload["reagency_id"]["label"] == "restricted_case"
    assert payload["after"]["redacted"] is True
    assert "RES-CASE-1" not in json.dumps(payload, ensure_ascii=False)

    # 原值视图仍可由有权者核对。
    revealed = service.events_page(snapshot["id"], limit=10, offset=0, reveal=True)
    raw = next(item for item in revealed["items"] if item["event_id"] == event_id)["payload"]
    assert raw["after"]["case_no"] == "RES-CASE-1"
    assert service.verify(snapshot["id"])["ok"] is True


def test_bundle_verifies_independently_and_detects_reorder_insert(client):
    ids = seed_events(6)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1], chunk_size=2)
    secret = service.repository.archive_secret("2026-10-01T09:00:00+00:00")

    bundle = service.export_bundle(snapshot["id"], profile="canonical")
    assert ArchiveService.verify_bundle(bundle)["ok"] is True
    assert ArchiveService.verify_bundle(bundle, secret=secret)["ok"] is True

    # 字段被改动：原值摘要校验失败。
    tampered = json.loads(json.dumps(bundle))
    tampered["events"][0]["canonical"]["action"] = "forged"
    result = ArchiveService.verify_bundle(tampered)
    assert result["ok"] is False
    assert any("原值摘要不匹配" in error for error in result["errors"])

    # 重排：交换两个事件的位置，连续摘要断裂。
    reordered = json.loads(json.dumps(bundle))
    reordered["events"][0], reordered["events"][1] = reordered["events"][1], reordered["events"][0]
    result = ArchiveService.verify_bundle(reordered)
    assert result["ok"] is False
    assert any("连续摘要断裂" in error for error in result["errors"])

    # 插入：伪造一条事件，块摘要与根摘要都无法对上。
    inserted = json.loads(json.dumps(bundle))
    forged = dict(inserted["events"][0])
    forged["event_id"] = 99999
    forged["seq"] = 1
    inserted["events"].insert(0, forged)
    result = ArchiveService.verify_bundle(inserted)
    assert result["ok"] is False

    # 错误密钥无法验证脱敏承诺。
    bad = ArchiveService.verify_bundle(bundle, secret="wrong-secret")
    assert bad["ok"] is False
    assert any("脱敏结果或承诺与策略不符" in error for error in bad["errors"])

    # manifest/redacted 剖面同样自洽可验。
    for profile in ("manifest", "redacted"):
        other = service.export_bundle(snapshot["id"], profile=profile)
        assert ArchiveService.verify_bundle(other)["ok"] is True


def test_trace_returns_live_event_without_mutating_state(client):
    ids = seed_events(2)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1])
    trace = service.trace_event(snapshot["id"], ids[0], reveal=False)
    assert trace["live_exists"] is True
    assert trace["digest_match"] is True
    assert trace["read_only"] is True
    assert trace["live_event"]["id"] == ids[0]
    assert trace["live_event"]["after"]["phone"] != "13800138000"

    missing = service.trace_event(snapshot["id"], ids[0], reveal=True)
    assert missing["live_event"]["after"]["phone"] == "13800138000"


def test_manifest_signature_detects_wholesale_rewrite(client):
    ids = seed_events(4)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1], chunk_size=2)
    secret = service.repository.archive_secret("2026-10-01T09:00:00+00:00")

    verify = service.verify(snapshot["id"])
    assert verify["ok"] is True
    signature_check = next(c for c in verify["checks"] if c["name"] == "manifest_signature")
    assert signature_check["ok"] is True

    # 整体重写尝试：删除线上事件及对应清单条目。
    # 不重算摘要时，事件数与分块链立即暴露；即便重算，没有封存密钥也无法伪造根签名。
    connection = get_connection()
    victim = ids[1]
    connection.execute("DELETE FROM audit_events WHERE id=?", (victim,))
    connection.execute("DELETE FROM audit_archive_events WHERE snapshot_id=? AND event_id=?", (snapshot["id"], victim))
    result = service.verify(snapshot["id"])
    assert result["ok"] is False
    failed = {c["name"] for c in result["checks"] if not c["ok"]}
    assert {"range_count", "chunk_chain"} <= failed

    # 签名只对密钥持有者有意义：错误密钥无法通过签名校验，正确密钥可以。
    fake_signature = sign("wrong-secret", snapshot["snapshot_code"], snapshot["manifest_digest"])
    assert not constant_time_equals(fake_signature, snapshot["manifest_signature"])
    assert constant_time_equals(
        sign(secret, snapshot["snapshot_code"], snapshot["manifest_digest"]),
        snapshot["manifest_signature"],
    )

    # 导出包层面：攻击者删除一条事件并重算全部公开摘要（无密钥），
    # manifest_root 能对上重算值，但 manifest_signature 必然暴露。
    from app.archives.hashing import GENESIS_DIGEST
    bundle = service.export_bundle(snapshot["id"], profile="redacted")
    bundle["events"] = [
        item for item in bundle["events"] if item["event_id"] != victim
    ]
    previous_chunk = GENESIS_DIGEST
    for chunk in sorted(bundle["chunks"], key=lambda c: c["seq"]):
        members = [e for e in bundle["events"] if e["chunk_seq"] == chunk["seq"]]
        previous_entry = GENESIS_DIGEST
        for offset, item in enumerate(members):
            payload = {
                "seq": offset + 1,
                "event_id": item["event_id"],
                "event_digest": item["event_digest"],
                "redacted_digest": digest(item["redacted"]),
                "redaction_count": item["redaction_count"],
            }
            item["entry_digest"] = chain_digest(previous_entry, payload)
            previous_entry = item["entry_digest"]
        chunk["event_count"] = len(members)
        chunk["event_entry_digest"] = previous_entry
        chunk_payload = {
            "schema": "audit-archive-chunk/v1", "seq": chunk["seq"],
            "start_event_id": members[0]["event_id"], "end_event_id": members[-1]["event_id"],
            "event_count": len(members),
            "first_event_digest": members[0]["event_digest"],
            "last_event_digest": members[-1]["event_digest"],
            "event_entry_digest": previous_entry,
        }
        previous_chunk = chain_digest(previous_chunk, chunk_payload)
        chunk["chunk_digest"] = previous_chunk
    forged_manifest = {
        "schema": "audit-archive-manifest/v1",
        "snapshot_code": bundle["snapshot"]["snapshot_code"],
        "fingerprint": bundle["snapshot"]["fingerprint"],
        "total_events": len(bundle["events"]), "total_chunks": len(bundle["chunks"]),
        "last_chunk_digest": previous_chunk,
    }
    bundle["snapshot"]["manifest_digest"] = digest(forged_manifest)
    with_secret = ArchiveService.verify_bundle(bundle, secret=secret)
    assert any(c["name"] == "manifest_signature" and not c["ok"] for c in with_secret["checks"])


def test_chunk_chain_construction_details(client):
    ids = seed_events(3)
    service = make_service()
    snapshot = completed_snapshot(service, ids[-1], chunk_size=1)
    chunks = service.list_chunks(snapshot["id"])
    assert [c["seq"] for c in chunks] == [0, 1, 2]
    # 首块以前置常量开头，后续块绑定前一块摘要。
    payload = {
        "schema": "audit-archive-chunk/v1",
        "seq": 1,
        "start_event_id": chunks[1]["start_event_id"],
        "end_event_id": chunks[1]["end_event_id"],
        "event_count": chunks[1]["event_count"],
        "first_event_digest": chunks[1]["first_event_digest"],
        "last_event_digest": chunks[1]["last_event_digest"],
        "event_entry_digest": chunks[1]["event_entry_digest"],
    }
    assert chain_digest(chunks[0]["chunk_digest"], payload) == chunks[1]["chunk_digest"]
    # 首块以创世常量为前置，换成错误前置摘要必然不匹配。
    assert chain_digest("deadbeef", {**payload, "seq": 0}) != chunks[0]["chunk_digest"]
