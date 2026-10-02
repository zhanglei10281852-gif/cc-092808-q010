"""审计事件的规范化与按策略脱敏。

规范化固定字段集合（而非直接哈希库内 JSON 文本），因此任何字段的增删改
都会改变事件摘要。脱敏只"标记不删除"：被隐藏的值替换为带承诺（HMAC）的
标记，标记本身参与摘要，未授权者看不到原值，持有快照封存密钥的复核者仍
可验证原值。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterator

from app.archives.hashing import field_hmac
from app.core.privacy import mask_email, mask_id_card, mask_phone, sanitize_text

POLICY_SCHEMA = "audit-archive-policy/v1"
SCOPE_SCHEMA = "audit-archive-scope/v1"
EVENT_SCHEMA = "audit-event/v1"

REDACT = "redact"
NONE = "none"

# 与 app.repositories.audit.SENSITIVE_KEYS 保持一致，覆盖令牌/密钥类字段。
TOKEN_KEYS = {"password", "password_hash", "token", "token_digest", "secret", "authorization"}
CONTACT_KEYS = {"phone", "contact", "mobile", "email", "id_card", "identity_number"}
ID_CARD_KEYS = {"id_card", "identity_number"}
EMAIL_KEYS = {"email"}

# reagency_id 指向受限案件的业务资源类型。
CASE_RESOURCE_TYPES = {
    "forensic_case",
    "case",
    "case_event",
    "specimen",
    "custody_event",
    "examination",
    "release_request",
    "quality_alert",
}

CANONICAL_FIELDS = (
    "schema",
    "id",
    "actor_user_id",
    "actor_name",
    "action",
    "resource_type",
    "reagency_id",
    "outcome",
    "before",
    "after",
    "metadata",
    "correlation_id",
    "created_at",
)


def parse_json_field(raw: str | None) -> Any:
    return json.loads(raw) if raw is not None else None


def normalize_event(row: dict[str, Any]) -> dict[str, Any]:
    """把数据库行转换为字段集合固定的规范化事件。"""
    return {
        "schema": EVENT_SCHEMA,
        "id": int(row["id"]),
        "actor_user_id": row["actor_user_id"],
        "actor_name": row["actor_name"],
        "action": row["action"],
        "resource_type": row["resource_type"],
        "reagency_id": row["reagency_id"],
        "outcome": row["outcome"],
        "before": parse_json_field(row["before_json"]),
        "after": parse_json_field(row["after_json"]),
        "metadata": parse_json_field(row["metadata_json"]) or {},
        "correlation_id": row["correlation_id"],
        "created_at": row["created_at"],
    }


def freeze_policy(
    *,
    redact_tokens: bool,
    redact_contacts: bool,
    redact_restricted_cases: bool,
    restricted_case_ids: list[int],
) -> dict[str, Any]:
    """把管理员选择固化为参与指纹的策略对象（排序、无易变字段）。"""
    return {
        "schema": POLICY_SCHEMA,
        "token_fields": REDACT if redact_tokens else NONE,
        "contact_fields": REDACT if redact_contacts else NONE,
        "restricted_cases": REDACT if redact_restricted_cases else NONE,
        "restricted_case_ids": sorted(set(int(case_id) for case_id in restricted_case_ids)),
    }


def freeze_scope(*, end_event_id: int, created_before: str) -> dict[str, Any]:
    return {
        "schema": SCOPE_SCHEMA,
        "start_event_id": 1,
        "end_event_id": int(end_event_id),
        "created_before": created_before,
    }


@dataclass(frozen=True, slots=True)
class RedactionPoint:
    ref: str
    label: str


def _mark(secret: str, points: list[RedactionPoint], event_id: int, path: str, label: str, original: Any, **extra: Any) -> dict[str, Any]:
    ref = f"{event_id}#/{path}"
    points.append(RedactionPoint(ref=ref, label=label))
    mark: dict[str, Any] = {
        "redacted": True,
        "ref": ref,
        "label": label,
        "commit": field_hmac(secret, ref, original),
    }
    mark.update(extra)
    return mark


def _mask_contact(key: str, value: str) -> str:
    lowered = key.casefold()
    if lowered in EMAIL_KEYS or "@" in value:
        return mask_email(value) or value
    if lowered in ID_CARD_KEYS:
        return mask_id_card(value) or value
    return mask_phone(value) or value


def _walk(
    value: Any,
    *,
    secret: str,
    event_id: int,
    path: str,
    policy: dict[str, Any],
    points: list[RedactionPoint],
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path}/{key}"
            lowered = key.casefold()
            if policy["token_fields"] == REDACT and lowered in TOKEN_KEYS:
                result[key] = _mark(secret, points, event_id, child_path, "token", item)
            elif policy["contact_fields"] == REDACT and lowered in CONTACT_KEYS and isinstance(item, str):
                result[key] = _mark(
                    secret, points, event_id, child_path, "contact", item,
                    masked=_mask_contact(key, item),
                )
            else:
                result[key] = _walk(
                    item, secret=secret, event_id=event_id, path=child_path, policy=policy, points=points
                )
        return result
    if isinstance(value, list):
        return [
            _walk(item, secret=secret, event_id=event_id, path=f"{path}/{index}", policy=policy, points=points)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and policy["contact_fields"] == REDACT:
        sanitized = sanitize_text(value)
        if sanitized != value:
            return _mark(
                secret, points, event_id, path, "contact_embedded", value, masked=sanitized
            )
    return value


def build_redacted_view(
    event: dict[str, Any],
    policy: dict[str, Any],
    *,
    secret: str,
) -> tuple[dict[str, Any], list[RedactionPoint]]:
    """按策略生成脱敏视图；返回视图与脱敏点（标记与点一一对应）。"""
    event_id = int(event["id"])
    points: list[RedactionPoint] = []
    view = {field: event[field] for field in CANONICAL_FIELDS}
    restricted = (
        policy["restricted_cases"] == REDACT
        and event["resource_type"] in CASE_RESOURCE_TYPES
        and event["reagency_id"] is not None
        and int(event["reagency_id"]) in set(policy["restricted_case_ids"])
    )
    view["restricted_case"] = restricted
    if restricted:
        # 受限案件：整体隐藏业务载荷与案件标识，元数据仍按字段策略处理。
        if view["reagency_id"] is not None:
            view["reagency_id"] = _mark(secret, points, event_id, "reagency_id", "restricted_case", event["reagency_id"])
        for container in ("before", "after"):
            view[container] = (
                _mark(secret, points, event_id, container, "restricted_case", event[container])
                if event[container] is not None
                else None
            )
        view["metadata"] = _walk(
            view["metadata"], secret=secret, event_id=event_id, path="metadata", policy=policy, points=points
        )
    else:
        for container in ("before", "after", "metadata"):
            view[container] = _walk(
                view[container], secret=secret, event_id=event_id, path=container, policy=policy, points=points
            )
    return view, points


def iter_redaction_marks(node: Any) -> Iterator[dict[str, Any]]:
    """遍历视图，产出所有脱敏标记（供导出与无密钥校验使用）。"""
    if isinstance(node, dict):
        if node.get("redacted") is True:
            yield node
        for value in node.values():
            yield from iter_redaction_marks(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_redaction_marks(item)
