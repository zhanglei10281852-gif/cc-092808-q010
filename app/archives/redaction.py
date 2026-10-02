from __future__ import annotations

import hashlib
import hmac
from typing import Any

from app.archives.hasher import canonical_json
from app.core.privacy import mask_email, mask_id_card, mask_phone, sanitize_text

# 策略标识。改变策略必须产生新版本快照，旧归档保留不变。
POLICY_NONE = "none"          # 不额外脱敏（仍保留审计表既有的密钥剔除）
POLICY_STANDARD = "standard"  # 令牌/联系方式/受限案件按查看者权限脱敏
POLICY_STRICT = "strict"      # 在 standard 基础上对受限案件整段屏蔽

POLICIES = (POLICY_NONE, POLICY_STANDARD, POLICY_STRICT)

TOKEN_KEYS = {"token", "token_digest", "secret", "authorization", "api_key", "apikey"}
PHONE_KEYS = {"phone", "mobile", "contact", "telephone"}
IDCARD_KEYS = {"id_card", "identity_number"}
EMAIL_KEYS = {"email", "mail"}

ENVELOPE_ALGORITHM = "hmac-sha256+mask-v1"


class ReviewAuthority:
    """查看者权限：决定脱敏清单中哪些信封可以被打开复核。"""

    def __init__(self, *, can_review_tokens: bool = False, can_review_contacts: bool = False,
                 can_review_restricted: bool = False) -> None:
        self.can_review_tokens = can_review_tokens
        self.can_review_contacts = can_review_contacts
        self.can_review_restricted = can_review_restricted

    def can_open(self, category: str) -> bool:
        return {
            "token": self.can_review_tokens,
            "contact": self.can_review_contacts,
            "restricted_case": self.can_review_restricted,
        }.get(category, False)


def value_proof(category: str, original: Any, secret: bytes) -> str:
    """原值证据：HMAC(快照密钥, 类别||规范化原值)。

    不含密钥的读取方无法据此离线猜测原值；持有密钥的有权复核者可重算比对。
    """
    material = category.encode("ascii") + b"\x00" + canonical_json(original)
    return hmac.new(secret, material, hashlib.sha256).hexdigest()


def envelope_for(category: str, original: Any, masked: Any, secret: bytes) -> dict[str, Any]:
    """生成可复核信封：不存放原值，只存放掩码与密钥绑定的原值证据。"""
    return {
        "_redacted": ENVELOPE_ALGORITHM,
        "category": category,
        "masked": masked,
        "proof": value_proof(category, original, secret),
    }


def _mask_scalar(category: str, value: str) -> str:
    if category == "email":
        return mask_email(value) or "***"
    if category == "id_card":
        return mask_id_card(value) or "****"
    if category == "phone":
        return mask_phone(value) or "****"
    return "***"


def _text_category(value: str) -> str | None:
    import re

    from app.core.privacy import EMAIL_RE, ID_CARD_RE, PHONE_RE

    if PHONE_RE.search(value):
        return "phone"
    if ID_CARD_RE.search(value):
        return "id_card"
    if EMAIL_RE.search(value):
        return "email"
    return None


def _envelope_key_category(key: str) -> str | None:
    folded = key.casefold()
    if folded in TOKEN_KEYS:
        return "token"
    if folded in PHONE_KEYS:
        return "phone"
    if folded in IDCARD_KEYS:
        return "id_card"
    if folded in EMAIL_KEYS:
        return "email"
    if folded in {"address", "contact_address"}:
        return "address"
    return None


def apply_policy(value: Any, policy: str, secret: bytes) -> Any:
    """对一条已规范化事件的字段做脱敏，返回替换为信封后的结构。

    受限案件的整段屏蔽在服务层根据事件上下文单独处理，因此这里只做字段级脱敏。
    """
    if policy == POLICY_NONE:
        return value
    return _walk(value, secret)


def _walk(value: Any, secret: bytes) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            category = _envelope_key_category(key)
            if category == "token":
                result[key] = envelope_for("token", item, "***", secret) if item is not None else item
            elif category in {"phone", "id_card", "email", "address"} and isinstance(item, str) and item:
                masked = _mask_scalar(category, item) if category != "address" else "***"
                result[key] = envelope_for("contact", item, masked, secret)
            else:
                result[key] = _walk(item, secret)
        return result
    if isinstance(value, list):
        return [_walk(item, secret) for item in value]
    if isinstance(value, str):
        if _text_category(value) is not None:
            masked = sanitize_text(value)
            if masked != value:
                return envelope_for("contact", value, masked, secret)
        return value
    return value


def build_restricted_envelope(event: dict[str, Any], secret: bytes) -> dict[str, Any]:
    """strict 策略下受限案件事件的整段屏蔽信封。"""
    summary = {
        "action": event.get("action"),
        "resource_type": event.get("resource_type"),
        "reagency_id": event.get("reagency_id"),
        "outcome": event.get("outcome"),
        "created_at": event.get("created_at"),
    }
    return envelope_for("restricted_case", event, summary, secret)


def reveal_for_review(value: Any, authority: ReviewAuthority) -> Any:
    """按复核权限把信封渲染成可读形式（不返回原值，仅声明可否复核并给掩码）。"""
    if isinstance(value, dict):
        if set(value) >= {"_redacted", "category", "masked", "proof"}:
            category = str(value["category"])
            openable = authority.can_open(category)
            rendered = dict(value)
            rendered["review"] = "allowed" if openable else "masked"
            if not openable:
                # 无复核权限时连同密钥绑定证据一并隐去，避免泄露可离线枚举的线索。
                rendered.pop("proof", None)
            return rendered
        return {key: reveal_for_review(item, authority) for key, item in value.items()}
    if isinstance(value, list):
        return [reveal_for_review(item, authority) for item in value]
    return value


def verify_envelope(envelope: dict[str, Any], category: str, original: Any, secret: bytes) -> bool:
    """有权复核者用快照密钥验证某个原值与信封证据一致。"""
    if envelope.get("_redacted") != ENVELOPE_ALGORITHM or envelope.get("category") != category:
        return False
    expected = value_proof(category, original, secret)
    return hmac.compare_digest(expected, str(envelope.get("proof", "")))
