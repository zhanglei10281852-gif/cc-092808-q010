"""归档快照使用的稳定序列化与连续摘要原语。

所有摘要都基于规范化字节序列，保证同一数据无论何时、由谁重新计算，
得到的摘要完全一致；HMAC 仅用于对无复核权限者隐藏字段原值，不改变
公开摘要链的可校验性。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

ALGORITHM = "sha256"
GENESIS_DIGEST = "-"


def canonical_json(value: Any) -> bytes:
    """以排序键、无多余空白、不转义非 ASCII 的方式生成确定性字节。"""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    """对任意可 JSON 规范化的值计算 sha256（hex）。"""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def chain_digest(previous_digest: str, payload: Any) -> str:
    """把前一摘要与当前负载绑定：插入、删除、重排都会破坏后续链。"""
    return hashlib.sha256(previous_digest.encode("ascii") + b"\n" + canonical_json(payload)).hexdigest()


def field_hmac(secret: str, field_path: str, value: Any) -> str:
    """对脱敏字段原值计算带上下文的 HMAC，便于有权者复核而不泄露原值。"""
    message = canonical_json({"field": field_path, "value": value})
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign(secret: str, context: str, value: Any) -> str:
    """对摘要值计算带上下文的 HMAC 签名，供持密钥复核方识别整体重写。"""
    message = canonical_json({"context": context, "digest": value})
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def constant_time_equals(left: str | None, right: str | None) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left, right)
