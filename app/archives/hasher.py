from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64
FORMAT_VERSION = "forensics-archive/v1"


def canonical_json(value: Any) -> bytes:
    """确定性 JSON 编码：键排序、无空白、UTF-8，保证跨进程一致。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_payload(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def chain_digest(previous_digest: str, payload: Any) -> str:
    """把上一环节点与当前载荷连接起来：删除、插入、重排都会破坏后续摘要。"""
    material = previous_digest.encode("ascii") + b"\n" + canonical_json(payload)
    return hashlib.sha256(material).hexdigest()
