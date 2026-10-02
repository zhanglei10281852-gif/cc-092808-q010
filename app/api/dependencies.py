from __future__ import annotations

from fastapi import Header

from app.core.errors import AuthenticationError
from app.core.security import Principal
from app.database import get_connection
from app.services.auth import AuthService


def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError("缺少 Bearer 会话令牌")
    token = authorization[7:].strip()
    if not token:
        raise AuthenticationError("会话令牌为空")
    connection = get_connection()
    principal = AuthService(connection).principal(token)
    # principal() 内部会顺带更新 last_seen_at（过期会话还会写 revoked_at）。
    # 这些写操作在 Python sqlite3 的延迟事务下会自动开启事务，若不提交，
    # 后续端点用保存点嵌套写入时永远不会真正落盘。依赖在端点业务之前执行，
    # 此刻事务只含会话簿记，提交它不会波及业务数据。
    if connection.in_transaction:
        connection.commit()
    return principal
