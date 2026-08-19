"""审计日志记录与查询。"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .models import _connect


def log_action(
    db_path: Path,
    user_id: int | None,
    action: str,
    resource_type: str | None = None,
    resource_id: int | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """记录一条审计日志。"""
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO audit_logs
               (user_id, action, resource_type, resource_id, detail, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                action,
                resource_type,
                resource_id,
                json.dumps(detail, ensure_ascii=False) if detail else None,
                ip_address,
                time.time(),
            ),
        )


def get_logs(
    db_path: Path,
    user_id: int | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """查询审计日志，支持按用户/操作/资源类型过滤。"""
    conditions = []
    params: list = []
    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)
    if action is not None:
        conditions.append("action = ?")
        params.append(action)
    if resource_type is not None:
        conditions.append("resource_type = ?")
        params.append(resource_type)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.extend([limit, offset])

    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT a.*, u.username, u.nickname
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                {where}
                ORDER BY a.created_at DESC
                LIMIT ? OFFSET ?""",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def count_logs(
    db_path: Path,
    user_id: int | None = None,
    action: str | None = None,
    resource_type: str | None = None,
) -> int:
    """统计日志总数。"""
    conditions = []
    params: list = []
    if user_id is not None:
        conditions.append("user_id = ?")
        params.append(user_id)
    if action is not None:
        conditions.append("action = ?")
        params.append(action)
    if resource_type is not None:
        conditions.append("resource_type = ?")
        params.append(resource_type)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM audit_logs{where}", params
        ).fetchone()
    return row["cnt"]
