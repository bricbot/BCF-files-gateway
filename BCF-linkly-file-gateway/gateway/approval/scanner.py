"""文件扫描逻辑：递归扫描源目录，支持四种协议。"""

from __future__ import annotations

import time
from pathlib import Path

from .models import _connect
from .mounts import create_adapter, FileInfo


# 状态目录名称
STATUS_DIRS = (".accepted", ".rejected", ".exception", ".review")


def scan_task_source(
    db_path: Path,
    task_id: int,
    secret: str,
) -> dict:
    """扫描审批任务源目录中的文件，更新 file_records 表。

    返回 {"new": int, "removed": int, "total": int,
          "status_counts": {".accepted": int, ".rejected": int, ".exception": int, ".review": int}}。
    """
    from .tasks import get_task
    from .mounts import get_mount

    task = get_task(db_path, task_id)
    if task is None:
        return {"new": 0, "removed": 0, "total": 0, "status_counts": {}}

    source_mount = get_mount(db_path, task["source_mount_id"])
    if source_mount is None:
        return {"new": 0, "removed": 0, "total": 0, "status_counts": {}}

    try:
        adapter = create_adapter(source_mount, secret)
        files = adapter.list_files()
    except Exception:
        return {"new": 0, "removed": 0, "total": 0, "status_counts": {}}

    # 过滤掉非文件
    files = [f for f in files if not f.is_dir]

    # 统计状态目录中的文件数量
    status_counts = {}
    for sd in STATUS_DIRS:
        status_counts[sd] = 0
    try:
        all_items = adapter.list_files()
        for item in all_items:
            parts = Path(item.path).parts
            for sd in STATUS_DIRS:
                if sd in parts:
                    status_counts[sd] += 1
                    break
    except Exception:
        pass

    # 获取当前数据库中已有的记录
    with _connect(db_path) as conn:
        existing = conn.execute(
            "SELECT id, file_path, status FROM file_records WHERE task_id = ?",
            (task_id,),
        ).fetchall()
    existing_map = {r["file_path"]: dict(r) for r in existing}

    new_count = 0
    now = time.time()

    # 插入新文件
    with _connect(db_path) as conn:
        for f in files:
            if f.path not in existing_map:
                conn.execute(
                    """INSERT INTO file_records
                       (task_id, file_name, file_path, file_size, file_mtime, status, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
                    (task_id, f.name, f.path, f.size, f.mtime, now, now),
                )
                new_count += 1

    # 标记已不存在的文件为 removed
    removed_count = 0
    current_paths = {f.path for f in files}
    with _connect(db_path) as conn:
        for path, rec in existing_map.items():
            if path not in current_paths and rec["status"] == "pending":
                conn.execute(
                    "DELETE FROM file_records WHERE id = ? AND status = 'pending'",
                    (rec["id"],),
                )
                removed_count += 1

    # 统计总数
    with _connect(db_path) as conn:
        total = conn.execute(
            "SELECT COUNT(*) as cnt FROM file_records WHERE task_id = ?",
            (task_id,),
        ).fetchone()["cnt"]

    return {"new": new_count, "removed": removed_count, "total": total, "status_counts": status_counts}


def get_pending_files(db_path: Path, task_id: int) -> list[dict]:
    """获取任务中待审批的文件列表。"""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT fr.*, u.username as reviewer_name
               FROM file_records fr
               LEFT JOIN users u ON fr.reviewed_by = u.id
               WHERE fr.task_id = ? AND fr.status = 'pending'
               ORDER BY fr.file_path""",
            (task_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_reviewing_files(db_path: Path, task_id: int) -> list[dict]:
    """获取任务中复核入库的文件列表（高亮显示）。"""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT fr.*, rr.marked_by, rr.marked_at, rr.status as review_status,
                      u.username as marked_by_name
               FROM file_records fr
               JOIN review_records rr ON fr.id = rr.file_record_id
               LEFT JOIN users u ON rr.marked_by = u.id
               WHERE fr.task_id = ? AND rr.status = 'reviewing'
               ORDER BY rr.marked_at DESC""",
            (task_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_processed_files(
    db_path: Path, task_id: int, status: str | None = None, limit: int = 100
) -> list[dict]:
    """获取已处理的文件列表。"""
    conditions = ["task_id = ?"]
    params: list = [task_id]
    if status:
        conditions.append("status = ?")
        params.append(status)
    where = " AND ".join(conditions)
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT fr.*, u.username as reviewer_name
                FROM file_records fr
                LEFT JOIN users u ON fr.reviewed_by = u.id
                WHERE {where}
                ORDER BY fr.updated_at DESC
                LIMIT ?""",
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows]
