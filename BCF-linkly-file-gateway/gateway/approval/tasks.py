"""审批任务 CRUD。"""

from __future__ import annotations

import time
from pathlib import Path

from .models import _connect


def create_task(
    db_path: Path,
    name: str,
    description: str | None,
    source_mount_id: int,
    target_mount_id: int,
    task_type: str,
    end_time: float | None,
    assignee_ids: list[int],
    created_by: int,
) -> int:
    """创建审批任务，返回 task_id。"""
    now = time.time()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO approval_tasks
               (name, description, source_mount_id, target_mount_id, task_type,
                end_time, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, description, source_mount_id, target_mount_id, task_type,
             end_time, created_by, now, now),
        )
        task_id = cursor.lastrowid
        for uid in assignee_ids:
            conn.execute(
                "INSERT INTO task_assignees (task_id, user_id, assigned_at) VALUES (?, ?, ?)",
                (task_id, uid, now),
            )
        return task_id


def get_task(db_path: Path, task_id: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT t.*, sm.name as source_name, tm.name as target_name
               FROM approval_tasks t
               LEFT JOIN mounts sm ON t.source_mount_id = sm.id
               LEFT JOIN mounts tm ON t.target_mount_id = tm.id
               WHERE t.id = ?""",
            (task_id,),
        ).fetchone()
    if row is None:
        return None
    task = dict(row)
    # 加载审批人
    with _connect(db_path) as conn:
        assignees = conn.execute(
            """SELECT u.id, u.username, u.nickname
               FROM task_assignees ta
               JOIN users u ON ta.user_id = u.id
               WHERE ta.task_id = ?""",
            (task_id,),
        ).fetchall()
    task["assignees"] = [dict(a) for a in assignees]
    return task


def list_tasks(
    db_path: Path,
    user_id: int | None = None,
    is_active: bool | None = None,
    task_type: str | None = None,
) -> list[dict]:
    """列出审批任务。user_id 不为空时只列出分配给该用户的任务。"""
    conditions = []
    params: list = []

    if is_active is not None:
        conditions.append("t.is_active = ?")
        params.append(1 if is_active else 0)
    if task_type:
        conditions.append("t.task_type = ?")
        params.append(task_type)
    if user_id is not None:
        conditions.append(
            """t.id IN (SELECT task_id FROM task_assignees WHERE user_id = ?)"""
        )
        params.append(user_id)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT t.*, sm.name as source_name, tm.name as target_name
                FROM approval_tasks t
                LEFT JOIN mounts sm ON t.source_mount_id = sm.id
                LEFT JOIN mounts tm ON t.target_mount_id = tm.id
                {where}
                ORDER BY t.created_at DESC""",
            params,
        ).fetchall()

    tasks = []
    for row in rows:
        task = dict(row)
        # 加载审批人
        with _connect(db_path) as conn2:
            assignees = conn2.execute(
                """SELECT u.id, u.username, u.nickname
                   FROM task_assignees ta
                   JOIN users u ON ta.user_id = u.id
                   WHERE ta.task_id = ?""",
                (task["id"],),
            ).fetchall()
        task["assignees"] = [dict(a) for a in assignees]
        # 统计文件数
        with _connect(db_path) as conn3:
            counts = conn3.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM file_records WHERE task_id = ?
                   GROUP BY status""",
                (task["id"],),
            ).fetchall()
        task["file_counts"] = {r["status"]: r["cnt"] for r in counts}
        tasks.append(task)
    return tasks


def update_task(db_path: Path, task_id: int, **kwargs) -> None:
    allowed = {"name", "description", "source_mount_id", "target_mount_id",
               "task_type", "end_time", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = time.time()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [task_id]
    with _connect(db_path) as conn:
        conn.execute(f"UPDATE approval_tasks SET {set_clause} WHERE id = ?", values)


def set_assignees(db_path: Path, task_id: int, assignee_ids: list[int]) -> None:
    """重新设置任务的审批人列表。"""
    now = time.time()
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM task_assignees WHERE task_id = ?", (task_id,))
        for uid in assignee_ids:
            conn.execute(
                "INSERT INTO task_assignees (task_id, user_id, assigned_at) VALUES (?, ?, ?)",
                (task_id, uid, now),
            )


def delete_task(db_path: Path, task_id: int) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM task_assignees WHERE task_id = ?", (task_id,))
        conn.execute("DELETE FROM file_records WHERE task_id = ?", (task_id,))
        conn.execute("DELETE FROM review_records WHERE task_id = ?", (task_id,))
        conn.execute("DELETE FROM transfer_queue WHERE task_id = ?", (task_id,))
        conn.execute("DELETE FROM approval_tasks WHERE id = ?", (task_id,))


def get_tasks_for_user(db_path: Path, user_id: int) -> list[dict]:
    """获取分配给指定用户的所有活跃任务。"""
    return list_tasks(db_path, user_id=user_id, is_active=True)
