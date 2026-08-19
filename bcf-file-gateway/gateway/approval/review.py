"""文件审批操作：批准/拒绝/复核/撤回。"""

from __future__ import annotations

import time
from pathlib import Path

from .models import _connect


def approve_files(
    db_path: Path,
    file_ids: list[int],
    user_id: int,
) -> int:
    """批准文件入库，将文件加入传输队列。返回加入队列的数量。"""
    now = time.time()
    count = 0
    with _connect(db_path) as conn:
        for fid in file_ids:
            row = conn.execute(
                "SELECT * FROM file_records WHERE id = ? AND status = 'pending'",
                (fid,),
            ).fetchone()
            if row is None:
                continue
            # 更新文件状态
            conn.execute(
                """UPDATE file_records SET status = 'approved', reviewed_by = ?,
                   reviewed_at = ?, updated_at = ? WHERE id = ?""",
                (user_id, now, now, fid),
            )
            # 获取任务信息
            task = conn.execute(
                "SELECT * FROM approval_tasks WHERE id = ?", (row["task_id"],)
            ).fetchone()
            # 加入传输队列
            conn.execute(
                """INSERT INTO transfer_queue
                   (file_record_id, task_id, action, status, source_path, target_path,
                    created_by, created_at)
                   VALUES (?, ?, 'accept', 'pending', ?, ?, ?, ?)""",
                (fid, row["task_id"], row["file_path"], row["file_path"], user_id, now),
            )
            count += 1
    return count


def reject_files(
    db_path: Path,
    file_ids: list[int],
    user_id: int,
    reject_reason: str = "",
) -> int:
    """拒绝文件入库。批量拒绝时附加【批拒：时间戳】。返回处理数量。"""
    now = time.time()
    count = 0
    is_batch = len(file_ids) > 1

    with _connect(db_path) as conn:
        for fid in file_ids:
            row = conn.execute(
                "SELECT * FROM file_records WHERE id = ? AND status = 'pending'",
                (fid,),
            ).fetchone()
            if row is None:
                continue

            # 构建拒绝原因
            reason = reject_reason
            if is_batch and reason:
                reason = f"{reason}【批拒：{int(now)}】"

            # 更新文件状态
            conn.execute(
                """UPDATE file_records SET status = 'rejected', reviewed_by = ?,
                   reviewed_at = ?, reject_reason = ?, updated_at = ? WHERE id = ?""",
                (user_id, now, reason, now, fid),
            )
            # 加入传输队列（移动到 .rejected 目录）
            conn.execute(
                """INSERT INTO transfer_queue
                   (file_record_id, task_id, action, status, source_path, target_path,
                    created_by, created_at)
                   VALUES (?, ?, 'reject', 'pending', ?, ?, ?, ?)""",
                (fid, row["task_id"], row["file_path"], row["file_path"], user_id, now),
            )
            count += 1
    return count


def mark_for_review(
    db_path: Path,
    file_ids: list[int],
    user_id: int,
) -> int:
    """将文件标记为复核入库。返回处理数量。"""
    now = time.time()
    count = 0
    with _connect(db_path) as conn:
        for fid in file_ids:
            row = conn.execute(
                "SELECT * FROM file_records WHERE id = ? AND status = 'pending'",
                (fid,),
            ).fetchone()
            if row is None:
                continue
            # 更新文件状态
            conn.execute(
                """UPDATE file_records SET status = 'reviewing', reviewed_by = ?,
                   reviewed_at = ?, updated_at = ? WHERE id = ?""",
                (user_id, now, now, fid),
            )
            # 创建复核记录
            conn.execute(
                """INSERT INTO review_records
                   (file_record_id, task_id, marked_by, marked_at, status, created_at)
                   VALUES (?, ?, ?, ?, 'reviewing', ?)""",
                (fid, row["task_id"], user_id, now, now),
            )
            count += 1
    return count


def withdraw_review(
    db_path: Path,
    file_ids: list[int],
    user_id: int,
    reason: str,
) -> int:
    """撤回复核入库标记，必须填写撤回理由。返回处理数量。"""
    if not reason.strip():
        raise ValueError("撤回复核必须填写撤回理由")
    now = time.time()
    count = 0
    with _connect(db_path) as conn:
        for fid in file_ids:
            # 检查是否是复核状态
            rr = conn.execute(
                """SELECT * FROM review_records
                   WHERE file_record_id = ? AND status = 'reviewing'""",
                (fid,),
            ).fetchone()
            if rr is None:
                continue
            # 更新复核记录
            conn.execute(
                """UPDATE review_records SET status = 'withdrawn',
                   withdrawn_by = ?, withdrawn_at = ?, withdraw_reason = ?
                   WHERE id = ?""",
                (user_id, now, reason, rr["id"]),
            )
            # 恢复文件为待审批状态
            conn.execute(
                """UPDATE file_records SET status = 'pending', reviewed_by = NULL,
                   reviewed_at = NULL, updated_at = ? WHERE id = ?""",
                (now, fid),
            )
            count += 1
    return count


def get_file_detail(db_path: Path, file_id: int) -> dict | None:
    """获取文件详情。"""
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT fr.*, t.name as task_name, u.username as reviewer_name
               FROM file_records fr
               JOIN approval_tasks t ON fr.task_id = t.id
               LEFT JOIN users u ON fr.reviewed_by = u.id
               WHERE fr.id = ?""",
            (file_id,),
        ).fetchone()
    return dict(row) if row else None
