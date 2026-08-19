"""异步传输队列：后台 worker 处理文件传输。"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
from datetime import datetime
from pathlib import Path

from .models import _connect, get_config
from .mounts import create_adapter
from .tasks import get_task
from .mounts import get_mount

logger = logging.getLogger(__name__)


class TransferWorker:
    """后台文件传输 worker。"""

    def __init__(self, db_path: Path, secret: str):
        self.db_path = db_path
        self.secret = secret
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """启动 worker 循环。"""
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("TransferWorker started")

    async def stop(self) -> None:
        """停止 worker。"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("TransferWorker stopped")

    async def _loop(self) -> None:
        while self._running:
            try:
                await self._process_next()
            except Exception:
                logger.exception("Transfer worker error")
            await asyncio.sleep(1)

    async def _process_next(self) -> None:
        """处理队列中的下一个待处理任务。"""
        max_concurrent = int(get_config(self.db_path, "max_concurrent_transfers", "3"))

        with _connect(self.db_path) as conn:
            # 检查当前正在处理的任务数
            active = conn.execute(
                "SELECT COUNT(*) as cnt FROM transfer_queue WHERE status = 'processing'"
            ).fetchone()["cnt"]
            if active >= max_concurrent:
                return

            # 取一个待处理任务
            row = conn.execute(
                """SELECT * FROM transfer_queue
                   WHERE status = 'pending'
                   ORDER BY created_at ASC LIMIT 1"""
            ).fetchone()
            if row is None:
                return

            queue_id = row["id"]
            conn.execute(
                "UPDATE transfer_queue SET status = 'processing', started_at = ? WHERE id = ?",
                (time.time(), queue_id),
            )

        # 在线程池中执行传输（避免阻塞事件循环）
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._do_transfer, queue_id)

    def _do_transfer(self, queue_id: int) -> None:
        """执行单个文件传输。"""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM transfer_queue WHERE id = ?", (queue_id,)
            ).fetchone()
            if row is None:
                return
            queue_item = dict(row)

        action = queue_item["action"]
        file_record_id = queue_item["file_record_id"]
        task_id = queue_item["task_id"]

        task = get_task(self.db_path, task_id)
        if task is None:
            self._fail_queue(queue_id, "任务不存在")
            return

        source_mount = get_mount(self.db_path, task["source_mount_id"])
        target_mount = get_mount(self.db_path, task["target_mount_id"])
        if source_mount is None or target_mount is None:
            self._fail_queue(queue_id, "挂载点配置错误")
            return

        try:
            src_adapter = create_adapter(source_mount, self.secret)
            tgt_adapter = create_adapter(target_mount, self.secret)
        except Exception as e:
            self._fail_queue(queue_id, f"创建适配器失败: {e}")
            return

        src_path = queue_item["source_path"]
        max_retries = int(get_config(self.db_path, "max_retry_count", "1"))

        # 尝试传输
        success = False
        last_error = ""
        for attempt in range(max_retries + 1):
            try:
                if action == "accept":
                    # 1. 从源挂载下载到本地临时文件
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                    try:
                        src_adapter.copy_file(src_path, tmp_path)
                        # 2. 从本地临时文件上传到目标挂载
                        tgt_adapter.upload_file(tmp_path, src_path)
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    # 3. 将源文件移动到 .accepted 目录
                    src_adapter.move_to_status_dir(src_path, ".accepted")
                elif action == "reject":
                    # 移动到 .rejected 目录
                    src_adapter.move_to_status_dir(src_path, ".rejected")
                    # 写入拒绝原因
                    self._write_reject_reason(src_adapter, src_path, queue_item)
                elif action == "review":
                    # 移动到 .review 目录
                    src_adapter.move_to_status_dir(src_path, ".review")
                success = True
                break
            except Exception as e:
                last_error = str(e)
                logger.warning("Transfer attempt %d failed for %s: %s", attempt + 1, src_path, e)
                if attempt < max_retries:
                    with _connect(self.db_path) as conn:
                        conn.execute(
                            "UPDATE transfer_queue SET retry_count = retry_count + 1 WHERE id = ?",
                            (queue_id,),
                        )

        now = time.time()
        if success:
            with _connect(self.db_path) as conn:
                conn.execute(
                    """UPDATE transfer_queue SET status = 'completed', completed_at = ?
                       WHERE id = ?""",
                    (now, queue_id),
                )
                if action == "accept":
                    conn.execute(
                        "UPDATE file_records SET status = 'transferred', updated_at = ? WHERE id = ?",
                        (now, file_record_id),
                    )
                elif action == "reject":
                    conn.execute(
                        "UPDATE file_records SET status = 'rejected', updated_at = ? WHERE id = ?",
                        (now, file_record_id),
                    )
            logger.info("Transfer completed: %s -> %s", src_path, action)
        else:
            # 传输失败，移动到 .exception 目录
            try:
                src_adapter.move_to_status_dir(src_path, ".exception")
            except Exception:
                pass
            # 写入异常日志
            self._write_exception_log(src_adapter, src_path, last_error)
            with _connect(self.db_path) as conn:
                conn.execute(
                    """UPDATE transfer_queue SET status = 'failed', completed_at = ?,
                       error_log = ? WHERE id = ?""",
                    (now, last_error, queue_id),
                )
                conn.execute(
                    "UPDATE file_records SET status = 'exception', updated_at = ? WHERE id = ?",
                    (now, file_record_id),
                )
            logger.error("Transfer failed permanently: %s - %s", src_path, last_error)

    def _write_reject_reason(self, adapter, src_path: str, queue_item: dict) -> None:
        """写入拒绝原因文件。"""
        with _connect(self.db_path) as conn:
            fr = conn.execute(
                "SELECT reject_reason FROM file_records WHERE id = ?",
                (queue_item["file_record_id"],),
            ).fetchone()
        reason = fr["reject_reason"] if fr else ""
        if not reason:
            return
        base_name = Path(src_path).stem
        reason_file = f"{base_name}-rej_reason.txt"
        reason_path = str(Path(src_path).parent / reason_file)
        try:
            adapter.write_text_file(reason_path, reason)
        except Exception:
            logger.warning("Failed to write reject reason file for %s", src_path)

    def _write_exception_log(self, adapter, src_path: str, error: str) -> None:
        """写入异常日志文件。"""
        base_name = Path(src_path).stem
        log_file = f"{base_name}-exception.txt"
        log_path = str(Path(src_path).parent / log_file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_content = f"[{timestamp}] {error}\n{traceback.format_exc()}\n"
        try:
            adapter.write_text_file(log_path, log_content)
        except Exception:
            logger.warning("Failed to write exception log for %s", src_path)

    def _fail_queue(self, queue_id: int, error: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                """UPDATE transfer_queue SET status = 'failed', error_log = ?,
                   completed_at = ? WHERE id = ?""",
                (error, time.time(), queue_id),
            )


# ── 传输队列查询 API ──

def get_queue_items(
    db_path: Path,
    user_id: int | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """查询传输队列。"""
    conditions = []
    params: list = []
    if user_id is not None:
        conditions.append("tq.created_by = ?")
        params.append(user_id)
    if status:
        conditions.append("tq.status = ?")
        params.append(status)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    params.extend([limit])

    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT tq.*, fr.file_name, t.name as task_name, u.username as creator_name
                FROM transfer_queue tq
                LEFT JOIN file_records fr ON tq.file_record_id = fr.id
                LEFT JOIN approval_tasks t ON tq.task_id = t.id
                LEFT JOIN users u ON tq.created_by = u.id
                {where}
                ORDER BY tq.created_at DESC
                LIMIT ?""",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def pause_transfer(db_path: Path, queue_id: int) -> bool:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM transfer_queue WHERE id = ?", (queue_id,)
        ).fetchone()
        if row is None or row["status"] not in ("pending", "processing"):
            return False
        conn.execute(
            "UPDATE transfer_queue SET status = 'paused' WHERE id = ?", (queue_id,)
        )
    return True


def resume_transfer(db_path: Path, queue_id: int) -> bool:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM transfer_queue WHERE id = ?", (queue_id,)
        ).fetchone()
        if row is None or row["status"] != "paused":
            return False
        conn.execute(
            "UPDATE transfer_queue SET status = 'pending' WHERE id = ?", (queue_id,)
        )
    return True


def cancel_transfer(db_path: Path, queue_id: int) -> bool:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT status FROM transfer_queue WHERE id = ?", (queue_id,)
        ).fetchone()
        if row is None or row["status"] in ("completed", "failed", "cancelled"):
            return False
        conn.execute(
            "UPDATE transfer_queue SET status = 'cancelled', completed_at = ? WHERE id = ?",
            (time.time(), queue_id),
        )
    return True
