"""SQLite 记录链接创建历史，按本地时区自然日限制每用户创建次数。

MCP 与 HTTP 是两个进程，各自打开连接访问同一个库文件（WAL 模式），
因此每次操作都新建短连接，避免跨线程/跨进程复用连接。
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from pathlib import Path

RETENTION_DAYS = 30


class QuotaExceededError(Exception):
    """用户当日创建额度已用完。"""

    def __init__(self, user_id: str, used: int, limit: int):
        self.user_id = user_id
        self.used = used
        self.limit = limit
        super().__init__(f"用户 {user_id} 今日额度已用完（{used}/{limit} 次/天）")


def _today_start_ts() -> float:
    now = datetime.now()
    return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


class QuotaDB:
    def __init__(self, db_path: Path, daily_limit: int):
        self.db_path = db_path
        self.daily_limit = daily_limit
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS link_records (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    file_path TEXT,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_records_user_time"
                " ON link_records (user_id, created_at)"
            )
            # 下载链接 token 映射表：token -> (path, exp)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS link_tokens (
                    token TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            cutoff = time.time() - RETENTION_DAYS * 86400
            conn.execute("DELETE FROM link_records WHERE created_at < ?", (cutoff,))
            # 清理过期 token
            conn.execute("DELETE FROM link_tokens WHERE expires_at < ?", (time.time(),))

    def count_today(self, user_id: str) -> int:
        with self._connect() as conn:
            (count,) = conn.execute(
                "SELECT COUNT(*) FROM link_records"
                " WHERE user_id = ? AND created_at >= ?",
                (user_id, _today_start_ts()),
            ).fetchone()
        return count

    def check_quota(self, user_id: str, bypass_quota: bool = False) -> int:
        """校验额度，超限抛出 QuotaExceededError，返回今日已用次数。
        
        bypass_quota=True 时跳过额度检查（开发者权限）。
        """
        used = self.count_today(user_id)
        if not bypass_quota and used >= self.daily_limit:
            raise QuotaExceededError(user_id, used, self.daily_limit)
        return used

    def record(self, user_id: str, file_path: str) -> None:
        """链接生成成功后记账。"""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO link_records (user_id, file_path, created_at)"
                " VALUES (?, ?, ?)",
                (user_id, file_path, time.time()),
            )

    def get_quota_info(self, user_id: str, bypass_quota: bool = False) -> dict:
        """纯查询用户额度信息，不扣减、不记账。
        
        bypass_quota=True 时返回 unlimited（开发者权限）。
        """
        used = self.count_today(user_id)
        if bypass_quota:
            return {
                "used": used,
                "remaining": -1,  # -1 表示无限
                "daily_limit": -1,
                "unlimited": True,
            }
        return {
            "used": used,
            "remaining": max(0, self.daily_limit - used),
            "daily_limit": self.daily_limit,
            "unlimited": False,
        }

    def create_link_token(self, token: str, file_path: str, expires_at: float) -> None:
        """存储下载链接 token 到文件路径的映射。"""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO link_tokens (token, file_path, expires_at) VALUES (?, ?, ?)",
                (token, file_path, expires_at),
            )

    def verify_link_token(self, token: str) -> tuple[str, float] | None:
        """验证 token 并返回 (file_path, expires_at)，不存在或已过期返回 None。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT file_path, expires_at FROM link_tokens WHERE token = ?",
                (token,),
            ).fetchone()
        if row is None:
            return None
        file_path, expires_at = row
        if expires_at < time.time():
            return None
        return file_path, expires_at
