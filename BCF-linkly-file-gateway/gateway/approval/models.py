"""数据库 schema 初始化与通用连接管理。

所有审批模块的表结构在此创建和维护。
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn


def init_approval_schema(db_path: Path) -> None:
    """创建审批模块所需的全部表结构。"""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with _connect(db_path) as conn:
        # ── 用户与权限 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                nickname TEXT,
                role TEXT NOT NULL DEFAULT 'reviewer',
                is_active INTEGER DEFAULT 1,
                must_change_pwd INTEGER DEFAULT 0,
                created_at REAL,
                updated_at REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT,
                description TEXT,
                updated_at REAL
            )
        """)

        # ── 挂载点 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mounts (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                remote_path TEXT NOT NULL,
                username TEXT,
                password_enc TEXT,
                mount_type TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_by INTEGER REFERENCES users(id),
                created_at REAL,
                updated_at REAL
            )
        """)

        # ── 审批任务 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS approval_tasks (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                source_mount_id INTEGER REFERENCES mounts(id),
                target_mount_id INTEGER REFERENCES mounts(id),
                task_type TEXT NOT NULL,
                end_time REAL,
                is_active INTEGER DEFAULT 1,
                created_by INTEGER REFERENCES users(id),
                created_at REAL,
                updated_at REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_assignees (
                id INTEGER PRIMARY KEY,
                task_id INTEGER REFERENCES approval_tasks(id),
                user_id INTEGER REFERENCES users(id),
                assigned_at REAL,
                UNIQUE(task_id, user_id)
            )
        """)

        # ── 文件记录 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_records (
                id INTEGER PRIMARY KEY,
                task_id INTEGER REFERENCES approval_tasks(id),
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                file_mtime REAL,
                status TEXT DEFAULT 'pending',
                reviewed_by INTEGER REFERENCES users(id),
                reviewed_at REAL,
                reject_reason TEXT,
                created_at REAL,
                updated_at REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_file_records_task_status
            ON file_records (task_id, status)
        """)

        # ── 复核入库记录 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS review_records (
                id INTEGER PRIMARY KEY,
                file_record_id INTEGER REFERENCES file_records(id),
                task_id INTEGER REFERENCES approval_tasks(id),
                marked_by INTEGER REFERENCES users(id),
                marked_at REAL,
                withdrawn_by INTEGER REFERENCES users(id),
                withdrawn_at REAL,
                withdraw_reason TEXT,
                status TEXT DEFAULT 'reviewing',
                created_at REAL
            )
        """)

        # ── 传输队列 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transfer_queue (
                id INTEGER PRIMARY KEY,
                file_record_id INTEGER REFERENCES file_records(id),
                task_id INTEGER REFERENCES approval_tasks(id),
                action TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                source_path TEXT NOT NULL,
                target_path TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 1,
                error_log TEXT,
                started_at REAL,
                completed_at REAL,
                created_by INTEGER REFERENCES users(id),
                created_at REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_transfer_queue_status
            ON transfer_queue (status)
        """)

        # ── 审计日志 ──
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id INTEGER,
                detail TEXT,
                ip_address TEXT,
                created_at REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_user_time
            ON audit_logs (user_id, created_at)
        """)

        # ── 初始化默认配置 ──
        _init_default_config(conn)


# 默认系统配置
DEFAULT_CONFIGS: dict[str, tuple[str, str]] = {
    # key: (default_value, description)
    "scan_interval_minutes": ("10", "自动扫描间隔（分钟）"),
    "max_retry_count": ("1", "传输失败最大重试次数"),
    "max_files_per_task": ("10000", "单任务最大文件数"),
    "onetime_task_default_days": ("30", "一次性任务默认有效天数"),
    "password_min_length": ("8", "密码最小长度"),
    "password_require_special": ("false", "密码是否要求特殊字符"),
    "session_timeout_minutes": ("480", "登录会话超时（分钟）"),
    "max_concurrent_transfers": ("3", "同时传输并发数（建议不超过10）"),
    "max_upload_size_mb": ("500", "单文件大小上限（MB）"),
    "allowed_file_extensions": ("*", "允许的文件类型（*表示全部）"),
}


def _init_default_config(conn: sqlite3.Connection) -> None:
    """插入不存在的默认配置项。"""
    now = time.time()
    for key, (value, desc) in DEFAULT_CONFIGS.items():
        conn.execute(
            """INSERT OR IGNORE INTO system_config (key, value, description, updated_at)
               VALUES (?, ?, ?, ?)""",
            (key, value, desc, now),
        )


def get_config(db_path: Path, key: str, default: str = "") -> str:
    """读取系统配置项。"""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM system_config WHERE key = ?", (key,)
        ).fetchone()
    return row["value"] if row else default


def set_config(db_path: Path, key: str, value: str) -> None:
    """写入系统配置项。"""
    with _connect(db_path) as conn:
        conn.execute(
            """INSERT INTO system_config (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, time.time()),
        )


def get_all_config(db_path: Path) -> dict[str, str]:
    """读取全部系统配置。"""
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM system_config").fetchall()
    return {row["key"]: row["value"] for row in rows}
