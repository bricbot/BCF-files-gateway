"""登录认证、session 管理、权限校验。"""

from __future__ import annotations

import functools
import time
from pathlib import Path

import bcrypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

from .models import _connect


# ── 密码工具 ──

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


# ── Session 工具 ──

def _get_serializer(secret: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret, salt="approval-session")


def create_session_token(secret: str, user_id: int, role: str) -> str:
    s = _get_serializer(secret)
    return s.dumps({"uid": user_id, "role": role})


def load_session_token(secret: str, token: str, max_age: int = 86400 * 7) -> dict | None:
    s = _get_serializer(secret)
    try:
        return s.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


# ── 用户管理 ──

def has_any_admin(db_path: Path) -> bool:
    """检查数据库中是否存在管理员账户。"""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'"
        ).fetchone()
    return row["cnt"] > 0


def create_user(db_path: Path, username: str, password: str, role: str = "reviewer",
                nickname: str | None = None) -> int:
    """创建用户，返回 user_id。"""
    now = time.time()
    pwd_hash = hash_password(password)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO users (username, password_hash, nickname, role, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, pwd_hash, nickname or username, role, now, now),
        )
        return cursor.lastrowid


def authenticate(db_path: Path, username: str, password: str) -> dict | None:
    """验证用户名密码，成功返回用户信息 dict，失败返回 None。"""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()
    if row is None:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return dict(row)


def get_user(db_path: Path, user_id: int) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_username(db_path: Path, username: str) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def list_users(db_path: Path) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def update_user(db_path: Path, user_id: int, **kwargs) -> None:
    allowed = {"nickname", "password_hash", "role", "is_active", "must_change_pwd"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return
    updates["updated_at"] = time.time()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [user_id]
    with _connect(db_path) as conn:
        conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)


def change_password(db_path: Path, user_id: int, old_password: str, new_password: str) -> bool:
    """修改密码，旧密码验证通过返回 True。"""
    user = get_user(db_path, user_id)
    if user is None:
        return False
    if not verify_password(old_password, user["password_hash"]):
        return False
    update_user(db_path, user_id, password_hash=hash_password(new_password), must_change_pwd=0)
    return True


def force_reset_password(db_path: Path, user_id: int, new_password: str) -> None:
    """管理员强制重置用户密码。"""
    update_user(db_path, user_id, password_hash=hash_password(new_password))


def delete_user(db_path: Path, user_id: int) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM task_assignees WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ── 路由保护装饰器 ──

def get_current_user(request: Request, db_path: Path, secret: str,
                     session_timeout_minutes: int = 480) -> dict | None:
    """从 request 的 cookie 中解析当前用户。"""
    token = request.cookies.get("session_token")
    if not token:
        return None
    max_age = session_timeout_minutes * 60
    data = load_session_token(secret, token, max_age=max_age)
    if data is None:
        return None
    return get_user(db_path, data["uid"])


def require_login(func):
    """装饰器：要求用户已登录。"""
    @functools.wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        from .models import get_config
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        timeout = int(get_config(db_path, "session_timeout_minutes", "480"))
        user = get_current_user(request, db_path, secret, timeout)
        if user is None:
            # HTMX 请求返回 401 让前端跳转
            if request.headers.get("HX-Request") == "true":
                return Response(
                    content='<script>window.location.href="/app/login"</script>',
                    status_code=401,
                )
            return RedirectResponse("/app/login", status_code=302)
        request.state.user = user
        return await func(request, *args, **kwargs) if _is_async(func) else func(request, *args, **kwargs)
    return wrapper


def require_admin(func):
    """装饰器：要求用户是管理员。"""
    @functools.wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        user = getattr(request.state, "user", None)
        if user is None or user.get("role") != "admin":
            if request.headers.get("HX-Request") == "true":
                return Response(content="权限不足", status_code=403)
            return RedirectResponse("/app/login", status_code=302)
        return await func(request, *args, **kwargs) if _is_async(func) else func(request, *args, **kwargs)
    return wrapper


def _is_async(func) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(func)
