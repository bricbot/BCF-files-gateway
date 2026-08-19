"""WebUI 路由注册。"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from ..approval.auth import (
    authenticate, create_session_token, get_current_user, require_login,
    require_admin, has_any_admin, create_user, get_user, get_user_by_username,
    list_users, update_user, change_password, force_reset_password, delete_user,
)
from ..approval.logs import log_action, get_logs
from ..approval.models import get_all_config, set_config, get_config
from ..approval.mounts import (
    create_mount, get_mount, list_mounts, update_mount, delete_mount,
    test_mount_connection,
)
from ..approval.tasks import (
    create_task, get_task, list_tasks, delete_task, set_assignees,
)
from ..approval.scanner import (
    scan_task_source, get_pending_files, get_reviewing_files,
)
from ..approval.review import (
    approve_files, reject_files, mark_for_review, withdraw_review,
)
from ..approval.transfer import (
    get_queue_items, pause_transfer, resume_transfer, cancel_transfer,
)


def _templates_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def create_web_router() -> APIRouter:
    router = APIRouter(prefix="/app")
    templates = Jinja2Templates(directory=str(_templates_dir()))

    # ── Jinja2 自定义过滤器 ──
    def _datetime_filter(ts, fmt="%Y-%m-%d %H:%M"):
        if ts is None:
            return "-"
        return datetime.fromtimestamp(ts).strftime(fmt)

    def _filesize_filter(size):
        if size is None or size == 0:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size) < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    templates.env.filters["datetime"] = _datetime_filter
    templates.env.filters["filesize"] = _filesize_filter

    def _get_ctx(request: Request) -> dict:
        """获取模板上下文基础数据。"""
        user = getattr(request.state, "user", None)
        return {"user": user, "request": request}

    # ═══════════════════════════════════════════
    #  登录 / 注册
    # ═══════════════════════════════════════════

    @router.get("/login")
    async def login_page(request: Request, error: str = ""):
        db_path: Path = request.app.state.db_path
        has_admin = has_any_admin(db_path)
        return templates.TemplateResponse(request, "login.html", {
            "has_admin": has_admin, "error": error, "reg_error": "",
        })

    @router.post("/login")
    async def login_submit(request: Request):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        form = await request.form()
        username = form.get("username", "")
        password = form.get("password", "")
        user = authenticate(db_path, username, password)
        if user is None:
            return templates.TemplateResponse(request, "login.html", {
                "has_admin": has_any_admin(db_path),
                "error": "用户名或密码错误", "reg_error": "",
            })
        token = create_session_token(secret, user["id"], user["role"])
        log_action(db_path, user["id"], "login", ip_address=request.client.host if request.client else None)
        resp = RedirectResponse("/app/dashboard", status_code=302)
        timeout = int(get_config(db_path, "session_timeout_minutes", "480"))
        resp.set_cookie("session_token", token, max_age=timeout * 60, httponly=True, samesite="lax")
        return resp

    @router.post("/register")
    async def register_submit(request: Request):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        if has_any_admin(db_path):
            return RedirectResponse("/app/login", status_code=302)
        form = await request.form()
        username = form.get("username", "")
        nickname = form.get("nickname", "")
        password = form.get("password", "")
        confirm = form.get("confirm_password", "")
        min_len = int(get_config(db_path, "password_min_length", "8"))
        if not username or len(username) < 3:
            return templates.TemplateResponse(request, "login.html", {
                "has_admin": False, "error": "",
                "reg_error": "用户名至少 3 个字符",
            })
        if len(password) < min_len:
            return templates.TemplateResponse(request, "login.html", {
                "has_admin": False, "error": "",
                "reg_error": f"密码至少 {min_len} 个字符",
            })
        if password != confirm:
            return templates.TemplateResponse(request, "login.html", {
                "has_admin": False, "error": "",
                "reg_error": "两次密码不一致",
            })
        if get_user_by_username(db_path, username):
            return templates.TemplateResponse(request, "login.html", {
                "has_admin": False, "error": "",
                "reg_error": "用户名已存在",
            })
        uid = create_user(db_path, username, password, role="admin", nickname=nickname or username)
        log_action(db_path, uid, "create_admin", detail={"username": username})
        token = create_session_token(secret, uid, "admin")
        resp = RedirectResponse("/app/dashboard", status_code=302)
        resp.set_cookie("session_token", token, max_age=86400 * 30, httponly=True, samesite="lax")
        return resp

    @router.get("/logout")
    async def logout(request: Request):
        resp = RedirectResponse("/app/login", status_code=302)
        resp.delete_cookie("session_token")
        return resp

    # ═══════════════════════════════════════════
    #  仪表盘
    # ═══════════════════════════════════════════

    @router.get("")
    @router.get("/dashboard")
    @require_login
    async def dashboard(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        from ..approval.models import _connect
        with _connect(db_path) as conn:
            pending = conn.execute(
                """SELECT COUNT(*) as cnt FROM file_records fr
                   JOIN task_assignees ta ON fr.task_id = ta.task_id
                   WHERE ta.user_id = ? AND fr.status = 'pending'""",
                (user["id"],),
            ).fetchone()["cnt"]
            transferring = conn.execute(
                "SELECT COUNT(*) as cnt FROM transfer_queue WHERE created_by = ? AND status IN ('pending','processing')",
                (user["id"],),
            ).fetchone()["cnt"]
            today_start = datetime.now().replace(hour=0, minute=0, second=0).timestamp()
            completed = conn.execute(
                "SELECT COUNT(*) as cnt FROM transfer_queue WHERE created_by = ? AND status = 'completed' AND completed_at >= ?",
                (user["id"], today_start),
            ).fetchone()["cnt"]
        stats = {"pending_count": pending, "transferring_count": transferring, "completed_count": completed}
        recent_logs = []
        if user["role"] == "admin":
            with _connect(db_path) as conn:
                stats["user_count"] = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()["cnt"]
                stats["task_count"] = conn.execute("SELECT COUNT(*) as cnt FROM approval_tasks").fetchone()["cnt"]
                stats["mount_count"] = conn.execute("SELECT COUNT(*) as cnt FROM mounts").fetchone()["cnt"]
            recent_logs = get_logs(db_path, limit=20)
        return templates.TemplateResponse(request, "dashboard.html", {"user": user, "stats": stats, "recent_logs": recent_logs})

    # ═══════════════════════════════════════════
    #  个人中心
    # ═══════════════════════════════════════════

    @router.get("/profile")
    @require_login
    async def profile_page(request: Request, msg: str = "", pwd_error: str = "", pwd_msg: str = ""):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        my_logs = get_logs(db_path, user_id=user["id"], limit=50)
        return templates.TemplateResponse(request, "profile.html", {
            "user": user, "msg": msg, "pwd_error": pwd_error, "pwd_msg": pwd_msg, "my_logs": my_logs,
        })

    @router.post("/profile/nickname")
    @require_login
    async def profile_nickname(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        nickname = form.get("nickname", "")
        update_user(db_path, user["id"], nickname=nickname)
        log_action(db_path, user["id"], "update_nickname", detail={"nickname": nickname})
        return RedirectResponse(f"/app/profile?msg=昵称已更新", status_code=302)

    @router.post("/profile/password")
    @require_login
    async def profile_password(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        old_pwd = form.get("old_password", "")
        new_pwd = form.get("new_password", "")
        confirm = form.get("confirm_password", "")
        if new_pwd != confirm:
            return RedirectResponse("/app/profile?pwd_error=两次密码不一致", status_code=302)
        min_len = int(get_config(db_path, "password_min_length", "8"))
        if len(new_pwd) < min_len:
            return RedirectResponse(f"/app/profile?pwd_error=密码至少{min_len}个字符", status_code=302)
        if not change_password(db_path, user["id"], old_pwd, new_pwd):
            return RedirectResponse("/app/profile?pwd_error=旧密码不正确", status_code=302)
        log_action(db_path, user["id"], "change_password")
        return RedirectResponse("/app/profile?pwd_msg=密码已修改", status_code=302)

    # ═══════════════════════════════════════════
    #  我的任务（审批员）
    # ═══════════════════════════════════════════

    @router.get("/tasks")
    @require_login
    async def my_tasks(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        tasks = list_tasks(db_path, user_id=user["id"], is_active=True)
        return templates.TemplateResponse(request, "reviewer/tasks.html", {"user": user, "tasks": tasks})

    @router.get("/task/{task_id}")
    @require_login
    async def task_detail(request: Request, task_id: int, scan_result: str = ""):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        task = get_task(db_path, task_id)
        if task is None:
            return RedirectResponse("/app/tasks", status_code=302)
        pending = get_pending_files(db_path, task_id)
        reviewing = get_reviewing_files(db_path, task_id)
        sr = json.loads(scan_result) if scan_result else None
        return templates.TemplateResponse(request, "reviewer/task_detail.html", {
            "user": user, "task": task, "pending_files": pending,
            "reviewing_files": reviewing, "scan_result": sr,
        })

    @router.post("/task/{task_id}/scan")
    @require_login
    async def task_scan(request: Request, task_id: int):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        user = request.state.user
        result = scan_task_source(db_path, task_id, secret)
        log_action(db_path, user["id"], "scan_task", resource_type="task", resource_id=task_id, detail=result)
        return RedirectResponse(f"/app/task/{task_id}?scan_result={json.dumps(result)}", status_code=302)

    @router.post("/task/{task_id}/approve")
    @require_login
    async def task_approve(request: Request, task_id: int):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        file_ids_raw = form.get("file_ids", "[]")
        try:
            file_ids = json.loads(file_ids_raw) if isinstance(file_ids_raw, str) and file_ids_raw.startswith("[") else form.getlist("file_ids")
            file_ids = [int(x) for x in file_ids]
        except (json.JSONDecodeError, ValueError):
            file_ids = []
        if file_ids:
            count = approve_files(db_path, file_ids, user["id"])
            log_action(db_path, user["id"], "approve", resource_type="task", resource_id=task_id,
                       detail={"count": count, "file_ids": file_ids})
        return RedirectResponse(f"/app/task/{task_id}", status_code=302)

    @router.post("/task/{task_id}/reject")
    @require_login
    async def task_reject(request: Request, task_id: int):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        file_ids_raw = form.get("file_ids", "[]")
        try:
            file_ids = json.loads(file_ids_raw) if isinstance(file_ids_raw, str) and file_ids_raw.startswith("[") else form.getlist("file_ids")
            file_ids = [int(x) for x in file_ids]
        except (json.JSONDecodeError, ValueError):
            file_ids = []
        reason = form.get("reject_reason", "")
        if file_ids:
            count = reject_files(db_path, file_ids, user["id"], reason)
            log_action(db_path, user["id"], "reject", resource_type="task", resource_id=task_id,
                       detail={"count": count, "reason": reason})
        return RedirectResponse(f"/app/task/{task_id}", status_code=302)

    @router.post("/task/{task_id}/review")
    @require_login
    async def task_review(request: Request, task_id: int):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        file_ids_raw = form.get("file_ids", "[]")
        try:
            file_ids = json.loads(file_ids_raw) if isinstance(file_ids_raw, str) and file_ids_raw.startswith("[") else form.getlist("file_ids")
            file_ids = [int(x) for x in file_ids]
        except (json.JSONDecodeError, ValueError):
            file_ids = []
        if file_ids:
            count = mark_for_review(db_path, file_ids, user["id"])
            log_action(db_path, user["id"], "review", resource_type="task", resource_id=task_id,
                       detail={"count": count})
        return RedirectResponse(f"/app/task/{task_id}", status_code=302)

    @router.post("/task/{task_id}/withdraw")
    @require_login
    async def task_withdraw(request: Request, task_id: int):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        reason = form.get("reason", "")
        # 撤回所有复核中的文件
        reviewing = get_reviewing_files(db_path, task_id)
        file_ids = [f["id"] for f in reviewing]
        if file_ids and reason:
            withdraw_review(db_path, file_ids, user["id"], reason)
            log_action(db_path, user["id"], "withdraw_review", resource_type="task", resource_id=task_id,
                       detail={"reason": reason})
        return RedirectResponse(f"/app/task/{task_id}", status_code=302)

    # ═══════════════════════════════════════════
    #  传输状态
    # ═══════════════════════════════════════════

    @router.get("/transfers")
    @require_login
    async def transfers_page(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        items = get_queue_items(db_path, user_id=user["id"])
        return templates.TemplateResponse(request, "reviewer/transfers.html", {"user": user, "queue_items": items})

    @router.post("/transfers/pause")
    @require_login
    async def transfers_pause(request: Request):
        db_path: Path = request.app.state.db_path
        form = await request.form()
        qid = int(form.get("queue_id", 0))
        if qid:
            pause_transfer(db_path, qid)
        return RedirectResponse("/app/transfers", status_code=302)

    @router.post("/transfers/resume")
    @require_login
    async def transfers_resume(request: Request):
        db_path: Path = request.app.state.db_path
        form = await request.form()
        qid = int(form.get("queue_id", 0))
        if qid:
            resume_transfer(db_path, qid)
        return RedirectResponse("/app/transfers", status_code=302)

    @router.post("/transfers/cancel")
    @require_login
    async def transfers_cancel(request: Request):
        db_path: Path = request.app.state.db_path
        form = await request.form()
        qid = int(form.get("queue_id", 0))
        if qid:
            cancel_transfer(db_path, qid)
        return RedirectResponse("/app/transfers", status_code=302)

    # ═══════════════════════════════════════════
    #  管理员 - 挂载点
    # ═══════════════════════════════════════════

    @router.get("/admin/mounts")
    @require_login
    @require_admin
    async def admin_mounts(request: Request, test_result: str = ""):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        mounts = list_mounts(db_path)
        tr = None if test_result == "" else (test_result == "ok")
        return templates.TemplateResponse(request, "admin/mounts.html", {"user": user, "mounts": mounts, "test_result": tr})

    @router.post("/admin/mounts/save")
    @require_login
    @require_admin
    async def admin_mounts_save(request: Request):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        user = request.state.user
        form = await request.form()
        mid = form.get("mount_id", "")
        data = {
            "name": form.get("name", ""),
            "protocol": form.get("protocol", "local"),
            "host": form.get("host", ""),
            "port": int(form.get("port") or 0) or None,
            "remote_path": form.get("remote_path", ""),
            "username": form.get("username", "") or None,
            "mount_type": form.get("mount_type", "source"),
        }
        password = form.get("password", "")
        if mid:
            update_mount(db_path, int(mid), **data)
            if password:
                from ..approval.mounts import encrypt_password
                update_mount(db_path, int(mid), password_enc=encrypt_password(password, secret))
            log_action(db_path, user["id"], "update_mount", resource_type="mount", resource_id=int(mid))
        else:
            create_mount(db_path, secret, password=password, created_by=user["id"], **data)
            log_action(db_path, user["id"], "create_mount", resource_type="mount")
        return RedirectResponse("/app/admin/mounts", status_code=302)

    @router.post("/admin/mounts/test")
    @require_login
    @require_admin
    async def admin_mounts_test(request: Request):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        form = await request.form()
        mid = int(form.get("mount_id", 0))
        mount = get_mount(db_path, mid)
        ok = test_mount_connection(mount, secret) if mount else False
        return RedirectResponse(f"/app/admin/mounts?test_result={'ok' if ok else 'fail'}", status_code=302)

    @router.post("/admin/mounts/delete")
    @require_login
    @require_admin
    async def admin_mounts_delete(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        mid = int(form.get("mount_id", 0))
        if mid:
            delete_mount(db_path, mid)
            log_action(db_path, user["id"], "delete_mount", resource_type="mount", resource_id=mid)
        return RedirectResponse("/app/admin/mounts", status_code=302)

    # ═══════════════════════════════════════════
    #  管理员 - 任务
    # ═══════════════════════════════════════════

    @router.get("/admin/tasks")
    @require_login
    @require_admin
    async def admin_tasks(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        tasks = list_tasks(db_path)
        source_mounts = list_mounts(db_path, mount_type="source")
        target_mounts = list_mounts(db_path, mount_type="target")
        from ..approval.auth import list_users
        reviewers = [u for u in list_users(db_path) if u["is_active"]]
        return templates.TemplateResponse(request, "admin/tasks.html", {
            "user": user, "tasks": tasks, "source_mounts": source_mounts,
            "target_mounts": target_mounts, "reviewers": reviewers,
        })

    @router.post("/admin/tasks/save")
    @require_login
    @require_admin
    async def admin_tasks_save(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        assignee_ids = [int(x) for x in form.getlist("assignee_ids")]
        end_time = None
        et = form.get("end_time", "")
        if et:
            end_time = datetime.fromisoformat(et).timestamp()
        tid = create_task(
            db_path,
            name=form.get("name", ""),
            description=form.get("description", ""),
            source_mount_id=int(form.get("source_mount_id", 0)),
            target_mount_id=int(form.get("target_mount_id", 0)),
            task_type=form.get("task_type", "permanent"),
            end_time=end_time,
            assignee_ids=assignee_ids,
            created_by=user["id"],
        )
        log_action(db_path, user["id"], "create_task", resource_type="task", resource_id=tid)
        # 创建后立即触发首次扫描
        secret: str = request.app.state.secret
        scan_task_source(db_path, tid, secret)
        return RedirectResponse("/app/admin/tasks", status_code=302)

    @router.post("/admin/tasks/scan")
    @require_login
    @require_admin
    async def admin_tasks_scan(request: Request):
        db_path: Path = request.app.state.db_path
        secret: str = request.app.state.secret
        user = request.state.user
        form = await request.form()
        tid = int(form.get("task_id", 0))
        if tid:
            scan_task_source(db_path, tid, secret)
            log_action(db_path, user["id"], "scan_task", resource_type="task", resource_id=tid)
        return RedirectResponse("/app/admin/tasks", status_code=302)

    @router.post("/admin/tasks/delete")
    @require_login
    @require_admin
    async def admin_tasks_delete(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        tid = int(form.get("task_id", 0))
        if tid:
            delete_task(db_path, tid)
            log_action(db_path, user["id"], "delete_task", resource_type="task", resource_id=tid)
        return RedirectResponse("/app/admin/tasks", status_code=302)

    # ═══════════════════════════════════════════
    #  管理员 - 用户
    # ═══════════════════════════════════════════

    @router.get("/admin/users")
    @require_login
    @require_admin
    async def admin_users(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        users = list_users(db_path)
        return templates.TemplateResponse(request, "admin/users.html", {"user": user, "users": users})

    @router.post("/admin/users/save")
    @require_login
    @require_admin
    async def admin_users_save(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        username = form.get("username", "")
        password = form.get("password", "")
        nickname = form.get("nickname", "")
        role = form.get("role", "reviewer")
        min_len = int(get_config(db_path, "password_min_length", "8"))
        if len(password) < min_len:
            return RedirectResponse(f"/app/admin/users?error=密码至少{min_len}个字符", status_code=302)
        if get_user_by_username(db_path, username):
            return RedirectResponse("/app/admin/users?error=用户名已存在", status_code=302)
        uid = create_user(db_path, username, password, role=role, nickname=nickname or username)
        log_action(db_path, user["id"], "create_user", resource_type="user", resource_id=uid,
                   detail={"username": username, "role": role})
        return RedirectResponse("/app/admin/users", status_code=302)

    @router.post("/admin/users/reset-password")
    @require_login
    @require_admin
    async def admin_users_reset_pwd(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        uid = int(form.get("user_id", 0))
        new_pwd = form.get("new_password", "")
        min_len = int(get_config(db_path, "password_min_length", "8"))
        if len(new_pwd) < min_len:
            return RedirectResponse("/app/admin/users?error=密码太短", status_code=302)
        if uid:
            force_reset_password(db_path, uid, new_pwd)
            log_action(db_path, user["id"], "reset_password", resource_type="user", resource_id=uid)
        return RedirectResponse("/app/admin/users", status_code=302)

    @router.post("/admin/users/delete")
    @require_login
    @require_admin
    async def admin_users_delete(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        uid = int(form.get("user_id", 0))
        if uid and uid != user["id"]:
            delete_user(db_path, uid)
            log_action(db_path, user["id"], "delete_user", resource_type="user", resource_id=uid)
        return RedirectResponse("/app/admin/users", status_code=302)

    # ═══════════════════════════════════════════
    #  管理员 - 系统配置
    # ═══════════════════════════════════════════

    @router.get("/admin/config")
    @require_login
    @require_admin
    async def admin_config(request: Request, msg: str = ""):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        config = get_all_config(db_path)
        return templates.TemplateResponse(request, "admin/config.html", {"user": user, "config": config, "msg": msg})

    @router.post("/admin/config/save")
    @require_login
    @require_admin
    async def admin_config_save(request: Request):
        db_path: Path = request.app.state.db_path
        user = request.state.user
        form = await request.form()
        for key in ("scan_interval_minutes", "max_retry_count", "max_files_per_task",
                     "onetime_task_default_days", "password_min_length", "session_timeout_minutes",
                     "max_concurrent_transfers", "max_upload_size_mb", "allowed_file_extensions"):
            val = form.get(key, "")
            if val:
                set_config(db_path, key, val)
        # 特殊处理 checkbox
        special = form.get("password_require_special", "")
        set_config(db_path, "password_require_special", "true" if special == "true" else "false")
        log_action(db_path, user["id"], "update_config", resource_type="config")
        return RedirectResponse("/app/admin/config?msg=配置已保存", status_code=302)

    return router
