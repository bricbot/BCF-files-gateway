"""HTMX 片段 API：返回 HTML 片段供前端局部刷新。"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..approval.auth import require_login, get_current_user
from ..approval.models import get_config
from ..approval.scanner import get_pending_files, get_reviewing_files
from ..approval.transfer import get_queue_items


def create_api_router() -> APIRouter:
    router = APIRouter(prefix="/app/api")

    @router.get("/task/{task_id}/files")
    @require_login
    async def htmx_file_list(request: Request, task_id: int):
        """返回待审批文件列表 HTML 片段。"""
        db_path: Path = request.app.state.db_path
        pending = get_pending_files(db_path, task_id)
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
        _add_filters(templates)
        return templates.TemplateResponse(request, "components/file_list.html", {
            "files": pending, "task_id": task_id,
        })

    @router.get("/transfers/list")
    @require_login
    async def htmx_transfer_list(request: Request, status: str = ""):
        """返回传输队列 HTML 片段。"""
        db_path: Path = request.app.state.db_path
        user = request.state.user
        items = get_queue_items(db_path, user_id=user["id"], status=status or None)
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
        _add_filters(templates)
        return templates.TemplateResponse(request, "components/transfer_list.html", {
            "queue_items": items,
        })

    return router


def _add_filters(templates):
    """添加自定义 Jinja2 过滤器。"""
    from datetime import datetime

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
