"""FastAPI HTTP 服务：生成下载链接 + 签名限时下载 + 文件入库审批 WebUI。"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import Config, PROJECT_ROOT, detect_lan_ip
from .quota import QuotaDB, QuotaExceededError
from .security import (
    FileNotAvailableError,
    InvalidPathError,
    LinkInvalidError,
    build_download_url,
    validate_path,
    verify_download_token,
)

logger = logging.getLogger(__name__)


class LinkRequest(BaseModel):
    path: str = Field(..., description="知识库内原文件的绝对路径")
    user_id: str = Field(..., min_length=1, description="请求用户的 ID")
    ttl: int | None = Field(None, gt=0, description="链接有效期（秒），缺省取配置")


class QuotaRequest(BaseModel):
    user_id: str = Field(..., min_length=1, description="请求用户的 ID")


def create_app(config: Config) -> FastAPI:
    # ── 初始化审批模块数据库 schema ──
    from .approval.models import init_approval_schema
    init_approval_schema(config.db_path)

    # ── 后台任务引用（lifespan 管理） ──
    _transfer_worker = None
    _scheduler = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal _transfer_worker, _scheduler
        # 启动传输 worker
        from .approval.transfer import TransferWorker
        _transfer_worker = TransferWorker(config.db_path, config.secret)
        await _transfer_worker.start()
        logger.info("Transfer worker started")

        # 启动定时扫描调度器
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        _scheduler = AsyncIOScheduler()
        from .approval.scanner import scan_task_source
        from .approval.tasks import list_tasks

        def _auto_scan_all_tasks():
            """定时扫描所有活跃任务的源目录。"""
            tasks = list_tasks(config.db_path, is_active=True)
            for task in tasks:
                try:
                    scan_task_source(config.db_path, task["id"], config.secret)
                except Exception:
                    logger.exception("Auto scan failed for task %s", task["id"])

        interval = int(config.secret[:2], 16) % 5 + 8  # 用 secret 做种子避免硬编码
        from .approval.models import get_config
        interval = int(get_config(config.db_path, "scan_interval_minutes", "10"))
        _scheduler.add_job(_auto_scan_all_tasks, "interval", minutes=interval, id="auto_scan")
        _scheduler.start()
        logger.info("Scheduler started (scan interval: %d min)", interval)

        yield

        # 关闭
        if _transfer_worker:
            await _transfer_worker.stop()
        if _scheduler:
            _scheduler.shutdown(wait=False)
        logger.info("Background tasks stopped")

    app = FastAPI(title="bcf-file-gateway", docs_url=None, redoc_url=None, lifespan=lifespan)
    quota_db = QuotaDB(config.db_path, config.daily_limit)

    # ── 存储配置到 app.state 供路由使用 ──
    app.state.db_path = config.db_path
    app.state.secret = config.secret

    # ── 挂载静态文件 ──
    static_dir = PROJECT_ROOT / "gateway" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ── 注册审批 WebUI 路由 ──
    from .web.routes import create_web_router
    app.include_router(create_web_router())

    # ── 注册 HTMX 片段 API 路由 ──
    from .web.api import create_api_router
    app.include_router(create_api_router())

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "lan_ip": detect_lan_ip(),
            "port": config.port,
            "daily_limit": config.daily_limit,
        }

    @app.get("/skill")
    def skill():
        """返回 SKILL.md 内容，供智能体直接下载。"""
        skill_path = PROJECT_ROOT / "SKILL.md"
        if not skill_path.exists():
            return JSONResponse(status_code=404, content={"error": "SKILL.md 不存在"})
        return FileResponse(
            skill_path,
            media_type="text/markdown; charset=utf-8",
            filename="SKILL.md",
        )

    @app.post("/api/quota")
    def check_quota(req: QuotaRequest):
        """查询用户当日额度，不扣减。"""
        bypass = config.has_permission(req.user_id, "quota")
        return quota_db.get_quota_info(req.user_id, bypass_quota=bypass)

    @app.post("/api/link")
    def create_link(req: LinkRequest):
        bypass_quota = config.has_permission(req.user_id, "quota")
        bypass_whitelist = config.has_permission(req.user_id, "whitelist")
        try:
            real_path = validate_path(req.path, config.allowed_roots, bypass_whitelist=bypass_whitelist)
            used = quota_db.check_quota(req.user_id, bypass_quota=bypass_quota)
            ttl = req.ttl or config.link_ttl_seconds
            url, exp, token = build_download_url(config, real_path, ttl)
            quota_db.create_link_token(token, real_path, exp)
            quota_db.record(req.user_id, real_path)
        except InvalidPathError as e:
            return JSONResponse(status_code=403, content={"error": str(e)})
        except FileNotAvailableError as e:
            return JSONResponse(status_code=404, content={"error": str(e)})
        except QuotaExceededError as e:
            return JSONResponse(
                status_code=429,
                content={"error": str(e), "used_today": e.used, "daily_limit": e.limit},
            )

        return {
            "url": url,
            "filename": os.path.basename(real_path),
            "size": os.path.getsize(real_path),
            "expires_at": exp,
            "used_today": used + 1,
            "daily_limit": config.daily_limit if not bypass_quota else -1,
            "unlimited": bypass_quota,
        }

    @app.get("/dl/{token}")
    def download(token: str):
        try:
            real_path = verify_download_token(config, quota_db, token)
        except LinkInvalidError as e:
            return JSONResponse(status_code=403, content={"error": str(e)})
        except InvalidPathError as e:
            return JSONResponse(status_code=403, content={"error": str(e)})
        except FileNotAvailableError as e:
            return JSONResponse(status_code=404, content={"error": str(e)})

        # Starlette 会自动为中文文件名生成 filename* RFC 5987 头；
        # FileResponse 支持 Range，大文件可断点续传
        return FileResponse(real_path, filename=os.path.basename(real_path))

    return app
