"""FastMCP stdio 服务：供 qwenpaw 智能体注册调用。"""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP

from .config import load_config
from .quota import QuotaDB, QuotaExceededError
from .security import (
    FileNotAvailableError,
    GatewayError,
    build_download_url,
    validate_path,
)

mcp = FastMCP("BCF-linkly-file-gateway")

_config = load_config()
_quota_db = QuotaDB(_config.db_path, _config.daily_limit)


@mcp.tool()
def check_quota(user_id: str) -> str:
    """查询用户当日下载额度，不扣减。

    在用户请求下载文件时，先调用此工具确认用户当日是否还有剩余额度。
    如果 remaining > 0，智能体可以继续向用户确认文件名；
    如果 remaining == 0，智能体应告知用户今日额度已用完，明天再试。
    如果 unlimited == True，该用户是开发者，不受额度限制。

    Args:
        user_id: 发起下载请求的用户 ID（必填）。

    Returns:
        JSON 字符串：包含 used（今日已用次数）、remaining（剩余额度）、daily_limit（每日上限）、unlimited（是否开发者无限制）。
    """
    bypass = _config.has_permission(user_id, "quota")
    return json.dumps(_quota_db.get_quota_info(user_id, bypass_quota=bypass), ensure_ascii=False)


@mcp.tool()
def generate_download_link(user_id: str, file_path: str, ttl_seconds: int = 3600) -> str:
    """为知识库中的原文件生成局域网限时下载链接。

    当用户通过检索结果想下载某段文本出处的原文件时调用本工具。
    file_path 必须是知识库检索返回的原文件绝对路径；user_id 是发起请求的用户 ID，
    用于每日创建额度限制（默认每用户每天 10 次）。

    Args:
        user_id: 发起下载请求的用户 ID（必填）。
        file_path: 知识库中原文件的绝对路径（必填）。
        ttl_seconds: 下载链接有效期，单位秒，默认 3600。

    Returns:
        JSON 字符串：成功时包含 url、filename、size、expires_in_seconds、
        used_today、daily_limit；失败时包含 error 说明。
    """
    try:
        bypass_quota = _config.has_permission(user_id, "quota")
        bypass_whitelist = _config.has_permission(user_id, "whitelist")
        real_path = validate_path(file_path, _config.allowed_roots, bypass_whitelist=bypass_whitelist)
        used = _quota_db.check_quota(user_id, bypass_quota=bypass_quota)
        ttl = ttl_seconds or _config.link_ttl_seconds
        url, exp, token = build_download_url(_config, real_path, ttl)
        _quota_db.create_link_token(token, real_path, exp)
        _quota_db.record(user_id, real_path)
    except QuotaExceededError as e:
        return json.dumps(
            {
                "error": str(e),
                "used_today": e.used,
                "daily_limit": e.limit,
                "hint": "该用户今日下载链接额度已用完，请明天再试或联系管理员调整额度",
            },
            ensure_ascii=False,
        )
    except GatewayError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)

    return json.dumps(
        {
            "url": url,
            "filename": os.path.basename(real_path),
            "size": os.path.getsize(real_path),
            "expires_in_seconds": ttl,
            "used_today": used + 1,
            "daily_limit": _config.daily_limit if not bypass_quota else -1,
            "unlimited": bypass_quota,
            "hint": "请把 url 原样发给用户，链接仅在有效期内可下载",
        },
        ensure_ascii=False,
    )


if __name__ == "__main__":
    mcp.run()
