"""路径白名单校验 + 随机 token 限时链接。"""

from __future__ import annotations

import os
import secrets
import time

from .config import Config


class GatewayError(Exception):
    """网关业务错误基类。"""


class InvalidPathError(GatewayError):
    """路径不合法：非绝对路径或不在白名单目录内（HTTP 403）。"""


class FileNotAvailableError(GatewayError):
    """文件不存在、不是普通文件或不可读（HTTP 404）。"""


class LinkInvalidError(GatewayError):
    """下载链接签名无效或已过期（HTTP 403）。"""


def validate_path(raw_path: str, allowed_roots: list[str], bypass_whitelist: bool = False) -> str:
    """校验并规范化文件路径，返回解析后的真实路径。
    
    bypass_whitelist=True 时跳过白名单目录检查（开发者权限）。
    """
    if not raw_path or not os.path.isabs(raw_path):
        raise InvalidPathError(f"路径必须是绝对路径: {raw_path!r}")

    real = os.path.realpath(raw_path)
    
    # 开发者权限可跳过白名单检查
    if not bypass_whitelist:
        roots = [os.path.realpath(r) for r in allowed_roots]
        if not any(real == root or real.startswith(root + os.sep) for root in roots):
            raise InvalidPathError("路径不在允许的知识库目录内")

    if not os.path.isfile(real):
        raise FileNotAvailableError("文件不存在或不是普通文件")
    if not os.access(real, os.R_OK):
        raise FileNotAvailableError("文件不可读")
    return real


def generate_token() -> str:
    """生成 64 字符的随机 token。"""
    return secrets.token_hex(32)


def build_download_url(config: Config, path: str, ttl_seconds: int) -> tuple[str, int, str]:
    """生成随机 token 下载链接，返回 (url, exp, token)。
    
    调用方需负责将 token 存入数据库（quota_db.create_link_token）。
    """
    exp = int(time.time()) + ttl_seconds
    token = generate_token()
    url = f"{config.base_url()}/dl/{token}"
    return url, exp, token


def verify_download_token(config: Config, quota_db, token: str) -> str:
    """验证 token 并返回文件真实路径。
    
    从数据库查询 token 对应的 path 和 exp，验证是否过期，然后验证路径。
    """
    result = quota_db.verify_link_token(token)
    if result is None:
        raise LinkInvalidError("下载链接无效或已过期")
    
    path, exp = result
    # 链接生成后白名单可能收紧，下载时仍需复查
    return validate_path(path, config.allowed_roots)
