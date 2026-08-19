"""配置加载与校验。

读取项目根目录下的 config.toml；secret 为空时自动生成随机密钥并写回文件。
"""

from __future__ import annotations

import secrets
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

import tomli_w

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class DeveloperConfig:
    user_id: str
    permissions: list[str]  # "quota", "whitelist"


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 8790
    allowed_roots: list[str] = field(default_factory=list)
    link_ttl_seconds: int = 3600
    daily_limit: int = 10
    db_path: Path = PROJECT_ROOT / "data" / "gateway.db"
    secret: str = ""
    developers: dict[str, list[str]] = field(default_factory=dict)  # user_id -> permissions

    def has_permission(self, user_id: str, permission: str) -> bool:
        """检查用户是否有指定权限。"""
        perms = self.developers.get(user_id, [])
        return permission in perms

    def base_url(self) -> str:
        """下载链接使用的 http 前缀，host 指向局域网 IP。"""
        ip = detect_lan_ip()
        return f"http://{ip}:{self.port}"


def detect_lan_ip() -> str:
    """探测本机局域网 IP；失败时回退到 127.0.0.1。

    优先用 macOS 的 ipconfig 读物理网卡（en0/en1）地址，
    避免 UDP 默认路由法选中 VPN 虚拟网卡（如 clash 的 utun）。
    """
    for iface in ("en0", "en1"):
        try:
            out = subprocess.run(
                ["ipconfig", "getifaddr", iface],
                capture_output=True, text=True, timeout=2,
            )
            ip = out.stdout.strip()
            if ip:
                return ip
        except (OSError, subprocess.TimeoutExpired):
            continue
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # UDP connect 不实际发包，仅用于让内核选出出站网卡 IP
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def load_config(config_path: Path | None = None) -> Config:
    path = config_path or PROJECT_ROOT / "config.toml"
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {path}")

    with open(path, "rb") as f:
        data = tomllib.load(f)

    allowed_roots = data.get("allowed_roots", [])
    if not allowed_roots:
        raise ValueError("config.toml 中 allowed_roots 不能为空，请填写知识库根目录")

    db_path = Path(data.get("db_path", "data/gateway.db"))
    if not db_path.is_absolute():
        db_path = path.parent / db_path

    secret = data.get("secret", "")
    if not secret:
        secret = secrets.token_hex(32)
        data["secret"] = secret
        with open(path, "wb") as f:
            tomli_w.dump(data, f)

    # 加载开发者白名单
    developers: dict[str, list[str]] = {}
    for dev in data.get("developers", []):
        uid = dev.get("user_id", "")
        perms = dev.get("permissions", [])
        if uid:
            developers[uid] = list(perms)

    return Config(
        host=data.get("host", "0.0.0.0"),
        port=int(data.get("port", 8790)),
        allowed_roots=[str(r) for r in allowed_roots],
        link_ttl_seconds=int(data.get("link_ttl_seconds", 3600)),
        daily_limit=int(data.get("daily_limit", 10)),
        db_path=db_path,
        secret=secret,
        developers=developers,
    )
