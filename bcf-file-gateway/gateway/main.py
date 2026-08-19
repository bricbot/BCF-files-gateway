"""CLI 入口：python -m gateway.main http | mcp"""

from __future__ import annotations

import argparse
import logging
import sys


def _print_skill_banner() -> None:
    """输出 skill 文件的 HTTP 访问地址（可直接复制发给智能体）。"""
    from .config import detect_lan_ip, load_config

    config = load_config()
    skill_url = f"http://{detect_lan_ip()}:{config.port}/skill"
    webui_url = f"http://{detect_lan_ip()}:{config.port}/app"
    print("=" * 62, flush=True)
    print("智能体使用指南（skill）HTTP 地址：", flush=True)
    print(skill_url, flush=True)
    print("可直接复制上面的 URL 发给智能体", flush=True)
    print("-" * 62, flush=True)
    print("文件入库审批 WebUI 地址：", flush=True)
    print(webui_url, flush=True)
    print("=" * 62, flush=True)


def run_http() -> None:
    import uvicorn

    from .config import load_config
    from .server import create_app

    config = load_config()
    app = create_app(config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    logging.info("局域网下载地址: %s", config.base_url())
    logging.info("白名单目录: %s", config.allowed_roots)
    _print_skill_banner()
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


def run_mcp() -> None:
    from .mcp_server import mcp

    # stdio 传输：stdout 保留给 MCP 协议，日志走 stderr
    mcp.run()


def main() -> int:
    parser = argparse.ArgumentParser(prog="bcf-file-gateway", description="知识库文件下载网关")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("http", help="启动 HTTP 下载服务（FastAPI + uvicorn）")
    sub.add_parser("mcp", help="以 stdio 方式启动 MCP 服务")
    args = parser.parse_args()

    if args.cmd == "http":
        run_http()
    else:
        run_mcp()
    return 0


if __name__ == "__main__":
    sys.exit(main())
