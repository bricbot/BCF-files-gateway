# BCF-linkly-file-gateway — 知识库文件下载网关

配合 Linkly 知识库与 qwenpaw 智能体使用：智能体检索到某段文本后，若用户想下载出处原文件，智能体将原文件绝对路径连同用户 ID 传给本网关，网关生成一个**局域网内的限时下载链接**返回给用户。

## 功能

- 白名单目录校验：仅知识库目录内的文件可生成下载链接（防路径穿越、防符号链接逃逸）
- HMAC 签名限时链接：下载链接带 token 与过期时间，过期或篡改即失效
- 每用户每日额度：请求须携带 `user_id`，SQLite 记账，默认每人每天 10 次，按本地时区自然日重置
- 双入口：MCP 工具（stdio，供智能体注册）+ HTTP API，共享同一套安全与额度逻辑
- 中文文件名下载正常（RFC 5987），支持 Range 断点续传

## 目录结构

```
BCF-linkly-file-gateway/
├── pyproject.toml        # 依赖声明（fastapi / uvicorn / mcp<2.0 / tomli-w）
├── config.toml           # 运行配置
├── gateway/
│   ├── config.py         # 配置加载 + 局域网 IP 探测 + secret 自动生成
│   ├── security.py       # 白名单校验 + HMAC 签名/验签
│   ├── quota.py          # SQLite 额度记账
│   ├── server.py         # FastAPI HTTP 服务
│   ├── mcp_server.py     # FastMCP stdio 工具
│   └── main.py           # CLI 入口
└── data/gateway.db       # SQLite（运行时自动创建）
```

## 安装

需要 Python ≥ 3.10（本机使用 Homebrew 的 Python 3.13）：

```bash
cd BCF-linkly-file-gateway
/opt/homebrew/bin/python3.13 -m venv .venv
./.venv/bin/pip install -e .
```

## 配置（config.toml）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 绑定地址，局域网可访问 |
| `port` | `8790` | 下载服务端口 |
| `allowed_roots` | BCFfilesShare | 白名单知识库根目录列表，**按实际知识库目录修改** |
| `link_ttl_seconds` | `3600` | 链接默认有效期（秒） |
| `daily_limit` | `10` | 每用户每天可创建链接次数 |
| `db_path` | `data/gateway.db` | SQLite 文件位置 |
| `secret` | 自动生成 | 首次启动自动生成并写回，勿泄露、勿随意更换（更换后已发链接全部失效） |

修改 `allowed_roots` 或 `daily_limit` 后需重启服务生效。

## 启动

HTTP 下载服务（必须常驻，下载链接指向它）：

```bash
cd BCF-linkly-file-gateway
./.venv/bin/python -m gateway.main http
# 后台运行：
nohup ./.venv/bin/python -m gateway.main http > gateway-http.log 2>&1 &
```

启动日志会打印局域网下载地址（自动探测 en0/en1 的物理 IP，避开 VPN 虚拟网卡）。

服务启动时还会在终端输出 **skill 的 HTTP 访问地址**：

```
http://<局域网IP>:8790/skill
```

把这个 URL 直接发给智能体，它会自己下载并学会如何使用下载网关。

> macOS 防火墙：首次监听时会弹窗，需允许 Python 入站连接，否则局域网其他设备无法访问。

## qwenpaw 注册 MCP 服务

与 linkly mcp 相同的 stdio 方式注册：

```json
{
  "mcpServers": {
    "BCF-linkly-file-gateway": {
      "command": "/Users/myertai/VibeBase/BCFfilesShare/BCF-linkly-file-gateway/.venv/bin/python",
      "args": ["-m", "gateway.main", "mcp"],
      "cwd": "/Users/myertai/VibeBase/BCFfilesShare/BCF-linkly-file-gateway"
    }
  }
}
```

工具：`generate_download_link(user_id, file_path, ttl_seconds=3600)`

- `user_id`（必填）：发起请求的用户 ID，用于每日额度统计
- `file_path`（必填）：知识库检索返回的原文件绝对路径
- 返回 JSON：成功时含 `url` / `filename` / `size` / `expires_in_seconds` / `used_today` / `daily_limit`；失败时含 `error` 说明，智能体应把内容转述给用户

## HTTP API

```bash
# 健康检查
curl http://<LAN_IP>:8790/health

# 生成下载链接
curl -X POST http://<LAN_IP>:8790/api/link \
  -H 'Content-Type: application/json' \
  -d '{"path": "/绝对路径/文件.pdf", "user_id": "u123", "ttl": 3600}'

# 返回：{"url": "...", "filename": "...", "size": ..., "expires_at": ..., "used_today": ..., "daily_limit": ...}
```

| 状态码 | 含义 |
|---|---|
| 200 | 成功 |
| 403 | 路径不在白名单 / 非绝对路径 / 链接签名无效或过期 |
| 404 | 文件不存在或不可读 |
| 422 | 缺少必填参数（如 user_id） |
| 429 | 该用户今日额度已用完 |

## 额度说明

- 默认每用户每天 10 次，按本地时区自然日（0 点）重置
- 先校验后记账：路径校验失败不扣额度
- 需临时放开：调大 `daily_limit` 后重启；或删除 SQLite 中该用户当日记录：
  ```bash
  sqlite3 data/gateway.db "DELETE FROM link_records WHERE user_id='u123'"
  ```
- 记录保留 30 天，启动时自动清理
