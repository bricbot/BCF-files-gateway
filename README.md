# bcf-file-gateway — 知识库文件下载网关

局域网文件下载网关，提供白名单目录文件共享、审批工作流和远程挂载点管理。配合 Linkly 知识库与 qwenpaw 智能体使用：智能体检索到某段文本后，若用户想下载出处原文件，智能体将原文件绝对路径连同用户 ID 传给本网关，网关生成一个**局域网内的限时下载链接**返回给用户。

## 功能

- **白名单目录校验**：仅知识库目录内的文件可生成下载链接（防路径穿越、防符号链接逃逸）
- **限时下载链接**：随机 token + 过期时间，过期或篡改即失效
- **每用户每日额度**：SQLite 记账，默认每人每天 10 次，按本地时区自然日重置
- **双入口**：MCP 工具（stdio，供智能体注册）+ HTTP Web 界面，共享同一套安全与额度逻辑
- **Web 管理界面**：管理员/审批员角色、用户管理、挂载点配置、审批任务看板
- **审批工作流**：远程目录定时扫描 → 文件审批 → 异步传输（支持 accept/reject/review）
- **远程挂载点**：支持 SMB、FTP、WebDAV、SCP 四种协议，密码 Fernet 加密存储
- **中文文件名**：下载正常（RFC 5987），支持 Range 断点续传

## 目录结构

```
bcf-file-gateway/
├── pyproject.toml          # 依赖声明 + ruff/pytest 配置
├── config.toml             # 运行配置（已被 .gitignore 排除）
├── AGENTS.md               # 编码 Agent 开发指南
├── SKILL.md                # 外部智能体使用指南
├── gateway/
│   ├── config.py           # 配置加载 + 环境变量支持 + 局域网 IP 探测
│   ├── security.py         # 白名单校验 + token 限时链接
│   ├── quota.py            # SQLite 额度记账
│   ├── server.py           # FastAPI HTTP 服务
│   ├── mcp_server.py       # FastMCP stdio 工具
│   ├── main.py             # CLI 入口
│   ├── approval/           # 审批工作流
│   │   ├── auth.py         # 认证/会话管理（bcrypt + itsdangerous）
│   │   ├── models.py       # 数据库初始化 + CRUD
│   │   ├── mounts.py       # 挂载点管理 + 四种协议适配器
│   │   ├── scanner.py      # 定时扫描远程目录
│   │   ├── tasks.py        # 审批任务 CRUD
│   │   ├── review.py       # 审批决策处理
│   │   ├── transfer.py     # 异步传输队列 + 后台 worker
│   │   └── logs.py         # 操作日志
│   ├── web/                # HTTP 路由层
│   │   ├── routes.py       # 页面路由 + 表单处理
│   │   ├── api.py          # REST API 端点
│   │   └── templates/      # Jinja2 模板（admin/reviewer/dashboard）
│   └── static/             # CSS/JS 静态资源
└── tests/                  # 测试套件
    ├── test_security.py    # 路径校验 + token 测试
    └── test_crypto.py      # Fernet 加解密测试
```

## 安装

需要 Python ≥ 3.10：

```bash
cd bcf-file-gateway
python3 -m venv .venv
./.venv/bin/pip install -e .
```

## 配置

### config.toml

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 绑定地址，局域网可访问 |
| `port` | `8790` | 下载服务端口 |
| `allowed_roots` | — | 白名单知识库根目录列表，**按实际知识库目录修改** |
| `link_ttl_seconds` | `3600` | 链接默认有效期（秒） |
| `daily_limit` | `10` | 每用户每天可创建链接次数 |
| `db_path` | `data/gateway.db` | SQLite 文件位置 |
| `secret` | 自动生成 | 首次启动自动生成并写回 |

### 环境变量

| 变量 | 说明 |
|---|---|
| `APP_SECRET` | **生产环境推荐**。密钥优先从此变量读取，避免明文写入 config.toml |

修改 `config.toml` 后需重启服务生效。

## 启动

HTTP 下载服务（必须常驻，下载链接指向它）：

```bash
cd bcf-file-gateway
./.venv/bin/python -m gateway.main http
# 后台运行：
nohup ./.venv/bin/python -m gateway.main http > gateway-http.log 2>&1 &
```

启动日志会打印局域网下载地址（自动探测 en0/en1 的物理 IP，避开 VPN 虚拟网卡）。

Web 管理界面随 HTTP 服务一同启动，访问 `http://<局域网IP>:8790/app/` 进入。

> macOS 防火墙：首次监听时会弹窗，需允许 Python 入站连接，否则局域网其他设备无法访问。

## qwenpaw 注册 MCP 服务

与 linkly mcp 相同的 stdio 方式注册：

```json
{
  "mcpServers": {
    "bcf-file-gateway": {
      "command": "/path/to/bcf-file-gateway/.venv/bin/python",
      "args": ["-m", "gateway.main", "mcp"],
      "cwd": "/path/to/bcf-file-gateway"
    }
  }
}
```

工具：`generate_download_link(user_id, file_path, ttl_seconds=3600)`

- `user_id`（必填）：发起请求的用户 ID，用于每日额度统计
- `file_path`（必填）：知识库检索返回的原文件绝对路径
- 返回 JSON：成功时含 `url` / `filename` / `size` / `expires_in_seconds` / `used_today` / `daily_limit`；失败时含 `error` 说明

## HTTP API

```bash
# 健康检查
curl http://<LAN_IP>:8790/health

# 生成下载链接
curl -X POST http://<LAN_IP>:8790/api/link \
  -H 'Content-Type: application/json' \
  -d '{"path": "/绝对路径/文件.pdf", "user_id": "u123", "ttl": 3600}'
```

| 状态码 | 含义 |
|---|---|
| 200 | 成功 |
| 403 | 路径不在白名单 / 非绝对路径 / 链接签名无效或过期 |
| 404 | 文件不存在或不可读 |
| 422 | 缺少必填参数（如 user_id） |
| 429 | 该用户今日额度已用完 |

## 测试

```bash
cd bcf-file-gateway
PYTHONPATH=. .venv/bin/python -m pytest tests/ -v

# 运行 lint
.venv/bin/ruff check gateway/
```

## 额度说明

- 默认每用户每天 10 次，按本地时区自然日（0 点）重置
- 先校验后记账：路径校验失败不扣额度
- 需临时放开：调大 `daily_limit` 后重启；或删除 SQLite 中该用户当日记录：
  ```bash
  sqlite3 data/gateway.db "DELETE FROM link_records WHERE user_id='u123'"
  ```
- 记录保留 30 天，启动时自动清理

## 开发者白名单

`config.toml` 中可配置开发者白名单，指定用户可解除特定限制：

```toml
[[developers]]
user_id = "dev_admin"
permissions = ["quota", "whitelist"]
```

- `"quota"`：不受每日下载额度限制
- `"whitelist"`：可下载白名单目录之外的文件

## 安全说明

- 路径校验使用 `os.path.realpath` 解析符号链接后做目录前缀匹配，防止路径穿越
- 挂载点密码使用 Fernet 加密存储，密钥通过 PBKDF2（480,000 次迭代）从 secret 派生
- Session cookie 设置 `httponly` + `samesite=lax` 防止 CSRF
- 生产环境应通过 `APP_SECRET` 环境变量提供密钥，避免明文写入 config.toml

## 维护约定

每次修改 bcf-file-gateway 的功能、接口参数、白名单、端口或错误语义后，必须同步更新 [SKILL.md](SKILL.md) 对应章节，保持与实际行为一致。
