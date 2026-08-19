# AGENTS.md — bcf-file-gateway 开发指南

## 项目概述

局域网文件下载网关，提供白名单目录文件共享、审批工作流和远程挂载点管理。

**双入口架构：**
- HTTP Web 服务（FastAPI）：`gateway/server.py` — 用户界面 + REST API
- MCP stdio 服务：`gateway/mcp_server.py` — 供外部 AI 智能体调用

## 核心模块职责

```
gateway/
├── approval/          # 审批工作流核心逻辑
│   ├── auth.py        # 认证/会话管理（bcrypt + itsdangerous）
│   ├── models.py      # 数据库初始化 + CRUD 辅助
│   ├── mounts.py      # 挂载点管理 + 四种协议适配器（SMB/FTP/WebDAV/SCP）
│   ├── scanner.py     # 定时扫描远程目录
│   ├── tasks.py       # 审批任务 CRUD
│   ├── review.py      # 审批决策处理
│   ├── transfer.py    # 异步传输队列 + 后台 worker
│   └── logs.py        # 操作日志
├── web/               # HTTP 路由层
│   ├── routes.py      # 页面路由 + 表单处理
│   ├── api.py         # REST API 端点
│   └── templates/     # Jinja2 模板
├── static/            # CSS/JS 静态资源
├── security.py        # 路径白名单校验 + token 限时链接
├── config.py          # 配置加载（支持 APP_SECRET 环境变量）
├── quota.py           # 额度记账
└── main.py            # 入口点
```

## 安全模型关键约束

1. **路径白名单**：`security.py:validate_path` 是唯一的路径校验入口，使用 `os.path.realpath` 解析符号链接后做目录前缀匹配。修改时必须确保防穿越逻辑完整。
2. **Secret 管理**：生产环境必须通过 `APP_SECRET` 环境变量提供密钥，不要依赖 config.toml 自动生成。Secret 用于：
   - Fernet 密钥派生（`mounts.py:_derive_key`，PBKDF2）
   - Session token 签名（`auth.py:create_session_token`，itsdangerous）
3. **Token 限时链接**：`security.py:build_download_url` 生成随机 token，`verify_download_token` 验证时复查白名单。

## 开发约定

- **修改功能后必须同步更新 SKILL.md**：SKILL.md 是外部智能体的接口文档，任何 API 或工作流变更都需同步。
- **异常处理**：不要使用裸 `except Exception: pass`。连接测试失败用 `logger.warning`，目录创建等预期失败用 `logger.debug`，均需 `exc_info=True`。
- **协议适配器**：新增协议需实现 `ProtocolAdapter` 接口的全部方法（`test_connection`, `list_files`, `copy_file`, `move_to_status_dir`, `write_text_file`, `upload_file`）。

## 测试

```bash
# 运行测试
cd bcf-file-gateway && python -m pytest tests/

# 运行 lint
ruff check gateway/
```

## 配置

- `config.toml`：运行时配置（已被 .gitignore 排除）
- `APP_SECRET` 环境变量：生产环境密钥（推荐）
- `data/`：SQLite 数据库目录（已被 .gitignore 排除）
