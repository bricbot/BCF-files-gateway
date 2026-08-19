---
name: bcf-file-gateway
description: 指导智能体使用本机 bcf-file-gateway 知识库文件下载网关。当用户想下载知识库检索到的文本出处的原文件、需要生成文件下载链接、或提到 bcf-file-gateway、下载网关、下载链接额度时使用。维护 bcf-file-gateway 功能后必须同步更新本 skill。
---

# bcf-file-gateway 使用指南

本机运行的知识库文件下载网关，位于 `/Users/myertai/VibeBase/BCFfilesShare/bcf-file-gateway`。
典型场景：用户通过 qwenpaw 智能体在 Linkly 知识库中检索到一段文本，想下载该文本出处的原文件。

## 工作流（四步）

智能体处理用户下载请求时，必须按以下顺序执行：

### 步骤 1：用户提出下载需求
用户说"我想下载某个文件"或类似表达。

### 步骤 2：先查额度，再确认文件名
调用 `check_quota(user_id)` 查询用户当日剩余额度：
- 如果 `remaining == 0`，直接回复用户："今日下载额度已用完，明天再试。"
- 如果 `remaining > 0`，回复用户时**开头先说明剩余额度**，例如："你今天还剩 8 次下载额度。我理解你想下载的是《压型金属板建筑构造》，对吗？"

### 步骤 3：用户确认后，生成下载链接
用户确认文件名无误后，调用 `generate_download_link(user_id, file_path)` 生成链接。
- `user_id`（必填）：发起请求的用户 ID
- `file_path`（必填）：知识库检索返回的原文件绝对路径

### 步骤 4：返回下载链接
把返回的 `url` **原样**发给用户，提醒链接仅在有效期内可下载。

## MCP 工具

网关以 stdio MCP 服务注册（与 linkly mcp 注册方式相同），提供两个工具：

### check_quota(user_id: str)
查询用户当日下载额度，**不扣减**。
返回 JSON：`{used, remaining, daily_limit, unlimited}`
- `unlimited == true` 时该用户是开发者，不受额度限制

### generate_download_link(user_id: str, file_path: str, ttl_seconds: int = 3600)
为知识库中的原文件生成局域网限时下载链接，**扣减额度**。
返回 JSON：
- 成功：`url`、`filename`、`size`、`expires_in_seconds`、`used_today`、`daily_limit`
- 失败：`error`（及可能的 `hint`），需把错误原因如实转述给用户

## 行为约束

1. 拿到 `url` 后**原样**发给用户，不要改写、截断或二次编码。
2. 下载链接是短链接格式（`http://<IP>:<PORT>/dl/<64位token>`），**不包含文件路径信息**，更安全。
3. 同一文件重复请求也会消耗额度，先确认用户确实需要再调用 `generate_download_link`。
4. 收到 429 或 `remaining == 0` 时告知用户“今日下载额度已用完，明天重置”，不要重试或换 user_id 规避。
5. 收到 403（路径不在白名单）说明文件不属于知识库目录，如实告知用户，不要尝试拼凑其他路径绕过。
6. 收到 404 时先核对路径中的空格、全半角字符是否与检索结果完全一致。
7. 每用户每天默认 10 次，按本地时区自然日重置。

## 开发者白名单

`config.toml` 中可配置开发者白名单，指定用户可解除特定限制：

```toml
[[developers]]
user_id = "dev_admin"
permissions = ["quota", "whitelist"]
```

可解除的限制：
- `"quota"`：不受每日下载额度限制（`remaining` 返回 -1，`unlimited` 返回 true）
- `"whitelist"`：可下载白名单目录之外的文件

开发者用户用其 `user_id` 发起请求时，网关自动识别并解除对应限制，无需额外参数。

## 白名单目录（当前）

只有以下目录内的文件允许生成下载链接：

- `/Users/myertai/KB/设计、工艺、装备_c-technical-documents/设计图集`
- `/Users/myertai/KB/设计、工艺、装备_c-technical-documents/设计标准、规范`

## 备选方式：HTTP API

服务地址 `http://192.168.200.23:8790`（局域网 IP 可能变化，以 `GET /health` 返回的 `lan_ip` 为准）：

```bash
# 查询额度
POST /api/quota
{"user_id": "u123"}
# 返回：{"used": 2, "remaining": 8, "daily_limit": 10}

# 生成链接
POST /api/link
{"path": "/绝对路径/文件.pdf", "user_id": "u123", "ttl": 3600}
```

状态码：200 成功；403 路径不在白名单或链接无效；404 文件不存在；422 缺参数；429 当日额度用尽。

## 运维速查

```bash
cd /Users/myertai/VibeBase/BCFfilesShare/bcf-file-gateway
curl -s http://127.0.0.1:8790/health          # 健康检查
pkill -f "gateway.main http"                   # 停止
nohup ./.venv/bin/python -m gateway.main http > /tmp/bcf-file-gateway-http.log 2>&1 &  # 启动
```

- 服务启动时会在终端输出 skill 的 HTTP 访问地址（http://<局域网IP>:8790/skill），智能体可直接访问该 URL 下载本文件
- 修改 `config.toml`（白名单、额度、端口）后必须重启服务才生效
- MCP 入口由 qwenpaw 按需以 stdio 拉起，无需单独常驻
- 依赖锁定：mcp SDK 必须 `<2.0`（2.x 移除了 fastmcp 模块）

## 维护约定

每次修改 bcf-file-gateway 的功能、接口参数、白名单、端口或错误语义后，必须同步更新本 skill 对应章节，保持与实际行为一致。
