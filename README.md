# 代理协议配置管理后台（MVP）

## 功能
- FastAPI + SQLite 的管理后台，HTTP Basic 管理员认证。
- 管理 VLESS、VMess、Trojan、Shadowsocks、SOCKS5、HTTP、HTTPS 节点草稿。
- 参数校验、配置 JSON 生成、节点新增/列表/删除、审计日志。
- Xray-core / sing-box 配置适配器。
- sing-box Docker 集成部署支持 VLESS + Reality 与 Shadowsocks 双协议自动生成、客户端 URI 与 token 订阅。
- 管理后台仍默认仅绑定 localhost；可配置 HTTPS 公网管理基址与代理服务器公网域名/IP。

> 重要：按上方普通 Docker Compose 方式单独部署时，只启动管理后台，不会安装或控制代理核心。需要运行 sing-box 核心并通过网页校验/应用实际配置时，请使用下方集成部署脚本。TLS 证书、REALITY、协议细节及不同版本的字段兼容仍需按部署目标核验；不要把管理端口直接暴露到公网。

## 本机运行
需要 Python 3.12+。

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
```

设置环境变量（建议使用密码管理器生成至少 32 字符的随机密码）：
```bash
export ADMIN_USER=admin
export ADMIN_PASSWORD='replace-with-a-long-random-secret'
uvicorn app:app --host 127.0.0.1 --port 8000
```

浏览器打开 http://127.0.0.1:8000/ ，使用 HTTP Basic 登录。`/`, `/dashboard`, `/ui` 都是管理页面入口。

## Docker Compose
```bash
cp .env.example .env
# 编辑 .env，设置独立且高强度的 ADMIN_PASSWORD
docker compose up --build -d
docker compose logs -f
```
Compose 默认只绑定 `127.0.0.1:8000`。生产环境建议在前置反向代理配置 HTTPS、IP allowlist 或 VPN，并启用速率限制。HTTP Basic 必须在 TLS 内使用。

## sing-box 核心与网页登录管理后台（Docker）

仓库提供一键初始化脚本，会在 Linux VPS 上部署 sing-box 核心容器和带 HTTP Basic 登录的管理后台。目标主机需预先安装 Docker Engine 与 Docker Compose v2：

```bash
bash scripts/install-sing-box-docker.sh
```

脚本在 `$HOME/sing-box-docker` 初始化 Compose、随机管理员密码及仅监听 `127.0.0.1:2080` 的 SOCKS5 配置；构建时从官方镜像提取同版本核心供后台校验，校验通过后才启动。访问 `http://127.0.0.1:8000/` 登录，在“sing-box 核心配置”区域可编辑 JSON 并点击“校验并应用配置”。另可保存 HTTPS 管理基址与代理服务器域名/IP，一键生成 VLESS + Reality 和 Shadowsocks 双协议配置及客户端 URI / bearer 订阅链接。生成配置须经管理员审阅、校验并应用后才生效。应用前会备份并原子替换配置，核心容器内监督器检测到变更后重启核心；若新配置启动失败则尝试回滚，连接会短暂中断。

默认后台端口只绑定 `127.0.0.1`；远程管理必须使用带 HTTPS 的反向代理并尽可能限制来源 IP 或使用 VPN。核心使用 Linux host 网络，自动生成的代理入站会监听公网接口；只有确认要提供代理服务后才应用，并在防火墙中只放行必要端口。订阅 URL 包含可读取节点凭据的随机令牌，应按密码保管；后台关闭应用级访问日志以降低令牌泄漏风险。后台容器不挂载 Docker Socket。完整反向代理、节点生成及订阅步骤见 [docs/sing-box-docker.md](docs/sing-box-docker.md)。

## 233boy sing-box 上游脚本配置

登录后台后，在“233boy.com / sing-box 上游脚本”区域可以查看并保存官方安装脚本地址、复制本管理后台 Docker Compose 命令，以及复制 VPS 宿主机安装和多协议示例。上游地址仅允许指向 `233boy/sing-box` 的官方 `install.sh` 路径；后台只展示命令，不会下载或执行远程脚本。详细说明见 [docs/233boy-sing-box-admin.md](docs/233boy-sing-box-admin.md)。

**233boy 安装器面向 VPS 宿主机，不是 Docker 安装器。** 该脚本需要 root、支持的 Linux 包管理器和 systemd/OpenRC；安装前请下载并检查脚本内容。容器部署请使用上面的独立 sing-box 核心 Docker 脚本；不要在后台容器中运行宿主机安装器。

## API
- `GET /health` 健康检查（无需登录）
- `GET /api/nodes` 节点列表（需认证，凭据脱敏）
- `POST /api/nodes` 创建节点（需认证）
- `GET /api/settings/sing-box` 查看已保存的官方脚本地址（需认证）
- `PUT /api/settings/sing-box` 更新官方脚本地址（仅允许官方仓库 URL，需认证）
- `GET/PUT /api/settings/public-links` 查看/更新 HTTPS 管理基址与代理服务器公网域名/IP（需认证）
- `POST /api/settings/public-links/rotate-subscription` 轮换订阅令牌并使旧链接失效（需认证）
- `GET /api/sing-box/runtime` 读取集成部署中的当前运行配置和核心状态（需认证）
- `PUT /api/sing-box/runtime` 校验、备份并应用 sing-box 配置（需认证；仅集成部署启用）
- `POST /api/sing-box/generate-multi` 生成 VLESS Reality + Shadowsocks 配置草稿和分享 URI（需认证）
- `GET /api/sing-box/share-links` 读取已应用且运行中的节点分享链接（需认证）
- `GET /sub/{token}` 与 `GET /sub/{token}/plain` 提供 Base64 / 纯文本订阅（订阅 token 是 bearer secret；无需后台登录）
- `GET /api/nodes/{id}/config?core=xray|sing-box` 获取完整配置（敏感信息，需认证）
- `DELETE /api/nodes/{id}` 删除节点（需认证）
- `GET /api/audit` 最近审计记录（需认证）

示例请求：
```bash
curl -u "$ADMIN_USER:$ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo","protocol":"VLESS","core":"xray","listen":"127.0.0.1","port":18443,"uuid":"00000000-0000-4000-8000-000000000001","network":"tcp","tls":false}' \
  http://127.0.0.1:8000/api/nodes
```

## 上线前必须完成
1. 为所有公开服务配置 TLS；管理面板只允许 VPN/可信 IP 访问。
2. 配置密钥不要明文写入审计日志；当前节点凭据存储在 SQLite JSON 中，生产环境应改为加密密钥存储或外部 secret manager，并限制数据库文件权限。
3. 采用 CSRF 防护或改用带 CSRF token 的会话认证；若通过浏览器使用 Basic Auth，避免不可信来源的跨站请求。
4. 为各协议按目标核心版本补齐 schema 校验与测试；用核心的 `-test`/`check` 命令做部署前验证。
5. 不要让 Web 应用以 root 运行；若需 reload 核心，使用最小权限的独立服务管理器，不接受任意命令或任意路径。
6. 为证书生命周期、更多协议生成、端口冲突、备份/恢复、管理员改密、限速和告警增加生产功能。
