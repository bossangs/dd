# sing-box Docker 部署与网页登录管理

本项目提供可网页登录、编辑并应用 sing-box 核心配置的 Docker 部署。它会启动两个独立容器：

- **sing-box 核心**：使用 sing-box 官方 GHCR 镜像中的核心二进制，采用 Linux host 网络监听配置端口。
- **Proxy Admin 管理后台**：使用 HTTP Basic 登录；配置编辑器先调用与核心同版本的 `sing-box check`，再备份和原子保存配置。核心容器内的监督器检测到配置变化后会校验并重启 sing-box。

默认固定使用官方 `v1.14.3` 标签，后台校验器与核心从相同镜像构建，避免 `latest` 更新造成校验/运行版本不一致。升级时在部署目录 `.env` 中同步修改 `SINGBOX_IMAGE`，然后从项目源码目录重新构建两个镜像并检查迁移说明。

Web 容器不挂载 Docker Socket，也不从网页执行任意主机命令。配置应用会短暂中断现有 sing-box 连接；新配置启动失败时，监督器会尝试恢复上一份可运行配置。

## 1. 部署前准备

- 一台你有权管理的 **Linux VPS**。
- 已安装并启动 Docker Engine 与 Docker Compose v2（命令为 `docker compose`）。安装脚本不会安装 Docker、修改系统包或配置防火墙。
- 可拉取 `ghcr.io/sagernet/sing-box` 官方镜像。
- 运行安装命令的账户能够访问 Docker daemon。若只允许 root 运行 Docker，请用 root 执行并注意安装目录及 `.env` 的属主。

## 2. 克隆项目并安装

在 VPS 终端执行：

```bash
git clone https://github.com/bossangs/proxy-admin.git
cd proxy-admin
bash scripts/install-sing-box-docker.sh
```

可将部署文件放到指定目录：

```bash
bash scripts/install-sing-box-docker.sh --dir "$HOME/services/sing-box"
```

脚本会检查 Linux、Docker/Compose、核心配置模板及 Docker daemon；在 `$HOME/sing-box-docker`（或 `--dir` 指定目录）创建 Compose、配置、数据和状态目录，生成随机管理员密码和随机 SOCKS5 密码，构建管理后台及核心镜像，用同版本核心执行配置校验，然后启动两个容器。`.env` 中 `ADMIN_PUBLIC_URL` 和 `SERVER_PUBLIC_ADDRESS` 初始为空，可在网页登录设置；已存在的配置和 `.env` 不会被覆盖。

管理后台用户名和随机密码存放在部署目录 `.env`，文件权限为 `600`。查看登录用户名：

```bash
grep '^ADMIN_USER=' "$HOME/sing-box-docker/.env"
```

查看随机密码（请勿把输出贴到聊天、工单或 GitHub）：

```bash
grep '^ADMIN_PASSWORD=' "$HOME/sing-box-docker/.env"
```

脚本还会在配置目录创建 `config/config.json`。该 JSON 包含随机 SOCKS5 密码，文件权限为 `600`，不要公开或提交到 Git。

## 3. 登录后台

部署完成后，在 VPS 本机打开：

```text
http://127.0.0.1:8000/
```

使用 `.env` 中的 `ADMIN_USER` 和 `ADMIN_PASSWORD` 登录。后台端口默认只绑定本机回环地址；远程访问请按下节配置反向代理和 HTTPS。不要把 HTTP Basic 登录直接暴露在公网明文 HTTP 上。

## 4. 发布 HTTPS 管理后台地址

公网后台地址必须是你控制的域名，且 DNS A/AAAA 记录指向该 VPS。应用本身不会申请域名、配置 DNS、安装反向代理或打开防火墙。若该 VPS 已安装 Caddy，可使用以下站点配置（将域名替换为真实域名）：

```caddyfile
admin.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Caddy 可为公开 DNS 域名自动申请/续期 HTTPS 证书；按其部署方式确保 TCP 80/443 可达。然后登录后台“公网管理地址与客户端订阅”，将后台地址填为 `https://admin.example.com`。后台仍仅监听本机 `127.0.0.1:8000`，不要将 8000 直接暴露到公网；尽可能再用 VPN 或可信 IP 限制访问。

## 5. 自动生成多协议节点并应用

1. 在“公网管理地址与客户端订阅”中填写代理服务器公网域名或 IP（不要带协议或端口），保存。
2. 在“自动生成双协议配置”输入节点名称、端口及 Reality 握手域名。默认同时生成 **VLESS + Reality**（TCP `8443`）与 **Shadowsocks AES-128-GCM**（TCP/UDP `8388`），自动生成 UUID、Reality 密钥、short ID 和 Shadowsocks 密码。默认端口避开 Caddy 常用的 443 管理端口。
3. 工具只会替换 `proxy-admin-generated-*` 专用 tag 的两个入站，不覆盖配置中的其他入站。生成结果会进入 JSON 编辑器草稿，并显示待应用的客户端分享 URI；请先审阅，再点击“校验并应用配置”。
4. 只有核心状态确认 `running` 且配置 SHA-256 匹配后，节点才会显示为已应用，订阅端点才开始返回节点。若端口冲突，先换端口或调整其他入站。

生成器目前固定提供上述两个 sing-box 入站类型；现有手动节点表单和 JSON 编辑器仍可用于其他协议，但不会自动纳入这个订阅。生成的分享链接采用常见 `vless://` Reality URI 与 Shadowsocks [SIP002 URI](https://shadowsocks.org/doc/sip002.html)，不同客户端对订阅及 URI 扩展的支持可能不同。

## 6. 客户端节点与订阅链接

应用配置后，后台会显示 VLESS Reality 和 Shadowsocks 的分享 URI，并提供两种订阅地址：`/sub/<随机令牌>` 返回以 Base64 编码的多行 URI 列表；`/sub/<随机令牌>/plain` 返回纯文本 URI 列表。把任一链接添加到支持相应格式的客户端。

订阅 token 是 **bearer secret**：任何拿到链接的人都能读取节点协议、地址和凭据，无需后台登录。请按密码保管，不要放入公开仓库、截图、聊天或公开工单。后台关闭 Uvicorn access log；如果反向代理启用访问日志，务必避免记录订阅 URL 路径。点击“更换订阅令牌”会立即让所有旧订阅失效，需要在客户端更新链接。订阅响应禁止缓存并标记为 noindex；这不是账号认证或按用户隔离的订阅系统。

“公网管理地址”仅用作后台展示和订阅 URL 的基址，并不会自动让服务公网可达。若未设置，页面会以当前浏览器访问来源作为临时展示基址；正式使用前应填写真实 HTTPS 地址，并从非服务器网络验证 DNS、TLS 与访问限制。

## 7. 编辑并应用 sing-box 配置

1. 登录后找到 **“sing-box 核心配置”** 区域。后台读取当前核心配置并显示核心状态。若先使用上面的生成器，新的双协议配置草稿会显示在 JSON 编辑器里。
2. 在文本编辑器中编辑完整 JSON。TLS、证书、REALITY、路由和协议字段需符合当前核心版本的[官方配置文档](https://sing-box.sagernet.org/configuration/)；证书/密钥文件由管理员放入部署目录的 `config/` 目录，并在 JSON 中使用容器绝对路径，例如 `/etc/sing-box/server.crt` 与 `/etc/sing-box/server.key`。后台校验器和核心容器都以只读方式挂载同一份文件到 `/etc/sing-box`。
3. 点击 **“校验并应用配置”**。后台会解析 JSON，再用与核心镜像一致的 sing-box 版本执行 `check`。语法或核心校验失败时，不会覆盖运行配置。
4. 校验通过后，后台在持久化数据卷中保存一份受限权限备份，再原子替换运行配置。核心容器内监督器检测文件变化，执行再次校验并重启 sing-box。
5. 页面显示 `running` 且新配置 SHA-256 匹配时，表示核心已确认应用。若页面报告回滚，旧配置仍在运行；检查容器日志、端口冲突、证书路径和配置版本后再修改。

应用配置会停止并重启核心进程，已有代理连接会短暂断开。核心监督器不会执行任意网页命令；它只监视固定配置文件、用固定 sing-box 命令校验并管理核心子进程。

## 8. 默认监听与网络安全

初始配置创建带随机用户名/密码的 SOCKS5 入站，但**只监听 `127.0.0.1:2080`**，默认不对公网开放。部署使用 Linux `host` 网络：核心配置中的监听端口直接在 VPS 上生效，不需要 Docker `ports` 映射。

生成双协议节点时，VLESS Reality 与 Shadowsocks 会监听 `0.0.0.0`，使它们可由公网网卡接收连接；这一步改变了公开攻击面。只有你确实要提供公网代理时才应用该配置：

1. 审阅生成的协议、随机凭据与监听地址；确认要提供公网服务后再应用。若不打算公网开放，可先在 JSON 中将入站改为回环地址或指定接口。
2. 点击应用后确认页面状态为 `running`。
3. 在 VPS 本机防火墙和云服务商安全组中只放行配置实际使用的端口及 TCP/UDP 协议（默认生成端口为 TCP `8443` 与 TCP/UDP `8388`；HTTPS 后台反代通常需 TCP `80/443`）。
4. 为管理后台单独配置 TLS 反向代理和访问限制；不要把管理后台端口直接改绑为公网地址。

模板不启用 TUN、`NET_ADMIN` 或 privileged 模式。需要 TUN 的场景必须单独审查网络权限和隔离设计。

## 9. 常用运维命令

在部署目录中执行（如果使用了 `--dir`，替换为实际路径）：

```bash
cd "$HOME/sing-box-docker"
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs -f sing-box
docker compose --env-file .env -f compose.yaml logs -f proxy-admin
docker compose --env-file .env -f compose.yaml restart proxy-admin
docker compose --env-file .env -f compose.yaml down
```

`down` 会停止并移除两个容器，不会删除配置、数据库和数据目录。恢复备份或重置登录口令前，先备份部署目录与 Docker 数据卷。要改镜像版本，可在 `.env` 中编辑 `SINGBOX_IMAGE`，再从项目源码目录重新构建并重启；版本升级前应查看 sing-box 迁移说明。

## 10. 与现有后台功能及 233boy 安装器的关系

- 运行配置编辑器直接管理 sing-box 容器实际使用的 JSON 配置。
- 现有 **“新增节点”** 表单仍保存通用节点草稿；新的自动生成器才会把 VLESS Reality 与 Shadowsocks 合并到 sing-box 配置草稿中，且仍须管理员审阅和应用。
- 233boy 的 `install.sh` 是面向 Linux **宿主机**的安装器，会检查 root、系统包管理器及 systemd/OpenRC；它不是 Docker 安装器。不要在管理后台容器中执行该脚本。
- 安全依据：管理后台不挂载 Docker Socket；核心共享配置目录与运行状态，不允许 Web 表单传入路径或 shell 命令。

## 来源

- [sing-box 官方 Docker 安装文档](https://sing-box.sagernet.org/installation/docker/)
- [sing-box 官方配置说明与校验命令](https://sing-box.sagernet.org/configuration/)
- [sing-box 官方容器镜像](https://github.com/SagerNet/sing-box/pkgs/container/sing-box)
- [sing-box 官方 VLESS 入站配置](https://sing-box.sagernet.org/configuration/inbound/vless/)
- [sing-box 官方 Shadowsocks 入站配置](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)
- [sing-box 官方 TLS / Reality 配置](https://sing-box.sagernet.org/configuration/shared/tls/)
- [Shadowsocks SIP002 分享 URI 规范](https://shadowsocks.org/doc/sip002.html)
- [常见 VLESS / 多协议分享链接参数说明](https://incy.gitbook.io/docs/docs-en/share-links.en)
- [233boy/sing-box](https://github.com/233boy/sing-box)
