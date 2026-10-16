# 233boy sing-box 上游脚本配置与安装步骤

后台的“233boy.com / sing-box 上游脚本”区域用于保存、查看上游安装器地址并复制部署命令。它不会在 Web 应用内下载或执行任何远程脚本，也不会改变现有 Xray / sing-box 节点配置生成逻辑。核心运行配置的网页编辑、VLESS Reality + Shadowsocks 双协议生成、客户端节点/订阅链接与公网地址设置由独立的 [sing-box Docker 部署](sing-box-docker.md)提供；这些功能不是 233boy 宿主机安装器的一部分。

## 先区分三种部署目标

- **Docker Compose**：部署本仓库的 `proxy-admin` 管理后台。
- **核心 Docker 部署**：运行本仓库的 `scripts/install-sing-box-docker.sh`，部署独立的 sing-box 官方镜像容器；详见 [sing-box 核心 Docker 部署文档](sing-box-docker.md)。
- **233boy 安装器**：安装 sing-box 核心与上游管理脚本到 Linux VPS **宿主机**，需要 root 和 systemd/OpenRC。它不是 Docker 安装器；不要把它放进本后台容器运行。

## A. 部署本管理后台（Docker Compose）

### 第 1 步：进入解压后的项目目录

确认当前目录中能看到 `compose.yaml`、`Dockerfile` 和 `.env.example`。以下命令均在这个目录运行：

```bash
cp .env.example .env
```

### 第 2 步：设置管理员凭据

编辑 `.env`，设置 `ADMIN_USER` 和独立、高强度的 `ADMIN_PASSWORD`，不要保留 `CHANGE_ME_TO_A_LONG_RANDOM_SECRET` 示例值，也不要把 `.env` 上传到 GitHub。

### 第 3 步：构建并启动后台

```bash
docker compose up --build -d
docker compose ps
docker compose logs -f
```

Compose 默认只将页面绑定到 `127.0.0.1:8000`。如需外部访问，应由受控的反向代理提供 HTTPS，并限制来源 IP 或使用 VPN；不要把 HTTP Basic 登录直接暴露在明文 HTTP 上。可用 `Ctrl+C` 退出日志跟踪；不会停止容器。

## B. 在 VPS 宿主机安装 233boy sing-box

### 第 1 步：检查服务器和安装条件

上游脚本当前检查：root 权限、64 位 x86_64/amd64 或 ARM64/aarch64 架构、apt-get/yum/zypper/apk 包管理器，以及 systemd 或 OpenRC 服务管理环境。服务器还需要能访问 GitHub。确认你有权管理该服务器，并检查域名、端口、安全组和备份需求。

### 第 2 步：登录 VPS 并切换到 root

以下命令在目标 **VPS 宿主机** 的终端执行，不是在本地管理后台容器内执行：

```bash
sudo -i
```

确认提示符对应 root 后继续。若你的系统没有 `sudo`，请使用服务商提供的 root 登录方式。

### 第 3 步：下载脚本，先检查内容和帮助

```bash
wget -O /tmp/sing-box-install.sh "https://github.com/233boy/sing-box/raw/main/install.sh"
cat /tmp/sing-box-install.sh
bash /tmp/sing-box-install.sh -h
```

安装器会以管理员权限安装软件、创建系统服务并下载上游管理脚本。`-h` 用于显示安装器参数帮助；审阅脚本内容、确认来源和操作影响后再继续。`main` 分支可能更新，线上脚本内容可能变化。

### 第 4 步：确认后执行安装

```bash
bash /tmp/sing-box-install.sh
```

安装器默认获取上游发布的 sing-box 核心版本，并创建一个 VLESS-REALITY 配置。不要在未审阅脚本时执行直接下载并运行的管道命令。

### 第 5 步：检查服务并查看初始配置

```bash
sing-box status
sing-box info
sing-box log
```

`info` 可能显示可用于客户端连接的敏感信息，不要公开粘贴到 GitHub、工单或聊天记录。若服务异常，检查日志、客户端支持情况、服务器防火墙和云服务商安全组；只开放配置实际使用的端口，不要为排错直接关闭整台服务器防火墙。

## C. 添加其他协议配置

安装后可用 `sing-box` 或快捷命令 `sb` 管理。上游 README 与文档列出 VLESS-REALITY、VLESS-H2-REALITY、VLESS/VMess/Trojan 的 WebSocket、H2、HTTPUpgrade/TLS 变体，以及 TUIC、Hysteria2、AnyTLS、Shadowsocks 2022、SOCKS 等能力。以下命令在已完成安装的 VPS 宿主机执行：

```bash
sing-box help
sing-box add reality          # VLESS-REALITY
sing-box add hy               # Hysteria2
sing-box add tuic             # TUIC
sing-box add trojan           # Trojan
sing-box add ss               # Shadowsocks
sing-box add tcp              # VMess-TCP
sing-box add vws example.com  # VLESS-WS-TLS，替换为你控制的域名
sing-box add vh2 example.com  # VLESS-H2-TLS，替换为你控制的域名
sing-box info
sing-box status
```

上游会自动处理部分参数；TLS 域名类方式应使用你控制且已正确配置的域名。创建配置后，按实际配置开放服务器本机防火墙与云安全组中的对应端口。具体参数、协议变体和当前内核兼容性以[上游 README](https://github.com/233boy/sing-box)及[上游使用文档](https://233boy.com/sing-box/sing-box-script/)为准。

## 重要操作风险

- `del` / `ddel` 删除配置时不会二次确认，执行前核对目标并做好备份。
- 卸载、更新、重装和服务重启会改变服务器状态；先阅读上游帮助说明。
- 不要在生产服务器上盲目复制示例；确认端口、域名、客户端兼容性和回滚方案。

## 来源

- [233boy/sing-box GitHub 仓库与 README](https://github.com/233boy/sing-box)
- [上游安装脚本](https://github.com/233boy/sing-box/blob/main/install.sh)
- [233boy sing-box 安装与使用文档](https://233boy.com/sing-box/sing-box-script/)
