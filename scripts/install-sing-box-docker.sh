#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SOURCE_DIR="${REPO_DIR}/deploy/sing-box"
DEST_DIR="${HOME:-/root}/sing-box-docker"

usage() {
  cat <<'USAGE'
用法：bash scripts/install-sing-box-docker.sh [--dir 安装目录]

在 Linux VPS 上部署 sing-box 官方核心容器和带登录认证的 Proxy Admin 管理后台。
要求：Docker Engine、Docker Compose v2 插件、可用的 Docker daemon，以及 GHCR 出网。
默认目录：$HOME/sing-box-docker
USAGE
}

while (($#)); do
  case "$1" in
    --dir)
      if (($# < 2)) || [[ -z "$2" ]]; then
        echo "错误：--dir 后必须提供目录路径。" >&2
        exit 2
      fi
      DEST_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "错误：未知参数：$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "错误：此部署脚本面向 Linux VPS。" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "错误：未找到 Docker。请先按 Docker 官方文档安装并启动 Docker Engine。" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "错误：未找到 Docker Compose v2 插件（docker compose）。" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "错误：无法连接 Docker daemon；请启动 Docker 或检查当前用户权限。" >&2
  exit 1
fi
for file in compose.yaml config.example.json core.Dockerfile proxy-admin.Dockerfile; do
  if [[ ! -f "${SOURCE_DIR}/${file}" ]]; then
    echo "错误：未找到 ${SOURCE_DIR}/${file}。请从完整的项目仓库运行脚本。" >&2
    exit 1
  fi
done
if [[ ! -f "${REPO_DIR}/scripts/sing-box-supervisor.py" || ! -f "${REPO_DIR}/deploy/sing-box/proxy-admin.Dockerfile" ]]; then
  echo "错误：缺少 sing-box 管理组件源文件。请从完整的项目仓库运行脚本。" >&2
  exit 1
fi

umask 077
mkdir -p "${DEST_DIR}/config" "${DEST_DIR}/data/sing-box" "${DEST_DIR}/state"
chmod 700 "${DEST_DIR}" "${DEST_DIR}/config" "${DEST_DIR}/data" "${DEST_DIR}/data/sing-box" "${DEST_DIR}/state"

copy_if_missing() {
  local source="$1" destination="$2"
  if [[ ! -e "$destination" ]]; then
    cp -- "$source" "$destination"
    printf '已创建：%s\n' "$destination"
  else
    printf '保留已有文件：%s\n' "$destination"
  fi
}

copy_if_missing "${SOURCE_DIR}/compose.yaml" "${DEST_DIR}/compose.yaml"
copy_if_missing "${SOURCE_DIR}/config.example.json" "${DEST_DIR}/config.example.json"

random_hex() {
  local value
  value="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$value" =~ ^[0-9a-f]{48}$ ]] || return 1
  printf '%s' "$value"
}

ENV_FILE="${DEST_DIR}/.env"
if [[ ! -e "$ENV_FILE" ]]; then
  : >"$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

get_env() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}
set_env() {
  local key="$1" value="$2" tmp="${ENV_FILE}.tmp"
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 { if (!found) { print key "=" value; found = 1 }; next }
    { print }
    END { if (!found) print key "=" value }
  ' "$ENV_FILE" >"$tmp"
  chmod 600 "$tmp"
  mv -- "$tmp" "$ENV_FILE"
}

if [[ -z "$(get_env PROJECT_ROOT)" ]]; then
  set_env PROJECT_ROOT "$REPO_DIR"
fi
if [[ -z "$(get_env SINGBOX_IMAGE)" ]]; then
  set_env SINGBOX_IMAGE "ghcr.io/sagernet/sing-box:v1.14.3"
fi
if [[ -z "$(get_env ADMIN_USER)" ]]; then
  set_env ADMIN_USER "admin"
fi
if [[ -z "$(get_env ADMIN_PUBLIC_URL)" ]]; then
  set_env ADMIN_PUBLIC_URL ""
fi
if [[ -z "$(get_env SERVER_PUBLIC_ADDRESS)" ]]; then
  set_env SERVER_PUBLIC_ADDRESS ""
fi
admin_password="$(get_env ADMIN_PASSWORD)"
if [[ -z "$admin_password" || "$admin_password" == "CHANGE_ME_TO_A_LONG_RANDOM_SECRET" ]]; then
  admin_password="$(random_hex)"
  set_env ADMIN_PASSWORD "$admin_password"
fi
unset admin_password

if [[ ! -e "${DEST_DIR}/config/config.json" ]]; then
  socks_password="$(random_hex)"
  sed "s/REPLACE_WITH_RANDOM_SECRET/${socks_password}/" \
    "${SOURCE_DIR}/config.example.json" >"${DEST_DIR}/config/config.json"
  chmod 600 "${DEST_DIR}/config/config.json"
  printf '已创建带随机口令且仅监听回环地址的 sing-box 配置：%s/config/config.json\n' "$DEST_DIR"
else
  printf '保留已有 sing-box 配置：%s/config/config.json\n' "$DEST_DIR"
fi
unset socks_password

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "${DEST_DIR}/compose.yaml")
printf '\n正在构建后台和 sing-box 核心镜像……\n'
"${COMPOSE[@]}" build
printf '\n正在使用与核心同版本的 sing-box 校验配置……\n'
"${COMPOSE[@]}" run --rm --no-deps --entrypoint /usr/local/bin/sing-box \
  sing-box -D /var/lib/sing-box check -c /etc/sing-box/config.json
printf '\n正在启动 sing-box 和管理后台……\n'
"${COMPOSE[@]}" up -d

cat <<SUMMARY

部署完成。
后台地址（默认仅本机可访问）：http://127.0.0.1:8000/
部署目录：${DEST_DIR}
登录用户名、随机密码：保存在 ${DEST_DIR}/.env（文件权限 600）
公网管理地址与代理服务器公网地址：可在后台“公网管理地址与客户端订阅”中设置
sing-box 配置：${DEST_DIR}/config/config.json

网页登录后，在“sing-box 核心配置”编辑 JSON 并点击“校验并应用”。后台会用同版本核心校验，
保存前自动备份；核心检测到配置更新后会重启并报告状态，启动失败时尝试恢复上一份可运行配置。
默认 SOCKS5 仅监听 127.0.0.1:2080。远程管理请在前置反向代理上启用 HTTPS 并限制来源 IP/VPN。

常用命令（在部署目录执行）：
  cd "${DEST_DIR}"
  docker compose --env-file .env -f compose.yaml ps
  docker compose --env-file .env -f compose.yaml logs -f
  docker compose --env-file .env -f compose.yaml restart proxy-admin
  docker compose --env-file .env -f compose.yaml down

完整的安装和网页操作步骤见：${REPO_DIR}/docs/sing-box-docker.md
SUMMARY
