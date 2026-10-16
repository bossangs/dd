import os, json, sqlite3, secrets, hashlib, hmac, ipaddress, re, subprocess, tempfile, time, threading, shutil, base64, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, field_validator

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("DB_PATH", str(APP_DIR / "data" / "app.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
if not ADMIN_PASSWORD:
    raise RuntimeError("Set ADMIN_PASSWORD before starting the application.")
CORE = os.getenv("CONFIG_CORE", "xray")
security = HTTPBasic()
app = FastAPI(title="Proxy Protocol Config Admin", version="0.1.0")

PROTOCOLS = {"VLESS", "VMess", "Trojan", "Shadowsocks", "SOCKS5", "HTTP", "HTTPS"}
CORES = {"xray", "sing-box"}
SINGBOX_SCRIPT_URL = "https://github.com/233boy/sing-box/raw/main/install.sh"
SINGBOX_SCRIPT_URLS = frozenset({SINGBOX_SCRIPT_URL, "https://raw.githubusercontent.com/233boy/sing-box/main/install.sh"})
SINGBOX_CONFIG_PATH = Path(os.getenv("SINGBOX_CONFIG_PATH", "")) if os.getenv("SINGBOX_CONFIG_PATH") else None
SINGBOX_STATUS_PATH = Path(os.getenv("SINGBOX_STATUS_PATH", "")) if os.getenv("SINGBOX_STATUS_PATH") else None
SINGBOX_DATA_DIR = os.getenv("SINGBOX_DATA_DIR", "/tmp/sing-box-check")
SINGBOX_BINARY = os.getenv("SINGBOX_BINARY", "/usr/local/bin/sing-box")
SINGBOX_APPLY_TIMEOUT = int(os.getenv("SINGBOX_APPLY_TIMEOUT", "20"))
SINGBOX_APPLY_LOCK = threading.Lock()
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
METHODS = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS nodes(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            protocol TEXT NOT NULL, core TEXT NOT NULL, config TEXT NOT NULL,
            created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS app_settings(
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        defaults = (
            ("singbox_script_url", SINGBOX_SCRIPT_URL),
            ("admin_public_url", normalize_admin_url(os.getenv("ADMIN_PUBLIC_URL", ""))),
            ("server_public_address", normalize_public_host(os.getenv("SERVER_PUBLIC_ADDRESS", ""))
             if os.getenv("SERVER_PUBLIC_ADDRESS", "").strip() else ""),
            ("subscription_token", secrets.token_urlsafe(32)),
            ("generated_profiles", "[]"),
        )
        for key, value in defaults:
            con.execute("INSERT OR IGNORE INTO app_settings(key,value,updated_at) VALUES(?,?,?)",
                        (key, value, now()))
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass

def get_setting(key: str, default: str = "") -> str:
    with db() as con:
        row = con.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    with db() as con:
        con.execute("""INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, now()))

def normalize_public_host(value: str) -> str:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    if not value or any(c in value for c in "/:@?#\\\\"):
        raise ValueError("请输入纯域名或 IP 地址，不含协议、端口或路径")
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("域名格式无效")
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                  for label in host.split(".")):
        raise ValueError("域名格式无效")
    return host

def normalize_admin_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        hostname = normalize_public_host(parts.hostname or "")
        port = parts.port
    except (ValueError, UnicodeError) as exc:
        raise ValueError("公网管理地址格式无效") from exc
    if (parts.scheme.lower() != "https" or not hostname or port == 0 or parts.username or parts.password
            or parts.path not in {"", "/"} or parts.query or parts.fragment):
        raise ValueError("管理后台公网地址必须是 HTTPS 根地址，例如 https://admin.example.com")
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port and port != 443:
        netloc += f":{port}"
    return urlunsplit(("https", netloc, "", "", ""))

init_db()

def require_auth(creds: HTTPBasicCredentials = Depends(security)):
    user_ok = hmac.compare_digest(creds.username.encode(), ADMIN_USER.encode())
    pass_ok = hmac.compare_digest(creds.password.encode(), ADMIN_PASSWORD.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Authentication required",
                            headers={"WWW-Authenticate": "Basic"})
    return creds.username

def audit(username: str, action: str, detail: str):
    with db() as con:
        con.execute("INSERT INTO audit(username,action,detail,created_at) VALUES(?,?,?,?)",
                    (username, action, detail[:500], now()))

class NodeIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    protocol: Literal["VLESS","VMess","Trojan","Shadowsocks","SOCKS5","HTTP","HTTPS"]
    core: Literal["xray","sing-box"]
    listen: str = "0.0.0.0"
    port: int = Field(ge=1, le=65535)
    uuid: str | None = None
    password: str | None = Field(default=None, max_length=256)
    method: str | None = None
    network: Literal["tcp","ws","grpc"] = "tcp"
    tls: bool = False
    server_name: str | None = Field(default=None, max_length=253)
    path: str | None = Field(default=None, max_length=256)
    username: str | None = Field(default=None, max_length=128)

    @field_validator("name")
    @classmethod
    def safe_name(cls, v):
        if not v.strip() or any(ord(c) < 32 for c in v):
            raise ValueError("Invalid node name")
        return v.strip()

    @field_validator("listen")
    @classmethod
    def safe_listen(cls, v):
        if v not in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("listen must be an IP address")
        return v

    @field_validator("uuid")
    @classmethod
    def valid_uuid(cls, v):
        if v and not UUID_RE.match(v):
            raise ValueError("uuid must be a valid UUID")
        return v

    @field_validator("method")
    @classmethod
    def valid_method(cls, v):
        if v and v not in METHODS:
            raise ValueError("Unsupported Shadowsocks method")
        return v

    @field_validator("server_name")
    @classmethod
    def valid_server_name(cls, v):
        if v and not re.fullmatch(r"[A-Za-z0-9.-]+", v):
            raise ValueError("Invalid server_name")
        return v

    @field_validator("path")
    @classmethod
    def valid_path(cls, v):
        if v and (not v.startswith("/") or "\n" in v):
            raise ValueError("path must begin with /")
        return v

    def model_post_init(self, __context):
        if self.protocol in {"VLESS", "VMess"} and not self.uuid:
            raise ValueError(f"{self.protocol} requires uuid")
        if self.protocol in {"Trojan", "Shadowsocks"} and not self.password:
            raise ValueError(f"{self.protocol} requires password")
        if self.protocol == "Shadowsocks" and not self.method:
            raise ValueError("Shadowsocks requires method")
        if self.protocol in {"SOCKS5", "HTTP", "HTTPS"} and self.username and not self.password:
            raise ValueError("password is required when username is set")
        if self.tls and not self.server_name:
            raise ValueError("server_name is required when tls=true")
        if self.protocol in {"SOCKS5", "HTTP", "HTTPS"} and self.core == "sing-box" and self.protocol == "HTTPS":
            # HTTPS proxy support varies by sing-box version; keep generation explicit.
            pass

class SingBoxSettingsIn(BaseModel):
    script_url: str

    @field_validator("script_url")
    @classmethod
    def official_script_only(cls, value):
        value = value.strip()
        if value not in SINGBOX_SCRIPT_URLS:
            raise ValueError("Only the official 233boy/sing-box install.sh URLs are allowed")
        return value

class SingBoxRuntimeConfigIn(BaseModel):
    config: str = Field(min_length=2, max_length=1_000_000)

class PublicLinksIn(BaseModel):
    admin_public_url: str = Field(default="", max_length=300)
    server_public_address: str = Field(default="", max_length=253)

    @field_validator("admin_public_url")
    @classmethod
    def valid_admin_public_url(cls, value):
        return normalize_admin_url(value)

    @field_validator("server_public_address")
    @classmethod
    def valid_server_public_address(cls, value):
        return normalize_public_host(value) if value.strip() else ""

class MultiProtocolGenerateIn(BaseModel):
    name: str = Field(default="My sing-box", min_length=1, max_length=80)
    server_address: str | None = Field(default=None, max_length=253)
    vless_port: int = Field(default=8443, ge=1, le=65535)
    shadowsocks_port: int = Field(default=8388, ge=1, le=65535)
    reality_server_name: str = Field(default="www.microsoft.com", min_length=1, max_length=253)

    @field_validator("name")
    @classmethod
    def safe_profile_name(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 for c in value):
            raise ValueError("节点名称无效")
        return value

    @field_validator("server_address")
    @classmethod
    def valid_generator_address(cls, value):
        return normalize_public_host(value) if value and value.strip() else None

    @field_validator("reality_server_name")
    @classmethod
    def valid_reality_server_name(cls, value):
        host = normalize_public_host(value)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        raise ValueError("Reality 握手名称应使用域名，而不是 IP 地址")

def singbox_runtime_ready():
    if not SINGBOX_CONFIG_PATH or not SINGBOX_STATUS_PATH:
        raise HTTPException(503, "sing-box runtime management is not configured")
    if not Path(SINGBOX_BINARY).is_file():
        raise HTTPException(503, "sing-box validator binary is unavailable")
    if not SINGBOX_CONFIG_PATH.is_file() or SINGBOX_CONFIG_PATH.is_symlink():
        raise HTTPException(503, "sing-box config file is unavailable")
    return SINGBOX_CONFIG_PATH

def singbox_runtime_status():
    if not SINGBOX_STATUS_PATH or not SINGBOX_STATUS_PATH.is_file():
        return {"state": "starting", "config_sha256": None, "updated_at": None, "error": None}
    try:
        value = json.loads(SINGBOX_STATUS_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {"state": "unknown"}
    except (OSError, json.JSONDecodeError):
        return {"state": "starting", "config_sha256": None, "updated_at": None, "error": None}

def singbox_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def atomic_singbox_write(path: Path, value: bytes):
    fd, temporary = tempfile.mkstemp(prefix=".sing-box-apply-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

def validate_singbox_candidate(candidate: Path, config_dir: Path):
    try:
        result = subprocess.run(
            [SINGBOX_BINARY, "-D", SINGBOX_DATA_DIR, "check", "-c", str(candidate)],
            cwd=str(config_dir), capture_output=True, text=True, timeout=30, check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "sing-box 配置校验超时")
    except OSError as exc:
        raise HTTPException(503, f"无法运行 sing-box 配置校验：{exc}")
    if result.returncode != 0:
        detail = (result.stdout + "\n" + result.stderr).strip()[:1200]
        raise HTTPException(422, "sing-box check 校验失败：" + (detail or "配置无效"))

def save_singbox_backup(current: bytes, old_digest: str):
    backup_dir = DB_PATH.parent / "singbox-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = backup_dir / f"config-{stamp}-{old_digest[:12]}-{secrets.token_hex(3)}.json"
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(current)
        stream.flush()
        os.fsync(stream.fileno())
    old_backups = sorted(backup_dir.glob("config-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in old_backups[10:]:
        stale.unlink(missing_ok=True)
    return backup

def xray_config(n: dict[str, Any]) -> dict[str, Any]:
    p, port, listen = n["protocol"], n["port"], n["listen"]
    stream = {"network": n["network"], "security": "tls" if n["tls"] else "none"}
    if n["tls"]:
        stream["tlsSettings"] = {"serverName": n["server_name"]}
    if n["network"] == "ws":
        stream["wsSettings"] = {"path": n.get("path") or "/"}
    elif n["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": (n.get("path") or "/").strip("/")}
    if p in {"VLESS", "VMess"}:
        user = {"id": n["uuid"], "email": n["name"]}
        if p == "VLESS":
            user["encryption"] = "none"
        else:
            user["alterId"] = 0
        settings = {"clients": [user]}
        protocol = p.lower()
    elif p == "Trojan":
        settings, protocol = {"clients": [{"password": n["password"], "email": n["name"]}]}, "trojan"
    elif p == "Shadowsocks":
        settings, protocol = {"method": n["method"], "password": n["password"], "network": "tcp,udp"}, "shadowsocks"
    elif p in {"SOCKS5", "HTTP", "HTTPS"}:
        protocol = "socks" if p == "SOCKS5" else "http"
        settings = {"auth": "password" if n.get("username") else "noauth"}
        if n.get("username"):
            settings["accounts"] = [{"user": n["username"], "pass": n["password"]}]
        if p == "HTTPS":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"certificates": []}
    else:
        raise ValueError("Unsupported protocol")
    inbound = {"tag": f"node-{n['id']}", "listen": listen, "port": port,
               "protocol": protocol, "settings": settings}
    if p in {"VLESS", "VMess", "Trojan"}:
        inbound["streamSettings"] = stream
    return {"log": {"loglevel": "warning"}, "inbounds": [inbound],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]}

def singbox_config(n: dict[str, Any]) -> dict[str, Any]:
    p = n["protocol"]
    typ = {"VLESS":"vless","VMess":"vmess","Trojan":"trojan","Shadowsocks":"shadowsocks",
           "SOCKS5":"socks","HTTP":"http","HTTPS":"http"}[p]
    inbound: dict[str, Any] = {"type": typ, "tag": f"node-{n['id']}",
                               "listen": n["listen"], "listen_port": n["port"]}
    if p in {"VLESS", "VMess"}:
        inbound["users"] = [{"uuid": n["uuid"]}]
    elif p == "Trojan":
        inbound["users"] = [{"password": n["password"]}]
    elif p == "Shadowsocks":
        inbound.update({"method": n["method"], "password": n["password"]})
    elif p in {"SOCKS5", "HTTP", "HTTPS"} and n.get("username"):
        inbound["users"] = [{"username": n["username"], "password": n["password"]}]
    if n["network"] in {"ws", "grpc"} and p in {"VLESS","VMess","Trojan"}:
        inbound["transport"] = {"type": n["network"]}
        if n["network"] == "ws":
            inbound["transport"]["path"] = n.get("path") or "/"
        else:
            inbound["transport"]["service_name"] = (n.get("path") or "").strip("/")
    if n["tls"]:
        inbound["tls"] = {"enabled": True, "server_name": n["server_name"]}
    return {"log": {"level": "warn"}, "inbounds": [inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}]}

def generate(n: dict[str, Any]) -> dict[str, Any]:
    if n["core"] == "xray":
        return xray_config(n)
    return singbox_config(n)

def safe_node(row):
    item = dict(row)
    cfg = json.loads(item.pop("config"))
    for k in ("password", "uuid"):
        if cfg.get(k):
            cfg[k] = "••••••••"
    item["config"] = cfg
    return item

@app.get("/", response_class=HTMLResponse)
def home(user: str = Depends(require_auth)):
    with db() as con:
        rows = con.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    node_json = json.dumps([safe_node(r) for r in rows], ensure_ascii=False)
    return HTMLResponse(HTML.replace("__NODES__", node_json))

@app.get("/api/nodes")
def list_nodes(user: str = Depends(require_auth)):
    with db() as con:
        rows = con.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    return [safe_node(r) for r in rows]

@app.get("/api/settings/sing-box")
def get_singbox_settings(user: str = Depends(require_auth)):
    with db() as con:
        row = con.execute("SELECT value FROM app_settings WHERE key=?", ("singbox_script_url",)).fetchone()
    return {"script_url": row["value"] if row else SINGBOX_SCRIPT_URL,
            "allowed_script_urls": sorted(SINGBOX_SCRIPT_URLS)}

@app.put("/api/settings/sing-box")
def update_singbox_settings(body: SingBoxSettingsIn, user: str = Depends(require_auth)):
    with db() as con:
        con.execute("""INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            ("singbox_script_url", body.script_url, now()))
    audit(user, "update_singbox_script_url", body.script_url)
    return {"script_url": body.script_url}

@app.get("/api/sing-box/runtime")
def get_singbox_runtime(user: str = Depends(require_auth)):
    path = singbox_runtime_ready()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(503, f"无法读取 sing-box 配置：{exc}")
    if len(content.encode("utf-8")) > 1_000_000:
        raise HTTPException(413, "sing-box 配置超过 1 MB 管理限制")
    return private_json({"config": content, "status": singbox_runtime_status()})

@app.put("/api/sing-box/runtime")
def apply_singbox_runtime(body: SingBoxRuntimeConfigIn, user: str = Depends(require_auth)):
    path = singbox_runtime_ready()
    raw = body.config.encode("utf-8")
    if len(raw) > 1_000_000:
        raise HTTPException(413, "sing-box 配置超过 1 MB 管理限制")
    try:
        parsed = json.loads(body.config)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, f"JSON 语法错误：第 {exc.lineno} 行，第 {exc.colno} 列")
    if not isinstance(parsed, dict):
        raise HTTPException(422, "sing-box 配置根节点必须是 JSON 对象")

    with SINGBOX_APPLY_LOCK:
        try:
            old = path.read_bytes()
        except OSError as exc:
            raise HTTPException(503, f"无法读取当前 sing-box 配置：{exc}")
        old_digest = singbox_digest(old)
        new_digest = singbox_digest(raw)
        status = singbox_runtime_status()
        if new_digest == old_digest and status.get("state") == "running" and status.get("config_sha256") == new_digest:
            return {"applied": True, "unchanged": True, "config_sha256": new_digest, "status": status}

        fd, candidate_name = tempfile.mkstemp(prefix=".sing-box-candidate-", suffix=".json", dir=str(path.parent))
        candidate = Path(candidate_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(candidate, 0o600)
            validate_singbox_candidate(candidate, path.parent)
        finally:
            candidate.unlink(missing_ok=True)

        backup = save_singbox_backup(old, old_digest)
        atomic_singbox_write(path, raw)
        deadline = time.monotonic() + max(1, min(SINGBOX_APPLY_TIMEOUT, 60))
        while time.monotonic() < deadline:
            status = singbox_runtime_status()
            if (status.get("requested_sha256") == new_digest
                    and status.get("state") == "running"
                    and status.get("config_sha256") == new_digest):
                audit(user, "apply_singbox_config", f"sha256={new_digest}")
                return {"applied": True, "unchanged": False, "config_sha256": new_digest,
                        "backup": backup.name, "status": status}
            if (status.get("requested_sha256") == new_digest
                    and status.get("state") in {"invalid", "failed", "rolled_back"}):
                detail = status.get("error") or "核心未能应用新配置；已恢复上一份可运行配置（如有）"
                audit(user, "apply_singbox_config_failed", f"sha256={new_digest}")
                raise HTTPException(409, detail[:1200])
            time.sleep(0.25)
        status = singbox_runtime_status()
        audit(user, "apply_singbox_config_pending", f"sha256={new_digest}")
        return JSONResponse(status_code=202, content={
            "applied": False, "pending": True, "config_sha256": new_digest,
            "message": "配置已保存并通过 check 校验，仍在等待 sing-box 监督器确认应用。",
            "backup": backup.name, "status": status,
        })

def subscription_path() -> str:
    return "/sub/" + get_setting("subscription_token")

def subscription_url() -> str:
    path = subscription_path()
    admin_url = get_setting("admin_public_url").rstrip("/")
    return admin_url + path if admin_url else path

def uri_host(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
        return f"[{parsed.compressed}]" if parsed.version == 6 else parsed.compressed
    except ValueError:
        return value

def profile_uri(profile: dict[str, Any], server_address: str | None = None) -> str:
    host = uri_host(server_address or profile["address"])
    label = quote(profile["name"], safe="")
    if profile["protocol"] == "vless-reality":
        params = {
            "encryption": "none", "security": "reality", "sni": profile["sni"],
            "fp": "chrome", "pbk": profile["public_key"], "sid": profile["short_id"],
            "type": "tcp", "flow": "xtls-rprx-vision",
        }
        return (f"vless://{profile['uuid']}@{host}:{profile['port']}?"
                f"{urlencode(params, quote_via=quote)}#{label}")
    userinfo = base64.urlsafe_b64encode(
        f"{profile['method']}:{profile['password']}".encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"ss://{userinfo}@{host}:{profile['port']}#{label}"

def singbox_reality_keypair() -> tuple[str, str]:
    try:
        result = subprocess.run([SINGBOX_BINARY, "generate", "reality-keypair"],
                                capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(503, f"无法生成 Reality 密钥：{exc}")
    if result.returncode != 0:
        raise HTTPException(503, "sing-box Reality 密钥生成失败")
    values = dict(re.findall(r"(?m)^([A-Za-z]+):\s*(\S+)\s*$", result.stdout))
    private_key, public_key = values.get("PrivateKey"), values.get("PublicKey")
    if not private_key or not public_key:
        raise HTTPException(503, "sing-box Reality 密钥输出格式无法识别")
    return private_key, public_key

def active_generated_profiles() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = singbox_runtime_ready()
    status = singbox_runtime_status()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HTTPException(503, f"无法读取 sing-box 运行配置：{exc}")
    digest = singbox_digest(raw)
    if status.get("state") != "running" or status.get("config_sha256") != digest:
        return [], status
    try:
        config = json.loads(raw)
        inbounds = config.get("inbounds", [])
        with db() as con:
            row = con.execute("SELECT value FROM app_settings WHERE key=?", ("generated_profiles",)).fetchone()
        profiles = json.loads(row["value"] if row else "[]")
    except (json.JSONDecodeError, TypeError, AttributeError):
        return [], status
    if not isinstance(inbounds, list) or not isinstance(profiles, list):
        return [], status
    by_tag = {item.get("tag"): item for item in inbounds if isinstance(item, dict)}
    active = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        inbound = by_tag.get(profile.get("tag"))
        if not inbound or inbound.get("listen_port") != profile.get("port"):
            continue
        if profile.get("protocol") == "vless-reality":
            users = inbound.get("users", [])
            tls = inbound.get("tls", {})
            reality = tls.get("reality", {}) if isinstance(tls, dict) else {}
            key_hash = hashlib.sha256(str(reality.get("private_key", "")).encode()).hexdigest()
            if (inbound.get("type") != "vless" or not users
                    or users[0].get("uuid") != profile.get("uuid")
                    or key_hash != profile.get("private_key_sha256")
                    or profile.get("short_id") not in reality.get("short_id", [])):
                continue
        elif profile.get("protocol") == "shadowsocks":
            if (inbound.get("type") != "shadowsocks"
                    or inbound.get("method") != profile.get("method")
                    or inbound.get("password") != profile.get("password")):
                continue
        else:
            continue
        active.append(profile)
    return active, status

def private_json(value: dict[str, Any]) -> JSONResponse:
    return JSONResponse(content=value, headers={
        "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff",
    })

@app.get("/api/settings/public-links")
def get_public_links_settings(user: str = Depends(require_auth)):
    path = subscription_path()
    return private_json({
        "admin_public_url": get_setting("admin_public_url"),
        "server_public_address": get_setting("server_public_address"),
        "subscription_path": path,
        "subscription_url": subscription_url(),
        "subscription_plain_url": subscription_url() + "/plain",
    })

@app.put("/api/settings/public-links")
def update_public_links_settings(body: PublicLinksIn, user: str = Depends(require_auth)):
    set_setting("admin_public_url", body.admin_public_url)
    set_setting("server_public_address", body.server_public_address)
    audit(user, "update_public_links_settings",
          f"admin_url={body.admin_public_url} server_address={body.server_public_address}")
    return get_public_links_settings(user)

@app.post("/api/settings/public-links/rotate-subscription")
def rotate_subscription_token(user: str = Depends(require_auth)):
    set_setting("subscription_token", secrets.token_urlsafe(32))
    audit(user, "rotate_subscription_token", "subscription token rotated")
    return get_public_links_settings(user)

@app.post("/api/sing-box/generate-multi")
def generate_singbox_multi(body: MultiProtocolGenerateIn, user: str = Depends(require_auth)):
    path = singbox_runtime_ready()
    address = body.server_address or get_setting("server_public_address")
    if not address:
        raise HTTPException(422, "请先保存公网服务器域名或 IP 地址")
    if body.vless_port == body.shadowsocks_port:
        raise HTTPException(422, "VLESS Reality 与 Shadowsocks 必须使用不同端口")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(422, f"当前核心配置无法解析：{exc}")
    if not isinstance(config, dict):
        raise HTTPException(422, "当前 sing-box 配置根节点必须是 JSON 对象")
    inbounds = config.setdefault("inbounds", [])
    if not isinstance(inbounds, list):
        raise HTTPException(422, "当前 sing-box 配置的 inbounds 必须是数组")
    reserved = {"proxy-admin-generated-vless-reality", "proxy-admin-generated-shadowsocks"}
    inbounds = [item for item in inbounds if not isinstance(item, dict) or item.get("tag") not in reserved]
    wanted_ports = {body.vless_port, body.shadowsocks_port}
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        try:
            existing_port = int(inbound.get("listen_port", inbound.get("port", 0)))
        except (TypeError, ValueError):
            existing_port = 0
        if existing_port in wanted_ports:
            raise HTTPException(409, f"端口 {existing_port} 已被现有入站占用，请选择其他端口")

    private_key, public_key = singbox_reality_keypair()
    client_uuid = str(uuid.uuid4())
    short_id = secrets.token_hex(8)
    ss_password = secrets.token_urlsafe(24)
    vless_tag = "proxy-admin-generated-vless-reality"
    ss_tag = "proxy-admin-generated-shadowsocks"
    inbounds.extend([
        {
            "type": "vless", "tag": vless_tag, "listen": "0.0.0.0",
            "listen_port": body.vless_port,
            "users": [{"uuid": client_uuid, "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True, "server_name": body.reality_server_name,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": body.reality_server_name, "server_port": 443},
                    "private_key": private_key, "short_id": [short_id],
                },
            },
        },
        {
            "type": "shadowsocks", "tag": ss_tag, "listen": "0.0.0.0",
            "listen_port": body.shadowsocks_port, "method": "aes-128-gcm",
            "password": ss_password,
        },
    ])
    config["inbounds"] = inbounds
    if not isinstance(config.get("outbounds"), list) or not config["outbounds"]:
        config["outbounds"] = [{"type": "direct", "tag": "direct"}]
    profiles = [
        {
            "protocol": "vless-reality", "tag": vless_tag, "name": body.name + " VLESS Reality",
            "address": address, "port": body.vless_port, "uuid": client_uuid,
            "sni": body.reality_server_name, "public_key": public_key, "short_id": short_id,
            "private_key_sha256": hashlib.sha256(private_key.encode()).hexdigest(),
        },
        {
            "protocol": "shadowsocks", "tag": ss_tag, "name": body.name + " Shadowsocks",
            "address": address, "port": body.shadowsocks_port,
            "method": "aes-128-gcm", "password": ss_password,
        },
    ]
    set_setting("generated_profiles", json.dumps(profiles, ensure_ascii=False))
    set_setting("server_public_address", address)
    node_links = [{"protocol": "VLESS + Reality", "name": profiles[0]["name"],
                   "share_url": profile_uri(profiles[0])},
                  {"protocol": "Shadowsocks", "name": profiles[1]["name"],
                   "share_url": profile_uri(profiles[1])}]
    audit(user, "generate_singbox_multi", f"server={address} ports={body.vless_port},{body.shadowsocks_port}")
    return private_json({
        "config": json.dumps(config, ensure_ascii=False, indent=2),
        "nodes": node_links,
        "subscription_url": subscription_url(),
        "message": "双协议配置已生成到编辑器草稿；审阅并点击“校验并应用配置”后节点和订阅才会生效。",
    })

@app.get("/api/sing-box/share-links")
def get_singbox_share_links(user: str = Depends(require_auth)):
    profiles, status = active_generated_profiles()
    address = get_setting("server_public_address")
    nodes = [{"protocol": "VLESS + Reality" if p["protocol"] == "vless-reality" else "Shadowsocks",
              "name": p["name"], "share_url": profile_uri(p, address or None)} for p in profiles]
    return private_json({"active": bool(nodes), "nodes": nodes, "status": status,
            "admin_public_url": get_setting("admin_public_url"),
            "subscription_path": subscription_path(),
            "subscription_url": subscription_url(),
            "subscription_plain_url": subscription_url() + "/plain"})

def public_subscription(token: str, plain: bool = False) -> Response:
    expected = get_setting("subscription_token")
    if not expected or not hmac.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(404, "Not found")
    profiles, _status = active_generated_profiles()
    if not profiles:
        raise HTTPException(503, "订阅尚无已运行的节点；请管理员先应用生成的配置")
    address = get_setting("server_public_address")
    lines = [profile_uri(p, address or None) for p in profiles]
    payload = "\n".join(lines) + "\n"
    if not plain:
        payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return Response(content=payload, media_type="text/plain; charset=utf-8", headers={
        "Cache-Control": "no-store, private", "X-Content-Type-Options": "nosniff",
        "X-Robots-Tag": "noindex, nofollow, noarchive",
    })

@app.get("/sub/{token}")
def get_subscription(token: str):
    return public_subscription(token)

@app.get("/sub/{token}/plain")
def get_plain_subscription(token: str):
    return public_subscription(token, plain=True)

@app.post("/api/nodes")
def create_node(body: NodeIn, user: str = Depends(require_auth)):
    data = body.model_dump()
    # A credential-free SOCKS/HTTP proxy is allowed only when intentionally requested.
    with db() as con:
        cur = con.execute("INSERT INTO nodes(name,protocol,core,config,created_at) VALUES(?,?,?,?,?)",
            (data["name"], data["protocol"], data["core"], json.dumps(data, ensure_ascii=False), now()))
        data["id"] = cur.lastrowid
        cfg = generate(data)
        con.execute("UPDATE nodes SET config=? WHERE id=?", (json.dumps(data, ensure_ascii=False), cur.lastrowid))
    audit(user, "create_node", f"id={data['id']} protocol={data['protocol']} core={data['core']}")
    return {"id": data["id"], "config": cfg, "warning": "Generated config is a draft; validate with the installed core before deployment."}

@app.get("/api/nodes/{node_id}/config")
def node_config(node_id: int, core: Literal["xray","sing-box"] | None = None,
                user: str = Depends(require_auth)):
    with db() as con:
        row = con.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Node not found")
    n = json.loads(row["config"])
    n["id"] = node_id
    if core:
        n["core"] = core
    cfg = generate(n)
    audit(user, "preview_config", f"id={node_id} core={n['core']}")
    return cfg

@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: int, user: str = Depends(require_auth)):
    with db() as con:
        cur = con.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Node not found")
    audit(user, "delete_node", f"id={node_id}")
    return {"ok": True}

@app.get("/api/audit")
def audit_log(user: str = Depends(require_auth)):
    with db() as con:
        rows = con.execute("SELECT id,username,action,detail,created_at FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]

@app.get("/health")
def health():
    return {"status": "ok"}

HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>代理协议配置管理</title><style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#182230;background:#f4f6fa}
body{max-width:1100px;margin:28px auto;padding:0 16px}.card{background:#fff;border:1px solid #e1e6ef;border-radius:14px;padding:20px;margin:16px 0;box-shadow:0 3px 12px #16233a08}
h1{font-size:26px}h2{font-size:18px;margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
label{display:block;font-size:13px;color:#526071}input,select{box-sizing:border-box;width:100%;padding:10px;margin:5px 0 10px;border:1px solid #ccd4df;border-radius:8px;background:#fff}
button{border:0;border-radius:8px;padding:10px 14px;background:#2158c7;color:white;cursor:pointer;margin:4px}button.secondary{background:#e8edf5;color:#1d2c43}pre{white-space:pre-wrap;overflow-wrap:anywhere;overflow:auto;background:#101827;color:#dbeafe;border-radius:10px;padding:14px}textarea{box-sizing:border-box;width:100%;min-height:420px;padding:14px;border:1px solid #ccd4df;border-radius:8px;font:13px/1.5 ui-monospace,SFMono-Regular,monospace;tab-size:2}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e8ecf2;font-size:14px}small,.muted{color:#68778a}.pill{display:inline-block;background:#e9f0ff;padding:4px 8px;border-radius:99px}
</style></head><body>
<h1>代理协议配置管理</h1><p class="muted">管理员控制台 · 配置草稿管理 · 生成结果需经对应核心验证</p>
<div class="card"><h2>新增节点</h2><form id="nodeform"><div class="grid">
<label>节点名称<input name="name" required maxlength="80" placeholder="例如：edge-01"></label>
<label>协议<select name="protocol" id="protocol"><option>VLESS</option><option>VMess</option><option>Trojan</option><option>Shadowsocks</option><option>SOCKS5</option><option>HTTP</option><option>HTTPS</option></select></label>
<label>配置核心<select name="core"><option value="xray">Xray-core</option><option value="sing-box">sing-box</option></select></label>
<label>监听 IP<input name="listen" value="127.0.0.1" required></label>
<label>端口<input name="port" type="number" min="1" max="65535" value="18443" required></label>
<label>UUID（VLESS/VMess）<input name="uuid" placeholder="xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"></label>
<label>密码（Trojan/SS/代理认证）<input name="password" type="password" autocomplete="new-password"></label>
<label>Shadowsocks 加密方法<select name="method"><option value="">不适用</option><option>aes-128-gcm</option><option>aes-256-gcm</option><option>chacha20-ietf-poly1305</option><option>2022-blake3-aes-128-gcm</option><option>2022-blake3-aes-256-gcm</option></select></label>
<label>传输方式<select name="network"><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option></select></label>
<label>TLS<input name="tls" type="checkbox" value="true" style="width:auto;margin-left:8px"></label>
<label>服务器名称 / SNI<input name="server_name" placeholder="example.com"></label>
<label>WebSocket 路径 / gRPC 服务名<input name="path" placeholder="/proxy"></label>
<label>代理用户名（可选）<input name="username" autocomplete="off"></label>
</div><button type="submit">保存并生成配置</button><span id="status" class="muted"></span></form></div>
<div class="card"><h2>233boy.com / sing-box 上游脚本</h2><p class="muted">保存并查看官方脚本地址，以及复制本管理后台 Docker Compose 和 VPS 宿主机安装命令。此区域只展示命令，不会从 Web 应用下载或执行上游脚本。</p>
<form id="singboxSettingsForm"><label>官方安装脚本地址<select id="singboxScriptUrl" required></select></label><button type="submit">保存上游地址</button><span id="singboxStatus" class="muted"></span></form>
<h3>按步骤操作</h3><ol class="muted"><li>先区分目标：项目根目录的 Compose 命令部署本管理后台；独立的核心 Docker 脚本部署 sing-box 容器；233boy 安装器则在 VPS 宿主机安装。</li><li>部署后台时，在已解压的项目根目录复制并编辑 .env，设置管理员账号和强随机密码，再运行 Docker Compose 命令。</li><li>使用本页下方的核心 Docker 部署脚本前，确认 Linux VPS 已安装 Docker Engine 与 Docker Compose v2，且可访问官方镜像仓库。</li><li>若使用 233boy 安装器，检查 VPS 系统、架构、root 权限、GitHub 出网、域名和防火墙端口；安装器要求 root 与 systemd/OpenRC。</li><li>在 VPS 下载 233boy 脚本并检查内容、查看 -h 帮助；确认来源和内容后才运行。不要把宿主机安装脚本放进后台容器执行。</li></ol>
<div class="grid"><div><h3>部署本管理后台（Docker Compose）</h3><p class="muted">在已解压的项目目录执行。先编辑 .env 设置独立强密码；服务默认只绑定本机 127.0.0.1:8000。</p><button class="secondary" type="button" onclick="copyText('dockerDeployCmd')">复制 Docker 命令</button><pre id="dockerDeployCmd">cp .env.example .env&#10;# 编辑 .env：设置 ADMIN_USER 和强随机 ADMIN_PASSWORD&#10;docker compose up --build -d&#10;docker compose logs -f</pre></div>
<div><h3>在 VPS 宿主机安装 sing-box</h3><p class="muted">该上游安装器要求 root，并依赖 systemd/OpenRC；这是宿主机安装，不是容器安装。建议先下载、审阅再执行。</p><button class="secondary" type="button" onclick="copyText('singboxInstallCmd')">复制宿主机安装命令</button><pre id="singboxInstallCmd">正在读取已保存的上游地址…</pre></div>
<div><h3>安装后的多协议示例</h3><p class="muted">安装器默认创建 VLESS-REALITY。以下示例由 233boy 管理脚本提供；TLS 域名类配置需替换为你有权使用的域名。</p><button class="secondary" type="button" onclick="copyText('singboxProtocolCmd')">复制协议示例</button><pre id="singboxProtocolCmd">sing-box help&#10;sing-box add reality&#10;sing-box add hy&#10;sing-box add tuic&#10;sing-box add trojan&#10;sing-box add ss&#10;sing-box add tcp&#10;sing-box add vws example.com&#10;sing-box add vh2 example.com&#10;sing-box info</pre></div></div>
<p class="muted">上游仓库：<a href="https://github.com/233boy/sing-box" target="_blank" rel="noopener noreferrer">github.com/233boy/sing-box</a> · 安装与参数说明：<a href="https://233boy.com/sing-box/sing-box-script/" target="_blank" rel="noopener noreferrer">233boy.com 文档</a></p>
<p class="muted">安全提示：233boy 脚本以 root 权限安装软件并配置服务；执行前审阅源代码。删除配置（del/ddel）会直接生效；不要在生产服务器上盲目执行示例。</p></div>
<div class="card"><h2>sing-box 核心 Docker 部署</h2><p class="muted">此脚本部署 sing-box 核心容器，不是本管理后台。它不会自动安装 Docker，不会挂载 Docker Socket，也不会把后台节点草稿自动写入核心配置。</p>
<ol class="muted"><li>在 Linux VPS 上准备 Docker Engine 和 Docker Compose v2，并从项目仓库根目录运行下面命令。</li><li>初始化脚本默认在 $HOME/sing-box-docker 部署，创建带随机密码的 SOCKS5 配置（仅监听 127.0.0.1:2080），校验后启动官方核心镜像。</li><li>如需对外提供服务，先按 sing-box 配置格式编辑 config/config.json，明确监听地址、协议、凭据和证书，再校验配置并重启；只放行实际使用的端口。</li><li>Compose 使用 Linux host 网络；默认配置只绑定回环地址。TUN 与特权模式未启用，配置文件含敏感凭据，应限制访问。</li></ol>
<button class="secondary" type="button" onclick="copyText('singboxDockerCmd')">复制核心 Docker 部署命令</button><pre id="singboxDockerCmd">git clone https://github.com/bossangs/dd.git
cd dd
bash scripts/install-sing-box-docker.sh</pre>
<p class="muted">部署文档：<a href="https://github.com/bossangs/dd/blob/main/docs/sing-box-docker.md" target="_blank" rel="noopener noreferrer">sing-box Docker 部署</a>。</p></div>
<div class="card"><h2>sing-box 核心配置</h2><p class="muted">使用当前管理员登录认证。点击“校验并应用”后，后台会用与核心相同版本的 sing-box 执行 check、备份旧配置并原子保存；核心容器内监督器会重启 sing-box，失败时尝试恢复上一份可运行配置。应用配置会短暂中断现有连接。</p>
<p><strong>运行状态：</strong><span id="singboxRuntimeStatus" class="muted">正在读取配置管理状态…</span></p>
<label for="singboxRuntimeConfig">当前 sing-box JSON 配置（包含凭据，请勿公开或分享此页面）</label><textarea id="singboxRuntimeConfig" spellcheck="false" autocomplete="off" autocapitalize="off"></textarea>
<button class="secondary" type="button" onclick="loadSingBoxRuntime()">重新读取</button><button type="button" onclick="applySingBoxRuntime()">校验并应用配置</button>
<p class="muted">配置管理仅在使用本项目的 sing-box Docker 部署脚本后可用；核心监听端口使用宿主机网络，防火墙仍需按实际配置单独设置。</p></div>
<div class="card"><h2>公网管理地址与客户端订阅</h2><p class="muted">后台容器端口仍只绑定 127.0.0.1；请先用 HTTPS 反向代理发布后台，再填写其根地址。服务器公网域名/IP 用于生成客户端节点，二者不是同一个地址。</p>
<form id="publicLinksForm"><div class="grid">
<label>后台公网 HTTPS 地址<input id="adminPublicUrl" type="url" placeholder="https://admin.example.com" autocomplete="url"></label>
<label>代理服务器公网域名或 IP<input id="serverPublicAddress" type="text" placeholder="proxy.example.com 或 203.0.113.10" autocomplete="off" autocapitalize="off"></label>
</div><button type="submit">保存公网地址</button><button class="secondary" type="button" onclick="rotateSubscription()">更换订阅令牌</button><span id="publicLinksStatus" class="muted"></span></form>
<p><strong>Base64 订阅链接：</strong></p><pre id="subscriptionUrl" class="linkout">尚未设置管理地址</pre><button class="secondary" type="button" onclick="copyText('subscriptionUrl')">复制订阅链接</button>
<p><strong>纯文本订阅链接：</strong></p><pre id="plainSubscriptionUrl" class="linkout">尚未设置管理地址</pre><button class="secondary" type="button" onclick="copyText('plainSubscriptionUrl')">复制纯文本订阅链接</button>
<p class="muted">订阅令牌是可读取节点凭据的私密链接。请勿公开发布；轮换后旧订阅立即失效。客户端节点和订阅仅在生成配置已应用且核心报告 running 后可用。</p></div>
<div class="card"><h2>自动生成双协议配置</h2><p class="muted">按保存的服务器公网地址生成 VLESS + Reality 与 Shadowsocks 两个入站及标准客户端分享 URI。只会替换带有本工具专用 tag 的旧生成入站，不会覆盖其他配置；生成后仍需审阅并点击“校验并应用配置”。</p>
<form id="multiGeneratorForm"><div class="grid">
<label>配置名称<input id="multiNodeName" value="My sing-box" maxlength="80" required></label>
<label>VLESS Reality TCP 端口<input id="vlessPort" type="number" min="1" max="65535" value="8443" required></label>
<label>Shadowsocks TCP/UDP 端口<input id="shadowsocksPort" type="number" min="1" max="65535" value="8388" required></label>
<label>Reality 握手域名<input id="realityServerName" value="www.microsoft.com" maxlength="253" required></label>
</div><button type="submit">生成双协议配置草稿</button><span id="multiGenerateStatus" class="muted"></span></form>
<p><strong>本次生成的节点链接（待应用）：</strong></p><pre id="generatedNodeDraft">先保存公网服务器地址，再生成配置。</pre>
<p><strong>当前已应用节点链接：</strong></p><pre id="activeNodeLinks">正在读取运行状态…</pre><button class="secondary" type="button" onclick="copyText('activeNodeLinks')">复制已应用节点链接</button></div>
<div class="card"><h2>节点列表</h2><div style="overflow:auto"><table><thead><tr><th>ID</th><th>名称</th><th>协议</th><th>核心</th><th>创建时间</th><th>操作</th></tr></thead><tbody id="nodes"></tbody></table></div></div>
<div class="card"><h2>配置预览</h2><p class="muted">预览接口会返回含凭据的配置，请勿分享或公开此页面。</p><pre id="preview">选择节点后点击“预览”</pre></div>
<div class="card"><h2>最近审计记录</h2><button class="secondary" onclick="loadAudit()">刷新审计</button><pre id="audit">点击刷新查看</pre></div>
<script>
let nodes=__NODES__;
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url,opts={}){let r=await fetch(url,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});if(!r.ok){let t=await r.text();throw Error(t)}return r.json()}
function render(){document.querySelector('#nodes').innerHTML=nodes.map(n=>`<tr><td>${n.id}</td><td>${esc(n.name)}</td><td><span class="pill">${esc(n.protocol)}</span></td><td>${esc(n.core)}</td><td>${esc(n.created_at)}</td><td><button onclick="preview(${n.id})">预览</button><button class="secondary" onclick="delNode(${n.id})">删除</button></td></tr>`).join('')||'<tr><td colspan="6">暂无节点</td></tr>'}
async function reload(){nodes=await api('/api/nodes');render()}
async function loadSingBoxSettings(){try{let d=await api('/api/settings/sing-box'),s=document.querySelector('#singboxScriptUrl');s.innerHTML=d.allowed_script_urls.map(u=>`<option value="${esc(u)}">${esc(u)}</option>`).join('');s.value=d.script_url;renderSingBoxInstall(d.script_url)}catch(e){document.querySelector('#singboxStatus').textContent='读取上游地址失败：'+e.message}}
function renderSingBoxInstall(url){document.querySelector('#singboxInstallCmd').textContent=['# 1) 在你管理的 VPS 进入 root shell','sudo -i','','# 2) 下载脚本，并检查来源与完整内容',`wget -O /tmp/sing-box-install.sh "${url}"`,'cat /tmp/sing-box-install.sh','','# 3) 查看安装器参数帮助','bash /tmp/sing-box-install.sh -h','','# 4) 确认脚本内容后再运行安装','bash /tmp/sing-box-install.sh','','# 5) 安装后检查服务和配置','sing-box status','sing-box info'].join('\n')}
function renderPublicLinks(d){document.querySelector('#adminPublicUrl').value=d.admin_public_url||'';document.querySelector('#serverPublicAddress').value=d.server_public_address||'';let base=(d.admin_public_url||window.location.origin).replace(/\/+$/,'');document.querySelector('#subscriptionUrl').textContent=base+d.subscription_path;document.querySelector('#plainSubscriptionUrl').textContent=base+d.subscription_path+'/plain'}
async function loadPublicLinks(){try{let d=await api('/api/settings/public-links');renderPublicLinks(d);document.querySelector('#publicLinksStatus').textContent=d.admin_public_url?'地址已加载；公网可用性取决于 HTTPS 反向代理和 DNS。':'请填写 HTTPS 管理域名；未设置时显示当前访问来源。'}catch(e){document.querySelector('#publicLinksStatus').textContent='读取公网地址失败：'+e.message}}
async function loadShareLinks(){try{let d=await api('/api/sing-box/share-links');let text=d.active?d.nodes.map(n=>`${n.protocol} · ${n.name}\n${n.share_url}`).join('\n\n'):'尚无已应用的生成节点。生成配置后，先校验并应用，待核心状态为 running 后这里会显示链接。';document.querySelector('#activeNodeLinks').textContent=text}catch(e){document.querySelector('#activeNodeLinks').textContent='暂时无法读取节点：'+e.message}}
async function rotateSubscription(){if(!confirm('轮换订阅令牌会立即使所有旧订阅链接失效。继续？'))return;try{let d=await api('/api/settings/public-links/rotate-subscription',{method:'POST'});renderPublicLinks(d);document.querySelector('#publicLinksStatus').textContent='已轮换令牌；旧订阅链接立即失效。';await loadShareLinks()}catch(e){document.querySelector('#publicLinksStatus').textContent='轮换失败：'+e.message}}
async function loadSingBoxRuntime(){let s=document.querySelector('#singboxRuntimeStatus');try{let d=await api('/api/sing-box/runtime');document.querySelector('#singboxRuntimeConfig').value=d.config;let st=d.status||{};s.textContent=`${st.state||'unknown'} · 配置 SHA-256 ${st.config_sha256||'尚未报告'}${st.error?' · '+st.error:''}`}catch(e){s.textContent='运行配置管理未就绪：'+e.message}}
async function applySingBoxRuntime(){let s=document.querySelector('#singboxRuntimeStatus');if(!confirm('将先校验并备份配置，再重启 sing-box 应用变更。现有连接会短暂中断。继续？'))return;s.textContent='正在校验、备份并应用…';try{let d=await api('/api/sing-box/runtime',{method:'PUT',body:JSON.stringify({config:document.querySelector('#singboxRuntimeConfig').value})});let st=d.status||{};s.textContent=d.applied?`已应用${d.unchanged?'（配置未变）':''} · SHA-256 ${d.config_sha256}`:`配置已保存，等待核心确认 · ${st.state||'pending'} · SHA-256 ${d.config_sha256}`;await loadShareLinks()}catch(e){s.textContent='未能应用配置：'+e.message}}
document.querySelector('#publicLinksForm').addEventListener('submit',async e=>{e.preventDefault();let s=document.querySelector('#publicLinksStatus');try{let d=await api('/api/settings/public-links',{method:'PUT',body:JSON.stringify({admin_public_url:document.querySelector('#adminPublicUrl').value,server_public_address:document.querySelector('#serverPublicAddress').value})});renderPublicLinks(d);s.textContent='公网地址已保存；管理后台仍需配置 HTTPS 反向代理。';await loadShareLinks()}catch(err){s.textContent='保存失败：'+err.message}});
document.querySelector('#multiGeneratorForm').addEventListener('submit',async e=>{e.preventDefault();let s=document.querySelector('#multiGenerateStatus'),address=document.querySelector('#serverPublicAddress').value.trim();if(!address){s.textContent='请先保存代理服务器公网域名或 IP 地址。';return}try{let body={name:document.querySelector('#multiNodeName').value,server_address:address,vless_port:Number(document.querySelector('#vlessPort').value),shadowsocks_port:Number(document.querySelector('#shadowsocksPort').value),reality_server_name:document.querySelector('#realityServerName').value};let d=await api('/api/sing-box/generate-multi',{method:'POST',body:JSON.stringify(body)});document.querySelector('#singboxRuntimeConfig').value=d.config;document.querySelector('#generatedNodeDraft').textContent=d.nodes.map(n=>`${n.protocol} · ${n.name}\n${n.share_url}`).join('\n\n');s.textContent=d.message}catch(err){s.textContent='生成失败：'+err.message}});
document.querySelector('#singboxSettingsForm').addEventListener('submit',async e=>{e.preventDefault();let status=document.querySelector('#singboxStatus');try{let d=await api('/api/settings/sing-box',{method:'PUT',body:JSON.stringify({script_url:document.querySelector('#singboxScriptUrl').value})});renderSingBoxInstall(d.script_url);status.textContent='已保存官方上游地址'}catch(err){status.textContent='保存失败：'+err.message}});
async function copyText(id){try{await navigator.clipboard.writeText(document.getElementById(id).textContent);document.querySelector('#singboxStatus').textContent='命令已复制'}catch(e){alert('复制失败，请手动选择命令文本复制。')}}
document.querySelector('#nodeform').addEventListener('submit',async e=>{e.preventDefault();let f=new FormData(e.target),d=Object.fromEntries(f.entries());d.port=Number(d.port);d.tls=f.get('tls')==='true';for(let k of ['uuid','password','method','server_name','path','username'])if(!d[k])d[k]=null;try{let r=await api('/api/nodes',{method:'POST',body:JSON.stringify(d)});document.querySelector('#status').textContent='已保存配置草稿，ID='+r.id;document.querySelector('#preview').textContent=JSON.stringify(r.config,null,2);e.target.reset();e.target.elements.listen.value='127.0.0.1';e.target.elements.port.value='18443';await reload()}catch(err){document.querySelector('#status').textContent='失败：'+err.message}});
async function preview(id){try{let n=nodes.find(x=>x.id===id);let c=await api(`/api/nodes/${id}/config?core=${encodeURIComponent(n.core)}`);document.querySelector('#preview').textContent=JSON.stringify(c,null,2)}catch(e){alert(e.message)}}
async function delNode(id){if(!confirm('确定删除节点 '+id+'？'))return;try{await api('/api/nodes/'+id,{method:'DELETE'});await reload()}catch(e){alert(e.message)}}
async function loadAudit(){try{document.querySelector('#audit').textContent=JSON.stringify(await api('/api/audit'),null,2)}catch(e){alert(e.message)}}
render();
loadSingBoxSettings();
loadSingBoxRuntime();
loadPublicLinks();
loadShareLinks();
</script></body></html>"""

HTML = HTML.replace("__NODES__", "__NODES__") # replaced safely at response time below
_original_home = home
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(user: str = Depends(require_auth)):
    with db() as con:
        rows = con.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    return HTMLResponse(HTML.replace("__NODES__", json.dumps([safe_node(r) for r in rows], ensure_ascii=False)))

# Make the root dashboard work as well.
@app.get("/ui", response_class=HTMLResponse)
def ui(user: str = Depends(require_auth)):
    with db() as con:
        rows = con.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
    return HTMLResponse(HTML.replace("__NODES__", json.dumps([safe_node(r) for r in rows], ensure_ascii=False)))
