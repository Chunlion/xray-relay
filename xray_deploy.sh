#!/usr/bin/env bash
# VLESS + REALITY 或 SOCKS5 入口，每个入口可绑定多个 SOCKS5 / VLESS 出站。
set -euo pipefail
umask 077

CONFIG_FILE="/usr/local/etc/xray-relay/config.json"
INFO_FILE="/root/xray_nodes_info.txt"
SERVICE_FILE="/etc/systemd/system/xray-relay.service"
SERVICE_MANAGER=systemd
SERVICE_LOG="/var/log/xray-relay.log"
REALITY_HOSTS=(www.bosch.com www.miele.com www.nespresso.com www.schaeffler.com
    www.siemens.com www.kuka.com)
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-}"
REALITY_DEST="${REALITY_DEST:-}"
SNI_BLOCKED=(google.com youtube.com facebook.com amazon.com wikipedia.org twitter.com
    instagram.com netflix.com microsoft.com apple.com cloudflare.com akamai.com
    fastly.com cloudfront.net bing.com yahoo.com github.com openai.com tiktok.com
    reddit.com linkedin.com whatsapp.com telegram.org baidu.com qq.com taobao.com
    jd.com weibo.com bilibili.com alipay.com)
CLIENT_FP="${CLIENT_FP:-chrome}"
START_PORT="${START_PORT:-}"
XRAY_BIN=""
CONFIG_BACKUP=""
NEW_CONFIG=""
NODES=()

prompt_read() {
    local variable="$1" value
    shift
    if ! read -r "$@" value; then
        return 1
    fi
    printf -v "$variable" '%s' "$value"
}

validate_sni() {
    local name="${1:-}" blocked
    name="${name,,}"
    [[ ${#name} -le 253 ]] || return 1
    [[ "$name" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || return 1
    for blocked in "${SNI_BLOCKED[@]}"; do
        if [[ "$name" == "$blocked" || "$name" == *".$blocked" ]]; then
            return 1
        fi
    done
    return 0
}

clear_screen() {
    [[ -t 1 ]] || return 0
    if [[ -n "${TERM:-}" ]] && command -v clear >/dev/null 2>&1; then
        clear || true
    else
        printf '\033[H\033[2J\033[3J'
    fi
}

pause_return() {
    local ignored
    [[ -t 0 ]] || return 0
    echo
    prompt_read ignored -p "按回车返回菜单" || true
}

parse_outbound_raw() {
    local raw="$1" out payload
    PARSED_HOST="" PARSED_PORT="" PARSED_NODE="" PARSE_ERROR=""
    out=$(INPUT="$raw" python3 - <<'PYEOF'
import os, sys, re, ipaddress, json, uuid
from urllib.parse import urlsplit, unquote, parse_qsl

raw = os.environ["INPUT"].strip()
def fail(message):
    print("ERR\t" + message)
    sys.exit(0)
def emit(host, port, node):
    print("OK\t" + "\x1f".join([host, str(port), json.dumps(node, ensure_ascii=True)]))
    sys.exit(0)
def ok(host, port, user, password):
    try:
        port = int(port)
    except (ValueError, TypeError):
        fail("端口必须为数字")
    if not 1 <= port <= 65535:
        fail("端口必须在 1-65535 之间")
    if not host or re.search(r'[\s/@?#\\]', host):
        fail("服务器地址无效")
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            fail("IPv6 地址无效")
    if (user is None) != (password is None) or (user is not None and (not user or not password)):
        fail("用户名和密码必须同时填写")
    fields = [host, str(port), user or "", password or ""]
    if any(re.search(r'[\x00-\x1f\x7f]', field) for field in fields):
        fail("字段不能包含控制字符")
    if any(len(field.encode()) > 255 for field in fields[2:]):
        fail("用户名和密码不能超过 255 字节")
    server = {"address": host, "port": port}
    if user:
        server["users"] = [{"user": user, "pass": password}]
    emit(host, port, {"protocol": "socks", "settings": {"servers": [server]}})

if re.search(r'[\x00-\x1f\x7f]', raw):
    fail("链接不能包含控制字符")
if raw.startswith("vless://"):
    try:
        url = urlsplit(raw)
        host, port = url.hostname, url.port
        identity = str(uuid.UUID(unquote(url.username or "")))
        pairs = parse_qsl(url.query, keep_blank_values=True)
    except ValueError:
        fail("VLESS 地址、端口或 UUID 无效")
    if not host or re.search(r'[\s/@?#\\%]', host) or not port or not 1 <= port <= 65535:
        fail("VLESS 地址或端口无效")
    if url.password is not None or url.path not in ("", "/"):
        fail("VLESS 链接格式无效")
    if re.search(r'%(?![0-9a-fA-F]{2})', raw):
        fail("链接中的百分号编码无效")
    if any(re.search(r'[\x00-\x1f\x7f]', key + value) for key, value in pairs):
        fail("字段不能包含控制字符")
    query = dict(pairs)
    if len(query) != len(pairs):
        fail("VLESS 参数不能重复")
    allowed = {"type", "security", "encryption", "flow", "sni", "fp", "pbk", "sid", "spx",
               "alpn", "allowInsecure", "host", "path", "serviceName", "mode", "authority", "headerType"}
    if query.keys() - allowed:
        fail("VLESS 链接包含尚不支持的参数")
    network = query.get("type", "tcp")
    if network == "raw":
        network = "tcp"
    security = query.get("security", "none")
    if network not in ("tcp", "ws", "grpc", "httpupgrade", "xhttp"):
        fail("VLESS 传输仅支持 TCP、WS、gRPC、HTTPUpgrade 和 XHTTP")
    if security not in ("none", "tls", "reality"):
        fail("VLESS 安全类型仅支持 none、tls 和 reality")
    if query.get("encryption", "none") != "none":
        fail("当前仅支持 encryption=none 的 VLESS 链接")
    if query.get("headerType", "none") != "none":
        fail("当前不支持 TCP HTTP 伪装")
    flow = query.get("flow", "")
    if flow not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        fail("不支持此 VLESS flow")
    if flow and (network != "tcp" or security == "none"):
        fail("Vision 需要 TCP + TLS 或 REALITY")
    user = {"id": identity, "encryption": "none"}
    if flow:
        user["flow"] = flow
    stream = {"network": network, "security": security}
    if security == "reality":
        key, sid = query.get("pbk", ""), query.get("sid", "")
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key):
            fail("REALITY 需要有效的 pbk 公钥")
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', sid):
            fail("REALITY sid 必须是最多 16 位的偶数位十六进制字符串")
        stream["realitySettings"] = {"serverName": query.get("sni", host),
            "fingerprint": query.get("fp") or "chrome", "publicKey": key, "shortId": sid,
            "spiderX": query.get("spx", "/")}
    elif security == "tls":
        tls = {"serverName": query.get("sni", host)}
        if query.get("fp"):
            tls["fingerprint"] = query["fp"]
        if query.get("alpn"):
            tls["alpn"] = query["alpn"].split(",")
        if query.get("allowInsecure", "0") not in ("0", "1", "false", "true"):
            fail("allowInsecure 必须是 0、1、false 或 true")
        tls["allowInsecure"] = query.get("allowInsecure", "0") in ("1", "true")
        stream["tlsSettings"] = tls
    if network == "ws":
        stream["wsSettings"] = {"path": query.get("path", "/")}
        if query.get("host"):
            stream["wsSettings"]["headers"] = {"Host": query["host"]}
    elif network == "grpc":
        if query.get("mode", "gun") not in ("gun", "multi"):
            fail("gRPC mode 必须是 gun 或 multi")
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", ""),
            "multiMode": query.get("mode") == "multi", "authority": query.get("authority", "")}
    elif network in ("httpupgrade", "xhttp"):
        settings = {"path": query.get("path", "/"), "host": query.get("host", "")}
        if network == "xhttp":
            mode = query.get("mode", "auto")
            if mode not in ("auto", "packet-up", "stream-up", "stream-one"):
                fail("XHTTP mode 无效")
            settings["mode"] = mode
        stream[network + "Settings"] = settings
    emit(host, port, {"protocol": "vless", "settings": {"vnext": [
        {"address": host, "port": port, "users": [user]}]}, "streamSettings": stream})
if raw.startswith(("socks5://", "socks://")):
    try:
        url = urlsplit(raw)
        host, port = url.hostname, url.port
        user, password = url.username, url.password
    except ValueError:
        fail("SOCKS5 链接格式无效")
    if url.path not in ("", "/") or url.query:
        fail("SOCKS5 链接不能包含路径或查询参数")
    if re.search(r'%(?![0-9a-fA-F]{2})', url.netloc):
        fail("链接中的百分号编码无效")
    ok(host, port, unquote(user) if user is not None else None,
       unquote(password) if password is not None else None)
match = re.fullmatch(r'\[([^\]]+)\]:(\d+):([^:]+):([^:]+)', raw)
if match:
    ok(*match.groups())
parts = raw.split(":")
if len(parts) == 4:
    ok(*parts)
fail("使用 socks5://用户名:密码@地址:端口、socks5://地址:端口 或 vless:// 链接")
PYEOF
)
    if [[ "$out" == OK$'\t'* ]]; then
        payload="${out#*$'\t'}"
        IFS=$'\x1f' read -r PARSED_HOST PARSED_PORT PARSED_NODE <<< "$payload"
        return 0
    fi
    PARSE_ERROR="${out#*$'\t'}"
    return 1
}

preflight_check() {
    if [[ $(id -u) != 0 ]]; then
        echo "需要以 root 运行。" >&2
        return 1
    fi
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null; then
        SERVICE_MANAGER=systemd
    elif command -v rc-service >/dev/null && command -v rc-update >/dev/null; then
        SERVICE_MANAGER=openrc
        SERVICE_FILE=/etc/init.d/xray-relay
    else
        echo "需要使用 systemd 或 OpenRC 的 Linux VPS。" >&2
        return 1
    fi
    local missing=0 cmd
    for cmd in curl python3 ss unzip; do
        command -v "$cmd" >/dev/null || missing=1
    done
    if (( missing )); then
        if command -v apk >/dev/null; then
            apk add --no-cache curl python3 iproute2 unzip ca-certificates || return 1
        elif command -v apt-get >/dev/null; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends curl python3 iproute2 unzip ca-certificates
        elif command -v dnf >/dev/null; then
            dnf install -y curl python3 iproute unzip ca-certificates
        elif command -v yum >/dev/null; then
            yum install -y curl python3 iproute unzip ca-certificates
        else
            echo "请先安装 curl、python3、iproute2、unzip 和 ca-certificates。" >&2
            return 1
        fi
    fi
    if [[ -n "$START_PORT" ]]; then
        if [[ ! "$START_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$START_PORT < 1024 || 10#$START_PORT > 65535 )); then
            echo "START_PORT 必须在 1024-65535 之间。" >&2
            return 1
        fi
        START_PORT=$((10#$START_PORT))
    fi
}

install_xray() {
    local candidate service_start service_bin="" relay_bin="" arch work
    if [[ "$SERVICE_MANAGER" == openrc ]]; then
        if [[ -f "$SERVICE_FILE" ]]; then
            relay_bin=$(sed -n 's/^command="\([^"]*\)"$/\1/p' "$SERVICE_FILE")
        fi
    else
        service_start=$(systemctl show -p ExecStart --value xray-relay 2>/dev/null || true)
        if [[ "$service_start" =~ path=([^[:space:]\;]+) ]]; then
            relay_bin="${BASH_REMATCH[1]}"
        fi
        service_start=$(systemctl show -p ExecStart --value xray 2>/dev/null || true)
        if [[ "$service_start" =~ path=([^[:space:]\;]+) ]]; then
            service_bin="${BASH_REMATCH[1]}"
        fi
    fi
    for candidate in "$relay_bin" /etc/xray/bin/xray /usr/local/bin/xray "$service_bin" /usr/bin/xray /usr/local/lib/xray-relay/xray; do
        if [[ -x "$candidate" ]] && "$candidate" version 2>/dev/null | grep -q '^Xray '; then
            XRAY_BIN="$candidate"
            echo "复用 Xray 核心: $XRAY_BIN"
            return 0
        fi
    done
    case $(uname -m) in
        x86_64|amd64) arch=64 ;;
        aarch64|arm64) arch=arm64-v8a ;;
        *) echo "自动安装仅支持 x86_64 和 ARM64。" >&2; return 1 ;;
    esac
    echo "未检测到可复用的 Xray，正在下载核心（${arch}）..."
    work=$(mktemp -d) || return 1
    if ! curl -fSL --connect-timeout 10 --max-time 120 \
        "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${arch}.zip" -o "$work/xray.zip" \
        || ! unzip -q "$work/xray.zip" xray -d "$work"; then
        rm -rf -- "$work"
        echo "下载 Xray 核心失败。" >&2
        return 1
    fi
    if ! (umask 022; install -d -m 755 /usr/local/lib/xray-relay \
        && install -m 755 "$work/xray" /usr/local/lib/xray-relay/xray); then
        rm -rf -- "$work"
        echo "无法安装 Xray 核心，请检查目录权限和磁盘空间。" >&2
        return 1
    fi
    rm -rf -- "$work"
    XRAY_BIN=/usr/local/lib/xray-relay/xray
    echo "Xray 核心已安装: $XRAY_BIN"
}

get_ip() {
    local candidate provider
    for provider in https://api.ipify.org https://ipv4.icanhazip.com https://ipv6.icanhazip.com; do
        candidate=$(curl -fsS --connect-timeout 3 --max-time 5 "$provider" 2>/dev/null || true)
        if python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$candidate" 2>/dev/null; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    if ! prompt_read candidate -p "VPS 公网 IP: "; then
        return 1
    fi
    if ! python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$candidate" 2>/dev/null; then
        echo "公网 IP 无效。" >&2
        return 1
    fi
    printf '%s\n' "$candidate"
}

probe_socks_udp() {
    local node="$1" report relay kind e2e
    report=$(NODE_JSON="$node" python3 - <<'PYEOF'
import ipaddress, json, os, socket, struct, sys

node = json.loads(os.environ["NODE_JSON"])
if node.get("protocol") != "socks":
    print("SKIP")
    sys.exit(0)
server = node["settings"]["servers"][0]
host, port = server["address"], int(server["port"])
account = (server.get("users") or [{}])[0]
user, password = account.get("user", ""), account.get("pass", "")

def out(message):
    print(message)
    sys.exit(0)

try:
    control = socket.create_connection((host, port), timeout=4)
except OSError as error:
    out("CONNECT:" + (error.strerror or "无法建立连接"))

def read_exact(size):
    data = b""
    while len(data) < size:
        chunk = control.recv(size - len(data))
        if not chunk:
            raise OSError("连接提前关闭")
        data += chunk
    return data

try:
    control.sendall(b"\x05\x01" + (b"\x02" if user else b"\x00"))
    reply = read_exact(2)
    if reply[1] == 2:
        name, secret = user.encode(), password.encode()
        control.sendall(b"\x01" + bytes([len(name)]) + name + bytes([len(secret)]) + secret)
        if read_exact(2)[1] != 0:
            out("AUTH")
    elif reply[1] != 0:
        out("METHOD:%d" % reply[1])
    control.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
    header = read_exact(4)
    if header[1] != 0:
        out("ASSOC:%d" % header[1])
    atyp = header[3]
    if atyp == 1:
        relay_host = socket.inet_ntoa(read_exact(4))
    elif atyp == 4:
        relay_host = socket.inet_ntop(socket.AF_INET6, read_exact(16))
    elif atyp == 3:
        relay_host = read_exact(read_exact(1)[0]).decode(errors="replace")
    else:
        out("ASSOC:地址类型 %d 不支持" % atyp)
    relay_port = struct.unpack("!H", read_exact(2))[0]
except OSError:
    out("ASSOC:连接中断")
finally:
    control.close()

if atyp == 3:
    kind = "domain"
else:
    address = ipaddress.ip_address(relay_host)
    if address.is_unspecified:
        kind = "unspecified"
    elif address.is_loopback:
        kind = "loopback"
    elif address.is_link_local:
        kind = "linklocal"
    elif address.is_private:
        kind = "private"
    else:
        kind = "public"

# 用一次 DNS 查询验证真实的 UDP 出口；0.0.0.0 按 Xray 的行为改用服务器地址。
target = host if kind == "unspecified" else relay_host
family = socket.AF_INET6 if ":" in target else socket.AF_INET
query = struct.pack("!HHHHHH", 0x5A5A, 0x0100, 1, 0, 0, 0)
query += b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
packet = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53) + query
datagram = socket.socket(family, socket.SOCK_DGRAM)
datagram.settimeout(3)
try:
    datagram.sendto(packet, (target, relay_port))
    e2e = "ok" if datagram.recv(2048)[10:12] == b"\x5a\x5a" else "bad"
except OSError:
    e2e = "timeout"
finally:
    datagram.close()
print(f"ASSOC relay={relay_host}:{relay_port} kind={kind} e2e={e2e}")
PYEOF
) || report="CONNECT:探测脚本异常"
    case "$report" in
        SKIP)
            return 0
            ;;
        CONNECT:*)
            echo "警告：无法连接上游 SOCKS5 ${PARSED_HOST}:${PARSED_PORT}（${report#CONNECT:}），UDP 未验证。" >&2
            ;;
        AUTH)
            echo "警告：上游 SOCKS5 认证失败，UDP 未验证。" >&2
            ;;
        METHOD:*)
            echo "警告：上游 SOCKS5 不接受所需的认证方式，UDP 未验证。" >&2
            ;;
        ASSOC:7)
            echo "警告：上游拒绝 UDP ASSOCIATE，不支持 UDP 转发。Wi-Fi Calling 需要 UDP，请更换上游或改用它的 VLESS 接入。" >&2
            ;;
        ASSOC:*)
            echo "警告：上游拒绝 UDP ASSOCIATE（${report#ASSOC:}），UDP 不可用。" >&2
            ;;
        ASSOC\ relay=*)
            relay=${report#*relay=}; relay=${relay%% *}
            kind=${report#*kind=}; kind=${kind%% *}
            e2e=${report##*e2e=}
            case "$e2e" in
                ok)
                    echo "UDP 出口已确认（DNS 查询往返正常）。"
                    ;;
                *)
                    case "$kind" in
                        loopback|private|linklocal)
                            echo "警告：上游返回的 UDP 中继地址 ${relay} 是本机或内网地址，Xray 会把 UDP 直接发往该地址，链路必然中断。" >&2
                            echo "      请在上游把 SOCKS5 入站的监听 IP 改为 0.0.0.0 或公网地址（3x-ui 默认是 127.0.0.1）；改不了就改用该上游的 VLESS 接入。" >&2
                            ;;
                        *)
                            echo "警告：UDP 关联已建立，但向 1.1.1.1:53 的测试查询无响应；上游可能限制 UDP 目标或存在分片问题，请用手机实测 Wi-Fi Calling。" >&2
                            ;;
                    esac
                    ;;
            esac
            ;;
    esac
}

collect_nodes() {
    local raw
    NODES=()
    echo "逐行粘贴 SOCKS5 或 VLESS 出站链接，输入隐藏；全部输入后按空回车结束。"
    while true; do
        if ! prompt_read raw -s -p "出站 [$(( ${#NODES[@]} + 1 ))]: "; then
            echo
            break
        fi
        echo
        [[ -n "$raw" ]] || break
        if parse_outbound_raw "$raw"; then
            NODES+=("$PARSED_NODE")
            echo "已添加出站 ${#NODES[@]}: ${PARSED_HOST}:${PARSED_PORT}"
            if [[ -t 0 ]]; then
                probe_socks_udp "$PARSED_NODE"
            fi
        else
            echo "格式错误: $PARSE_ERROR" >&2
        fi
    done
    if (( ${#NODES[@]} == 0 )); then
        echo "未输入出站，操作取消。" >&2
        return 1
    fi
}

generate_keys() {
    local key_output
    key_output=$("$XRAY_BIN" x25519) || return 1
    PRIVATE_KEY=$(awk -F ': *' 'tolower($1) ~ /^private ?key$/ {print $2}' <<< "$key_output")
    PUBLIC_KEY=$(awk -F ': *' 'tolower($1) ~ /public|^password/ {print $2; exit}' <<< "$key_output")
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        echo "Xray 未返回有效的 REALITY 密钥对。" >&2
        return 1
    fi
    UUID=$(python3 -c 'import uuid; print(uuid.uuid4())') || return 1
    SHORT_ID=$(python3 -c 'import secrets; print(secrets.token_hex(8))') || return 1
}

generate_config() {
    local target="$1" action="${2:-add-vless}" entry="${3:-}" outbound="${4:-}" occupied occupied_udp
    local reality_name="${REALITY_SERVER_NAME:-${REALITY_HOSTS[0]}}"
    local reality_dest="${REALITY_DEST:-${reality_name}:443}"
    occupied=$(ss -H -ltn) || return 1
    occupied_udp=$(ss -H -lun) || return 1
    CONFIG_FILE="$CONFIG_FILE" NEW_CONFIG_FILE="$target" ACTION="$action" ENTRY_TAG="$entry" \
    OUTBOUND_TAG="$outbound" EDIT_PORT="${EDIT_PORT:-}" EDIT_NAME="${EDIT_NAME:-}" \
    VPS_IP="${VPS_IP:-}" UUID="${UUID:-}" PRIVATE_KEY="${PRIVATE_KEY:-}" SHORT_ID="${SHORT_ID:-}" \
    START_PORT="$START_PORT" OCCUPIED="$occupied" UDP_OCCUPIED="$occupied_udp" \
    REALITY_DEST="$reality_dest" REALITY_SERVER_NAME="$reality_name" \
    NODES_DATA="$(printf '%s\n' "${NODES[@]}")" \
    python3 - <<'PYEOF'
import copy, json, os, re, secrets
source = os.environ["CONFIG_FILE"]
if os.path.isfile(source):
    with open(source) as file:
        config = json.load(file)
else:
    config = {"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [],
              "routing": {"domainStrategy": "AsIs", "rules": []}}
inbounds, outbounds, rules = config["inbounds"], config["outbounds"], config["routing"]["rules"]
action, entry_tag, outbound_tag = (os.environ[key] for key in ("ACTION", "ENTRY_TAG", "OUTBOUND_TAG"))
nodes = [json.loads(node) for node in os.environ["NODES_DATA"].splitlines() if node]
used = {int(line.split()[3].rsplit(":", 1)[1])
        for line in os.environ["OCCUPIED"].splitlines() if line.strip()}
used_udp = {int(line.split()[3].rsplit(":", 1)[1])
            for line in os.environ["UDP_OCCUPIED"].splitlines() if line.strip()}

def add_outbounds(prefix):
    added = []
    for node in nodes:
        index = 1
        while any(out["tag"] == f"{prefix}{index}" for out in outbounds):
            index += 1
        out = copy.deepcopy(node)
        out["tag"] = f"{prefix}{index}"
        outbounds.append(out)
        added.append(out)
    return added

if action in ("add-vless", "add-socks"):
    if not nodes:
        raise SystemExit("至少需要一个出站。")
    used.update(inbound["port"] for inbound in inbounds)
    protocol = action[4:]
    if protocol == "socks":
        used.update(used_udp)
    if os.environ["START_PORT"]:
        port = int(os.environ["START_PORT"])
        while port in used:
            port += 1
        if port > 65535:
            raise SystemExit("没有可用的监听端口。")
    else:
        available = [candidate for candidate in range(10000, 65536) if candidate not in used]
        if not available:
            raise SystemExit("没有可用的监听端口。")
        port = secrets.choice(available)
    index = 1
    while any(inbound["tag"] == f"{protocol}-in-{index}" for inbound in inbounds):
        index += 1
    entry_tag = f"{protocol}-in-{index}"
    inbound = {
        "tag": entry_tag, "_remark": f"VLESS-{index}",
        "listen": "::" if ":" in os.environ["VPS_IP"] else "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": [{"id": os.environ["UUID"], "flow": "xtls-rprx-vision"}], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": os.environ["REALITY_DEST"], "serverNames": [os.environ["REALITY_SERVER_NAME"]],
            "privateKey": os.environ["PRIVATE_KEY"], "shortIds": [os.environ["SHORT_ID"]]}}
    }
    if protocol == "socks":
        inbound.update({"_remark": f"SOCKS5-{index}", "protocol": "socks", "settings": {
            "auth": "password", "accounts": [{"user": "relay_" + secrets.token_hex(4),
                                                "pass": secrets.token_urlsafe(24)}],
            "udp": True, "ip": os.environ["VPS_IP"]}})
        del inbound["streamSettings"]
    inbounds.append(inbound)
    added = add_outbounds(f"socks5-{entry_tag}-")
    rules.append({"type": "field", "inboundTag": [entry_tag], "outboundTag": added[0]["tag"]})
elif action == "delete-inbound":
    inbound = next((item for item in inbounds if item["tag"] == entry_tag), None)
    if not inbound:
        raise SystemExit("节点不存在。")
    candidates = {out["tag"] for out in outbounds if out["tag"].startswith(f"socks5-{entry_tag}-")}
    for rule in rules[:]:
        if entry_tag in rule.get("inboundTag", []):
            candidates.add(rule.get("outboundTag"))
            rule["inboundTag"].remove(entry_tag)
            if not rule["inboundTag"]:
                rules.remove(rule)
    inbounds.remove(inbound)
    referenced = {rule.get("outboundTag") for rule in rules}
    outbounds[:] = [out for out in outbounds if out["tag"] not in candidates or out["tag"] in referenced]
else:
    inbound = next((item for item in inbounds if item["tag"] == entry_tag), None)
    rule = next((item for item in rules if item.get("inboundTag") == [entry_tag]), None)
    if not inbound or not rule:
        raise SystemExit("入站或对应路由不存在。")
    prefix = f"socks5-{entry_tag}-"
    members = [out for out in outbounds if out["tag"].startswith(prefix)]
    # 将上一版一对一的出站纳入该入口，保持其他入口的路由不变。
    if not members:
        old = next((out for out in outbounds if out["tag"] == rule.get("outboundTag")), None)
        if not old or old["protocol"] != "socks":
            raise SystemExit("找不到该入口的 SOCKS5 出站。")
        member = copy.deepcopy(old)
        member["tag"] = prefix + "1"
        outbounds.append(member)
        previous = old["tag"]
        rule["outboundTag"] = member["tag"]
        if outbound_tag == previous:
            outbound_tag = member["tag"]
        if not any(item.get("outboundTag") == previous for item in rules):
            outbounds.remove(old)
        members = [member]
    selected = next((out for out in members if out["tag"] == outbound_tag), None)
    if action == "add-outbounds":
        if not nodes:
            raise SystemExit("至少需要一个出站。")
        add_outbounds(prefix)
    elif action == "switch-outbound":
        if not selected:
            raise SystemExit("出站不属于该入口。")
        rule["outboundTag"] = selected["tag"]
    elif action == "edit-outbound":
        if not selected or len(nodes) != 1:
            raise SystemExit("选择一个出站并输入一条新的 SOCKS5 或 VLESS 链接。")
        tag = selected["tag"]
        selected.clear()
        selected.update(copy.deepcopy(nodes[0]), tag=tag)
    elif action == "delete-outbound":
        if not selected:
            raise SystemExit("出站不属于该入口。")
        if len(members) == 1:
            raise SystemExit("这是节点唯一的出站；删除整条节点请选择主菜单 4。")
        outbounds.remove(selected)
        if rule["outboundTag"] == selected["tag"]:
            rule["outboundTag"] = next(out["tag"] for out in members if out is not selected)
    elif action == "edit-inbound":
        if inbound["protocol"] == "socks":
            used.update(used_udp)
        raw_port = os.environ["EDIT_PORT"]
        if raw_port:
            if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1024 <= int(raw_port) <= 65535:
                raise SystemExit("端口必须在 1024-65535 之间。")
            port = int(raw_port)
            if port != inbound["port"] and (port in used or any(item["port"] == port for item in inbounds)):
                raise SystemExit("端口已被占用。")
            inbound["port"] = port
        name = os.environ["EDIT_NAME"]
        if name:
            if re.search(r'[\x00-\x1f\x7f]', name):
                raise SystemExit("名称不能包含控制字符。")
            inbound["_remark"] = name
    else:
        raise SystemExit("未知操作。")
with open(os.environ["NEW_CONFIG_FILE"], "w") as file:
    json.dump(config, file, indent=2)
PYEOF
}

apply_config_permissions() {
    local target="$1" group
    group=$(id -gn nobody) || return 1
    chown "root:$group" "$target" || return 1
    chmod 640 "$target"
}

show_xray_error() {
    ERROR_OUTPUT="$2" python3 - "$1" <<'PYEOF'
import json, os, re, sys
output = os.environ["ERROR_OUTPUT"]
secrets = set()
def collect(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"id", "privatekey", "pass", "password", "user", "username"} and isinstance(item, str) and item:
                secrets.add(item)
                secrets.add(json.dumps(item, ensure_ascii=False)[1:-1])
            else:
                collect(item)
    elif isinstance(value, list):
        for item in value:
            collect(item)
try:
    with open(sys.argv[1]) as file:
        collect(json.load(file))
except (OSError, ValueError):
    pass
for secret in sorted(secrets, key=len, reverse=True):
    pattern = re.escape(secret)
    if len(secret) < 4:
        pattern = r'(?<![\w])' + pattern + r'(?![\w])'
    output = re.sub(pattern, "[隐藏]", output)
print("\n".join(output.splitlines()[-15:])[:12000] or "Xray 未返回错误详情。", file=sys.stderr)
PYEOF
}

validate_and_install_config() {
    local new_config="$1" output status
    CONFIG_BACKUP=""
    echo "正在校验 Xray 配置..."
    if output=$("$XRAY_BIN" run -test -config "$new_config" -format json 2>&1); then
        echo "配置校验通过。"
    else
        status=$?
        echo "Xray 配置校验失败（退出码 ${status}），原配置未修改。" >&2
        echo "核心: $XRAY_BIN" >&2
        show_xray_error "$new_config" "$output"
        return 1
    fi
    apply_config_permissions "$new_config" || return 1
    if [[ -f "$CONFIG_FILE" ]]; then
        CONFIG_BACKUP=$(mktemp "${CONFIG_FILE}.bak.XXXXXX") || return 1
        cp -a "$CONFIG_FILE" "$CONFIG_BACKUP" || return 1
        chmod 600 "$CONFIG_BACKUP" || return 1
    fi
    mv -f "$new_config" "$CONFIG_FILE"
}

service_control() {
    if [[ "$SERVICE_MANAGER" == openrc ]]; then
        case "$1" in
            enable) rc-update add xray-relay default ;;
            disable) rc-update del xray-relay default ;;
            is-active) rc-service xray-relay status >/dev/null 2>&1 ;;
            *) rc-service xray-relay "$1" ;;
        esac
    elif [[ "$1" == is-active ]]; then
        systemctl is-active --quiet xray-relay
    else
        systemctl "$1" xray-relay
    fi
}

start_service() {
    local unit_tmp group
    unit_tmp=$(mktemp "${SERVICE_FILE}.XXXXXX") || return 1
    if [[ "$SERVICE_MANAGER" == openrc ]]; then
        group=$(id -gn nobody) || return 1
        cat > "$unit_tmp" <<EOF || return 1
#!/sbin/openrc-run
description="Xray VLESS / SOCKS5 relay"
command="$XRAY_BIN"
command_args="run -config \"$CONFIG_FILE\""
command_user="nobody:$group"
command_background=true
pidfile="/run/xray-relay.pid"
output_log="$SERVICE_LOG"
error_log="$SERVICE_LOG"

depend() {
    need net
}

start_pre() {
    checkpath --file --owner "\$command_user" --mode 0640 "\$output_log" || return 1
    : > "\$output_log"
}
EOF
        chmod 755 "$unit_tmp" || return 1
    else
        cat > "$unit_tmp" <<EOF || return 1
[Unit]
Description=Xray VLESS / SOCKS5 relay
After=network-online.target
Wants=network-online.target

[Service]
User=nobody
ExecStart="$XRAY_BIN" run -config "$CONFIG_FILE"
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
        chmod 644 "$unit_tmp" || return 1
    fi
    mv -f "$unit_tmp" "$SERVICE_FILE" || return 1
    if [[ "$SERVICE_MANAGER" == systemd ]]; then
        systemctl daemon-reload || return 1
    fi
    service_control enable || return 1
    restart_with_rollback
}

restart_with_rollback() {
    local since output log_hint
    since=$(date +%s)
    echo "正在启动 xray-relay 服务..."
    if service_control restart; then
        sleep 2
        if service_control is-active; then
            echo "xray-relay 服务运行中。"
            return 0
        fi
    fi
    echo "xray-relay 启动失败，服务日志：" >&2
    if [[ "$SERVICE_MANAGER" == openrc ]]; then
        log_hint="$SERVICE_LOG"
        output=$(tail -n 15 "$SERVICE_LOG" 2>&1 || true)
    else
        log_hint="journalctl -u xray-relay"
        output=$(journalctl -u xray-relay --since "@$since" -n 15 --no-pager 2>&1 || true)
    fi
    show_xray_error "$CONFIG_FILE" "$output"
    if [[ -n "$CONFIG_BACKUP" ]]; then
        cp -a "$CONFIG_BACKUP" "$CONFIG_FILE" || return 1
        apply_config_permissions "$CONFIG_FILE" || return 1
        if service_control restart; then
            sleep 2
            if service_control is-active; then
                echo "启动失败，已恢复原中转配置。" >&2
                return 1
            fi
        fi
        echo "已恢复原中转配置，但服务未恢复，请检查 $log_hint。" >&2
    else
        if ! service_control stop; then
            echo "启动失败，且无法停止 xray-relay，请检查 $log_hint。" >&2
            return 1
        fi
        service_control disable || return 1
        rm -f -- "$CONFIG_FILE" || return 1
        echo "首次启动失败，已停止服务并撤销本次配置，可从部署菜单重试。" >&2
    fi
    return 1
}

setup_firewall() {
    local port protocol
    while read -r port protocol; do
        if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
            ufw allow "$port/$protocol" || return 1
        elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="$port/$protocol" || return 1
            firewall-cmd --add-port="$port/$protocol" || return 1
        fi
    done < <(python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
for inbound in json.load(open(sys.argv[1]))["inbounds"]:
    print(inbound["port"], "tcp")
    if inbound["protocol"] == "socks" and inbound["settings"].get("udp"):
        print(inbound["port"], "udp")
PYEOF
)
}

print_result() {
    VPS_IP="$VPS_IP" XRAY_BIN="$XRAY_BIN" CLIENT_FP="$CLIENT_FP" \
    python3 - "$CONFIG_FILE" "$INFO_FILE" <<'PYEOF'
import json, os, re, subprocess, sys
from urllib.parse import urlencode, quote
config = json.load(open(sys.argv[1]))
host = os.environ["VPS_IP"]
if ":" in host:
    host = f"[{host}]"
lines = []
for index, inbound in enumerate(config["inbounds"], 1):
    name = inbound.get("_remark", f"{inbound['protocol'].upper()}-{index}")
    if inbound["protocol"] == "socks":
        account = inbound["settings"]["accounts"][0]
        user, password = (quote(account[key], safe="") for key in ("user", "pass"))
        lines.append(f"socks5://{user}:{password}@{host}:{inbound['port']}#{quote(name)}")
        continue
    reality = inbound["streamSettings"]["realitySettings"]
    try:
        key = subprocess.run([os.environ["XRAY_BIN"], "x25519", "-i", reality["privateKey"]],
                             capture_output=True, text=True)
    except OSError:
        raise SystemExit("无法生成节点链接：Xray 核心无法执行。")
    if key.returncode:
        raise SystemExit(f"无法生成节点链接：公钥派生失败（退出码 {key.returncode}）。")
    public_key = re.search(r'^(?:Public\s*Key|Password[^:]*):\s*(\S+)', key.stdout, re.I | re.M)
    if not public_key:
        raise SystemExit("无法生成节点链接：Xray 未返回公钥。")
    query = urlencode({"encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
                       "sni": reality["serverNames"][0], "fp": os.environ["CLIENT_FP"],
                       "pbk": public_key[1], "sid": reality["shortIds"][0], "type": "tcp"})
    uuid = inbound["settings"]["clients"][0]["id"]
    lines.append(f"vless://{uuid}@{host}:{inbound['port']}?{query}#{quote(name)}")
with open(sys.argv[2], "w") as file:
    file.write("\n".join(lines) + "\n")
os.chmod(sys.argv[2], 0o600)
print("节点链接：\n" + "\n\n".join(lines))
print(f"链接已保存到 {sys.argv[2]}")
print("请在云安全组及自定义防火墙中放行这些节点的 TCP 端口。")
if any(inbound["protocol"] == "socks" for inbound in config["inbounds"]):
    print("SOCKS5 节点还需放行同端口 UDP；UDP 转发需要上游出站支持。")
PYEOF
}

show_nodes() {
    python3 - "$CONFIG_FILE" "${1:-}" <<'PYEOF'
import json, sys

config = json.load(open(sys.argv[1]))
inbounds = config["inbounds"]
if not inbounds:
    print("暂无节点，请先新增 VLESS 或 SOCKS5 节点。")
    sys.exit(0)
filter_tag = sys.argv[2] if len(sys.argv) > 2 else ""
shown = 0

def field(source, key):
    item = source.get(key) if isinstance(source, dict) else None
    return "-" if item in (None, "", [], {}) else item

for index, inbound in enumerate(inbounds, 1):
    tag = inbound["tag"]
    if filter_tag and tag != filter_tag:
        continue
    shown += 1
    rule = next(item for item in config["routing"]["rules"] if item.get("inboundTag") == [tag])
    members = [out for out in config["outbounds"] if out["tag"].startswith(f"socks5-{tag}-")]
    if not members:
        members = [out for out in config["outbounds"] if out["tag"] == rule["outboundTag"]]
    settings = inbound.get("settings") or {}
    stream = inbound.get("streamSettings") or {}
    if shown > 1:
        print()
    print(f"节点 {index}) {inbound.get('_remark', tag)}")
    print(f"  协议  {str(field(inbound, 'protocol')).upper()}")
    print(f"  监听  {field(inbound, 'listen')}:{field(inbound, 'port')}")
    if inbound.get("protocol") == "vless":
        client = (settings.get("clients") or [{}])[0]
        print(f"  传输  {str(field(stream, 'network')).upper()}")
        print(f"  安全  {str(field(stream, 'security')).upper()}")
        print(f"  标识  {field(client, 'id')}")
        print(f"  流控  {field(client, 'flow')}")
        print(f"  加密  {field(settings, 'decryption')}")
        reality = stream.get("realitySettings") or {}
        tls = stream.get("tlsSettings") or {}
        if reality:
            print(f"  域名  {','.join(reality.get('serverNames') or []) or '-'}")
            print(f"  目标  {field(reality, 'dest')}")
            print(f"  短ID  {','.join(reality.get('shortIds') or []) or '-'}")
        if tls:
            print(f"  域名  {field(tls, 'serverName')}")
    else:
        account = (settings.get("accounts") or [{}])[0]
        print(f"  账号  {field(account, 'user')}")
        print(f"  UDP   {'开' if settings.get('udp') else '关'}")
    print(f"  出站  {len(members)} 个")
    for number, outbound in enumerate(members, 1):
        protocol = outbound["protocol"]
        server = outbound["settings"]["vnext" if protocol == "vless" else "servers"][0]
        address = f"[{server['address']}]" if ":" in server["address"] else server["address"]
        current = "  [当前]" if outbound["tag"] == rule["outboundTag"] else ""
        print(f"        {number}) {protocol.upper()} {address}:{server['port']}{current}")
if filter_tag and not shown:
    print("节点不存在。")
PYEOF
}

select_entry() {
    local number
    show_nodes || return 1
    echo
    prompt_read number -p "${1:-节点编号（0 返回）}: " || return 1
    [[ -n "$number" && "$number" != 0 ]] || return 1
    if [[ ! "$number" =~ ^[1-9][0-9]*$ ]]; then
        echo "编号无效。" >&2
        return 1
    fi
    SELECTED_ENTRY=$(python3 - "$CONFIG_FILE" "$number" <<'PYEOF'
import json, sys
inbounds = json.load(open(sys.argv[1]))["inbounds"]
index = int(sys.argv[2]) - 1
if index >= len(inbounds):
    raise SystemExit("入站编号无效。")
print(inbounds[index]["tag"])
PYEOF
) || return 1
}

select_outbound() {
    local number row label index=0 choices
    local -a items=()
    choices=$(python3 - "$CONFIG_FILE" "${SELECTED_ENTRY:-}" "${1:-}" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
for inbound in config["inbounds"]:
    tag = inbound["tag"]
    if sys.argv[2] and tag != sys.argv[2]:
        continue
    rule = next(item for item in config["routing"]["rules"] if item.get("inboundTag") == [tag])
    members = [out for out in config["outbounds"] if out["tag"].startswith(f"socks5-{tag}-")]
    if not members:
        members = [out for out in config["outbounds"] if out["tag"] == rule["outboundTag"]]
    if sys.argv[3] == "delete" and len(members) == 1:
        continue
    for out in members:
        protocol = out["protocol"]
        server = out["settings"]["vnext" if protocol == "vless" else "servers"][0]
        current = " [当前出口]" if out["tag"] == rule["outboundTag"] else ""
        label = f"{inbound.get('_remark', tag)} :{inbound['port']} → {protocol.upper()} {server['address']}:{server['port']}{current}"
        print("\x1f".join([tag, out["tag"], label]))
PYEOF
) || return 1
    if [[ -z "$choices" ]]; then
        echo "没有可选出站；删除整条节点请选择主菜单 4。"
        return 1
    fi
    while IFS= read -r row; do
        items+=("$row")
        label="${row#*$'\x1f'}"
        printf '%s) %s\n' "$((++index))" "${label#*$'\x1f'}"
    done <<< "$choices"
    prompt_read number -p "出站编号（0 返回）: " || return 1
    [[ -n "$number" && "$number" != 0 ]] || return 1
    if [[ ! "$number" =~ ^[1-9][0-9]*$ ]]; then
        echo "编号无效。" >&2
        return 1
    fi
    if (( ${#number} > 9 || number > ${#items[@]} )); then
        echo "出站编号无效。" >&2
        return 1
    fi
    IFS=$'\x1f' read -r SELECTED_ENTRY SELECTED_OUTBOUND label <<< "${items[number-1]}"
}

apply_change() {
    local action="$1"
    NEW_CONFIG=$(mktemp "${CONFIG_FILE}.new.XXXXXX") || return 1
    if ! generate_config "$NEW_CONFIG" "$@" || ! validate_and_install_config "$NEW_CONFIG"; then
        rm -f -- "$NEW_CONFIG"
        return 1
    fi
    if [[ "$action" == delete-inbound ]] && python3 -c 'import json,sys; sys.exit(bool(json.load(open(sys.argv[1]))["inbounds"]))' "$CONFIG_FILE"; then
        if ! service_control stop || ! service_control disable; then
            cp -a "$CONFIG_BACKUP" "$CONFIG_FILE" || return 1
            apply_config_permissions "$CONFIG_FILE" || return 1
            service_control enable || return 1
            restart_with_rollback || return 1
            echo "停止服务失败，已恢复原节点配置。" >&2
            return 1
        fi
        echo "已删除最后一个节点，中转服务已停止。"
    elif [[ "$SERVICE_MANAGER" == openrc ]]; then
        start_service || return 1
    elif [[ -f "$SERVICE_FILE" ]] && grep -Fxq "ExecStart=\"$XRAY_BIN\" run -config \"$CONFIG_FILE\"" "$SERVICE_FILE"; then
        if [[ "$action" == add-vless || "$action" == add-socks ]]; then
            service_control enable || return 1
        fi
        restart_with_rollback || return 1
    else
        start_service || return 1
    fi
    if [[ "$action" == add-vless || "$action" == add-socks || "$action" == edit-inbound ]]; then
        setup_firewall || return 1
        print_result || return 1
    fi
    if [[ "$action" == delete-inbound && -f "$INFO_FILE" ]]; then
        python3 - "$CONFIG_FILE" "$INFO_FILE" <<'PYEOF' || return 1
import json, sys
from urllib.parse import urlsplit
config = json.load(open(sys.argv[1]))
ports = {node["port"] for node in config["inbounds"]}
with open(sys.argv[2]) as file:
    links = [line for line in file if urlsplit(line.strip()).port in ports]
with open(sys.argv[2], "w") as file:
    file.writelines(links)
PYEOF
        echo "节点及其专用出站已删除，节点链接已更新。"
    fi
    echo "配置已更新。"
}

deploy_inbound() {
    local protocol="${1:-vless}"
    echo "创建 ${protocol^^} 入站，可输入多个 SOCKS5 / VLESS 出站，第一条为当前出口。"
    if [[ "$protocol" == socks ]]; then
        echo "SOCKS5 自动生成账号和密码，传输不加密。"
    fi
    collect_nodes || return 1
    echo "正在获取 VPS 公网 IP..."
    VPS_IP=$(get_ip) || return 1
    echo "正在检查 Xray 核心..."
    install_xray || return 1
    if [[ "$protocol" == vless ]]; then
        echo "正在生成 VLESS UUID 和 REALITY 密钥..."
        generate_keys || return 1
        if [[ -z "$REALITY_SERVER_NAME" ]]; then
            REALITY_SERVER_NAME="${REALITY_HOSTS[RANDOM % ${#REALITY_HOSTS[@]}]}"
        elif ! validate_sni "$REALITY_SERVER_NAME"; then
            echo "REALITY_SERVER_NAME 不是合法域名，或属于过于大众化的站点：${REALITY_SERVER_NAME}" >&2
            echo "请换成具体站点的域名，例如 www.bosch.com。" >&2
            return 1
        fi
        REALITY_DEST="${REALITY_DEST:-${REALITY_SERVER_NAME}:443}"
        echo "REALITY 回落目标: ${REALITY_SERVER_NAME}"
    fi
    (umask 022; install -d -m 755 "$(dirname "$CONFIG_FILE")") || return 1
    if [[ -z "$START_PORT" ]]; then
        echo "正在生成配置，随机分配 10000-65535 的空闲端口..."
    else
        echo "正在生成配置，从 ${START_PORT} 开始顺序分配空闲端口..."
    fi
    apply_change "add-$protocol"
}

add_node_menu() {
    local choice protocol
    while true; do
        clear_screen
        echo "添加节点 — 选择入站协议"
        echo "1) VLESS + REALITY"
        echo "2) SOCKS5（账号密码认证）"
        echo "0) 返回主菜单"
        prompt_read choice -p "选择: " || return 0
        case "$choice" in
            0) return 0 ;;
            1) protocol=vless ;;
            2) protocol=socks ;;
            *) echo "选项无效。" >&2; continue ;;
        esac
        if deploy_inbound "$protocol"; then
            pause_return
            return 0
        fi
        echo "部署失败。请根据以上错误修正后重试，或选择 0 返回。" >&2
    done
}

manage_node_menu() {
    local choice raw action
    select_entry || return 0
    while true; do
        clear_screen
        show_nodes "$SELECTED_ENTRY" || return 1
        echo
        echo "1) 添加出站（SOCKS5 / VLESS）"
        echo "2) 切换当前出站"
        echo "3) 编辑出站"
        echo "4) 修改节点名称和端口"
        echo "0) 返回主菜单"
        echo
        prompt_read choice -p "选择: " || return 0
        SELECTED_OUTBOUND=""
        case "$choice" in
            0) return 0 ;;
            1)
                collect_nodes || continue
                action=add-outbounds
                ;;
            2|3)
                select_outbound || continue
                if [[ "$choice" == 2 ]]; then
                    action=switch-outbound
                else
                    prompt_read raw -s -p "新的 SOCKS5 / VLESS 链接: " || continue
                    echo
                    if ! parse_outbound_raw "$raw"; then
                        echo "格式错误: $PARSE_ERROR" >&2
                        continue
                    fi
                    NODES=("$PARSED_NODE")
                    action=edit-outbound
                fi
                ;;
            4)
                prompt_read EDIT_NAME -p "新名称（回车保留）: " || continue
                prompt_read EDIT_PORT -p "新端口（回车保留）: " || continue
                VPS_IP=$(get_ip) || continue
                action=edit-inbound
                ;;
            *) echo "选项无效。" >&2; continue ;;
        esac
        if ! apply_change "$action" "$SELECTED_ENTRY" "$SELECTED_OUTBOUND"; then
            echo "操作失败。" >&2
        fi
        pause_return
    done
}

check_udp_menu() {
    local host port node count=0
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "暂无节点，请选择 2 添加节点。"
        return 0
    fi
    while IFS=$'\t' read -r host port node; do
        [[ -n "$node" ]] || continue
        count=$((count + 1))
        echo "SOCKS5 出站 ${count}: ${host}:${port}"
        PARSED_HOST="$host" PARSED_PORT="$port"
        probe_socks_udp "$node"
    done < <(python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
for out in json.load(open(sys.argv[1]))["outbounds"]:
    if out.get("protocol") != "socks":
        continue
    server = out["settings"]["servers"][0]
    print("%s\t%s\t%s" % (server["address"], server["port"], json.dumps(out, ensure_ascii=False)))
PYEOF
)
    (( count )) || echo "配置中没有 SOCKS5 出站，UDP 由 VLESS 出站端到端承载。"
}

manage_menu() {
    local choice action
    while true; do
        clear_screen
        echo "=============================================="
        echo " Xray VLESS / SOCKS5 中转"
        echo "=============================================="
        echo
        echo "1) 查看节点"
        echo "2) 添加节点"
        echo "3) 管理节点"
        echo "4) 删除节点（含其出站）"
        echo "5) 删除单个出站（保留节点）"
        echo "6) 查看节点链接"
        echo "7) 检查 SOCKS5 出站的 UDP"
        echo "0) 退出"
        echo
        prompt_read choice -p "选择: " || return 0
        case "$choice" in
            0) return 0 ;;
            2) add_node_menu; continue ;;
            3) manage_node_menu; continue ;;
            1|4|5|6|7)
                if [[ ! -f "$CONFIG_FILE" ]]; then
                    echo "暂无节点，请选择 2 添加节点。" >&2
                    pause_return
                    continue
                fi
                ;;
            *) echo "选项无效。" >&2; continue ;;
        esac
        case "$choice" in
            1) show_nodes ;;
            3) manage_node_menu ;;
            4|5)
                SELECTED_ENTRY="" SELECTED_OUTBOUND=""
                if [[ "$choice" == 4 ]]; then
                    echo "选择要删除的节点，将一并删除它的专用出站。"
                    select_entry "删除节点编号（0 返回）" || continue
                    action=delete-inbound
                else
                    echo "选择要删除的出站；删除当前出口会切换到剩余出站。唯一出站不列出，需删整条节点请选择主菜单 4。"
                    select_outbound delete || continue
                    action=delete-outbound
                fi
                if apply_change "$action" "$SELECTED_ENTRY" "$SELECTED_OUTBOUND"; then
                    show_nodes
                else
                    echo "删除失败，请根据以上错误重试。" >&2
                fi
                ;;
            6)
                if VPS_IP=$(get_ip); then print_result; fi
                ;;
            7) check_udp_menu ;;
        esac
        pause_return
    done
}

main() {
    preflight_check
    trap '[[ -z "$NEW_CONFIG" ]] || rm -f -- "$NEW_CONFIG"' EXIT
    if [[ -f "$CONFIG_FILE" ]]; then
        install_xray
    fi
    manage_menu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
