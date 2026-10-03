#!/usr/bin/env bash
# VLESS + REALITY 入口，每个入口对应一个 SOCKS5 出站。
set -euo pipefail
umask 077

CONFIG_FILE="/usr/local/etc/xray-relay/config.json"
INFO_FILE="/root/xray_nodes_info.txt"
SERVICE_FILE="/etc/systemd/system/xray-relay.service"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.cloudflare.com}"
REALITY_DEST="${REALITY_DEST:-${REALITY_SERVER_NAME}:443}"
CLIENT_FP="${CLIENT_FP:-chrome}"
START_PORT="${START_PORT:-20000}"
XRAY_BIN=""
CONFIG_BACKUP=""
NEW_CONFIG=""

prompt_read() {
    local variable="$1" value
    shift
    if ! read -r "$@" value; then
        return 1
    fi
    printf -v "$variable" '%s' "$value"
}

parse_socks5_raw() {
    local raw="$1" out payload
    PARSED_HOST="" PARSED_PORT="" PARSED_USER="" PARSED_PASS="" PARSE_ERROR=""
    out=$(INPUT="$raw" python3 - <<'PYEOF'
import os, sys, re, ipaddress
from urllib.parse import urlsplit, unquote

raw = os.environ["INPUT"].strip()
def fail(message):
    print("ERR\t" + message)
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
    print("OK\t" + "\x1f".join(fields))
    sys.exit(0)

if re.search(r'[\x00-\x1f\x7f]', raw):
    fail("链接不能包含控制字符")
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
fail("使用 socks5://用户名:密码@地址:端口 或 socks5://地址:端口")
PYEOF
)
    if [[ "$out" == OK$'\t'* ]]; then
        payload="${out#*$'\t'}"
        IFS=$'\x1f' read -r PARSED_HOST PARSED_PORT PARSED_USER PARSED_PASS <<< "$payload"
        return 0
    fi
    PARSE_ERROR="${out#*$'\t'}"
    return 1
}

preflight_check() {
    if [[ $(id -u) != 0 || ! -d /run/systemd/system ]]; then
        echo "需要在使用 systemd 的 Linux VPS 上以 root 运行。" >&2
        return 1
    fi
    local missing=0 cmd
    for cmd in curl python3 ss unzip; do
        command -v "$cmd" >/dev/null || missing=1
    done
    if (( missing )); then
        if command -v apt-get >/dev/null; then
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
    if [[ ! "$START_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$START_PORT < 1024 || 10#$START_PORT > 65535 )); then
        echo "START_PORT 必须在 1024-65535 之间。" >&2
        return 1
    fi
    START_PORT=$((10#$START_PORT))
}

install_xray() {
    local candidate service_start service_bin="" arch work
    service_start=$(systemctl show -p ExecStart --value xray 2>/dev/null || true)
    if [[ "$service_start" =~ path=([^[:space:]\;]+) ]]; then
        service_bin="${BASH_REMATCH[1]}"
    fi
    for candidate in /etc/xray/bin/xray /usr/local/bin/xray "$service_bin" /usr/local/lib/xray-relay/xray; do
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
    work=$(mktemp -d)
    if ! curl -fSL --connect-timeout 10 --max-time 120 \
        "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${arch}.zip" -o "$work/xray.zip" \
        || ! unzip -q "$work/xray.zip" xray -d "$work"; then
        rm -rf -- "$work"
        echo "下载 Xray 核心失败。" >&2
        return 1
    fi
    install -d -m 755 /usr/local/lib/xray-relay
    install -m 755 "$work/xray" /usr/local/lib/xray-relay/xray
    rm -rf -- "$work"
    XRAY_BIN=/usr/local/lib/xray-relay/xray
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

collect_nodes() {
    local raw
    NODES=()
    echo "逐行粘贴 SOCKS5 链接，输入隐藏；全部输入后按空回车结束。"
    while true; do
        if ! prompt_read raw -s -p "SOCKS5 [$(( ${#NODES[@]} + 1 ))]: "; then
            echo
            break
        fi
        echo
        [[ -n "$raw" ]] || break
        if parse_socks5_raw "$raw"; then
            NODES+=("${PARSED_HOST}"$'\x1f'"${PARSED_PORT}"$'\x1f'"${PARSED_USER}"$'\x1f'"${PARSED_PASS}")
        else
            echo "格式错误: $PARSE_ERROR" >&2
        fi
    done
    if (( ${#NODES[@]} == 0 )); then
        echo "未输入 SOCKS5，操作取消。" >&2
        return 1
    fi
}

generate_keys() {
    local key_output
    key_output=$("$XRAY_BIN" x25519)
    PRIVATE_KEY=$(awk -F ': *' 'tolower($1) ~ /^private ?key$/ {print $2}' <<< "$key_output")
    PUBLIC_KEY=$(awk -F ': *' 'tolower($1) ~ /public|^password/ {print $2; exit}' <<< "$key_output")
    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        echo "Xray 未返回有效的 REALITY 密钥对。" >&2
        return 1
    fi
    UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
    SHORT_ID=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
}

generate_config() {
    local target="$1" occupied
    occupied=$(ss -H -ltn)
    NEW_CONFIG_FILE="$target" VPS_IP="$VPS_IP" UUID="$UUID" PRIVATE_KEY="$PRIVATE_KEY" SHORT_ID="$SHORT_ID" \
    START_PORT="$START_PORT" OCCUPIED="$occupied" REALITY_DEST="$REALITY_DEST" \
    REALITY_SERVER_NAME="$REALITY_SERVER_NAME" NODES_DATA="$(printf '%s\n' "${NODES[@]}")" \
    python3 - <<'PYEOF'
import json, os
used = {int(line.split()[3].rsplit(":", 1)[1])
        for line in os.environ["OCCUPIED"].splitlines() if line.strip()}
port = int(os.environ["START_PORT"])
inbounds, outbounds = [], []
for index, node in enumerate(os.environ["NODES_DATA"].splitlines(), 1):
    host, socks_port, user, password = node.split("\x1f")
    while port in used:
        port += 1
    if port > 65535:
        raise SystemExit("没有可用的监听端口。")
    inbounds.append({
        "tag": f"vless-in-{index}", "listen": "::" if ":" in os.environ["VPS_IP"] else "0.0.0.0",
        "port": port, "protocol": "vless",
        "settings": {"clients": [{"id": os.environ["UUID"], "flow": "xtls-rprx-vision"}], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": os.environ["REALITY_DEST"], "serverNames": [os.environ["REALITY_SERVER_NAME"]],
            "privateKey": os.environ["PRIVATE_KEY"], "shortIds": [os.environ["SHORT_ID"]]}}
    })
    server = {"address": host, "port": int(socks_port)}
    if user:
        server["users"] = [{"user": user, "pass": password}]
    outbounds.append({"tag": f"socks5-out-{index}", "protocol": "socks", "settings": {"servers": [server]}})
    used.add(port)
    port += 1
config = {
    "log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds,
    "routing": {"domainStrategy": "AsIs", "rules": [
        {"type": "field", "inboundTag": [inbound["tag"]], "outboundTag": outbound["tag"]}
        for inbound, outbound in zip(inbounds, outbounds)]}
}
with open(os.environ["NEW_CONFIG_FILE"], "w") as file:
    json.dump(config, file, indent=2)
PYEOF
}

apply_config_permissions() {
    local target="$1" group
    group=$(id -gn nobody)
    chown "root:$group" "$target"
    chmod 640 "$target"
}

validate_and_install_config() {
    local new_config="$1"
    CONFIG_BACKUP=""
    if ! "$XRAY_BIN" run -test -config "$new_config" >/dev/null 2>&1; then
        echo "Xray 配置校验失败，原配置未修改。" >&2
        return 1
    fi
    apply_config_permissions "$new_config"
    if [[ -f "$CONFIG_FILE" ]]; then
        CONFIG_BACKUP="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S-%N)"
        cp -a "$CONFIG_FILE" "$CONFIG_BACKUP"
        chmod 600 "$CONFIG_BACKUP"
    fi
    mv -f "$new_config" "$CONFIG_FILE"
}

start_service() {
    local unit_tmp
    unit_tmp=$(mktemp "${SERVICE_FILE}.XXXXXX")
    cat > "$unit_tmp" <<EOF
[Unit]
Description=Xray VLESS to SOCKS5 relay
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
    chmod 644 "$unit_tmp"
    mv -f "$unit_tmp" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable xray-relay
    restart_with_rollback
}

restart_with_rollback() {
    if systemctl restart xray-relay; then
        sleep 2
        if systemctl is-active --quiet xray-relay; then
            return 0
        fi
    fi
    if [[ -n "$CONFIG_BACKUP" ]]; then
        cp -a "$CONFIG_BACKUP" "$CONFIG_FILE"
        apply_config_permissions "$CONFIG_FILE"
        if systemctl restart xray-relay; then
            sleep 2
            if systemctl is-active --quiet xray-relay; then
                echo "启动失败，已恢复原中转配置。" >&2
                return 1
            fi
        fi
        echo "已恢复原中转配置，但服务未恢复，请检查 journalctl -u xray-relay。" >&2
    else
        echo "启动失败，请检查 journalctl -u xray-relay。" >&2
    fi
    return 1
}

setup_firewall() {
    local port
    while read -r port; do
        if command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
            ufw allow "$port/tcp"
        elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="$port/tcp"
            firewall-cmd --add-port="$port/tcp"
        fi
    done < <(python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
for inbound in json.load(open(sys.argv[1]))["inbounds"]:
    print(inbound["port"])
PYEOF
)
}

print_result() {
    VPS_IP="$VPS_IP" PUBLIC_KEY="$PUBLIC_KEY" CLIENT_FP="$CLIENT_FP" \
    python3 - "$CONFIG_FILE" "$INFO_FILE" <<'PYEOF'
import json, os, sys
from urllib.parse import urlencode, quote
config = json.load(open(sys.argv[1]))
host = os.environ["VPS_IP"]
if ":" in host:
    host = f"[{host}]"
lines = []
for index, inbound in enumerate(config["inbounds"], 1):
    reality = inbound["streamSettings"]["realitySettings"]
    query = urlencode({"encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
                       "sni": reality["serverNames"][0], "fp": os.environ["CLIENT_FP"],
                       "pbk": os.environ["PUBLIC_KEY"], "sid": reality["shortIds"][0], "type": "tcp"})
    uuid = inbound["settings"]["clients"][0]["id"]
    lines.append(f"vless://{uuid}@{host}:{inbound['port']}?{query}#{quote(f'SOCKS5-{index}')}")
with open(sys.argv[2], "w") as file:
    file.write("\n".join(lines) + "\n")
os.chmod(sys.argv[2], 0o600)
print("部署完成，节点链接：\n" + "\n\n".join(lines))
print(f"链接已保存到 {sys.argv[2]}")
print("请在云安全组及自定义防火墙中放行这些节点的 TCP 端口。")
PYEOF
}

main() {
    preflight_check
    collect_nodes
    VPS_IP=$(get_ip)
    install_xray
    generate_keys
    install -d -m 755 "$(dirname "$CONFIG_FILE")"
    NEW_CONFIG=$(mktemp "${CONFIG_FILE}.new.XXXXXX")
    trap 'rm -f -- "$NEW_CONFIG"' EXIT
    generate_config "$NEW_CONFIG"
    validate_and_install_config "$NEW_CONFIG"
    start_service
    setup_firewall
    print_result
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
