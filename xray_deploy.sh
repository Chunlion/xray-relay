#!/usr/bin/env bash
# VLESS + REALITY 入口，每个入口可绑定多个 SOCKS5 出站。
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
NODES=()

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
    local candidate service_start service_bin="" relay_bin="" arch work
    service_start=$(systemctl show -p ExecStart --value xray-relay 2>/dev/null || true)
    if [[ "$service_start" =~ path=([^[:space:]\;]+) ]]; then
        relay_bin="${BASH_REMATCH[1]}"
    fi
    service_start=$(systemctl show -p ExecStart --value xray 2>/dev/null || true)
    if [[ "$service_start" =~ path=([^[:space:]\;]+) ]]; then
        service_bin="${BASH_REMATCH[1]}"
    fi
    for candidate in "$relay_bin" /etc/xray/bin/xray /usr/local/bin/xray "$service_bin" /usr/local/lib/xray-relay/xray; do
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
    if ! install -d -m 755 /usr/local/lib/xray-relay \
        || ! install -m 755 "$work/xray" /usr/local/lib/xray-relay/xray; then
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
            echo "已添加出站 ${#NODES[@]}: ${PARSED_HOST}:${PARSED_PORT}"
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
    local target="$1" action="${2:-add-vless}" entry="${3:-}" outbound="${4:-}" occupied
    occupied=$(ss -H -ltn) || return 1
    CONFIG_FILE="$CONFIG_FILE" NEW_CONFIG_FILE="$target" ACTION="$action" ENTRY_TAG="$entry" \
    OUTBOUND_TAG="$outbound" EDIT_PORT="${EDIT_PORT:-}" EDIT_NAME="${EDIT_NAME:-}" \
    VPS_IP="${VPS_IP:-}" UUID="${UUID:-}" PRIVATE_KEY="${PRIVATE_KEY:-}" SHORT_ID="${SHORT_ID:-}" \
    START_PORT="$START_PORT" OCCUPIED="$occupied" REALITY_DEST="$REALITY_DEST" \
    REALITY_SERVER_NAME="$REALITY_SERVER_NAME" NODES_DATA="$(printf '%s\n' "${NODES[@]}")" \
    python3 - <<'PYEOF'
import copy, json, os, re
source = os.environ["CONFIG_FILE"]
if os.path.isfile(source):
    with open(source) as file:
        config = json.load(file)
else:
    config = {"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [],
              "routing": {"domainStrategy": "AsIs", "rules": []}}
inbounds, outbounds, rules = config["inbounds"], config["outbounds"], config["routing"]["rules"]
action, entry_tag, outbound_tag = (os.environ[key] for key in ("ACTION", "ENTRY_TAG", "OUTBOUND_TAG"))
nodes = [node for node in os.environ["NODES_DATA"].splitlines() if node]
used = {int(line.split()[3].rsplit(":", 1)[1])
        for line in os.environ["OCCUPIED"].splitlines() if line.strip()}

def add_outbounds(prefix):
    added = []
    for node in nodes:
        host, port, user, password = node.split("\x1f")
        index = 1
        while any(out["tag"] == f"{prefix}{index}" for out in outbounds):
            index += 1
        server = {"address": host, "port": int(port)}
        if user:
            server["users"] = [{"user": user, "pass": password}]
        out = {"tag": f"{prefix}{index}", "protocol": "socks", "settings": {"servers": [server]}}
        outbounds.append(out)
        added.append(out)
    return added

if action == "add-vless":
    if not nodes:
        raise SystemExit("至少需要一个 SOCKS5 出站。")
    used.update(inbound["port"] for inbound in inbounds)
    port = int(os.environ["START_PORT"])
    while port in used:
        port += 1
    if port > 65535:
        raise SystemExit("没有可用的监听端口。")
    index = 1
    while any(inbound["tag"] == f"vless-in-{index}" for inbound in inbounds):
        index += 1
    entry_tag = f"vless-in-{index}"
    inbound = {
        "tag": entry_tag, "_remark": f"VLESS-{index}",
        "listen": "::" if ":" in os.environ["VPS_IP"] else "0.0.0.0", "port": port, "protocol": "vless",
        "settings": {"clients": [{"id": os.environ["UUID"], "flow": "xtls-rprx-vision"}], "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": os.environ["REALITY_DEST"], "serverNames": [os.environ["REALITY_SERVER_NAME"]],
            "privateKey": os.environ["PRIVATE_KEY"], "shortIds": [os.environ["SHORT_ID"]]}}
    }
    inbounds.append(inbound)
    added = add_outbounds(f"socks5-{entry_tag}-")
    rules.append({"type": "field", "inboundTag": [entry_tag], "outboundTag": added[0]["tag"]})
else:
    inbound = next((item for item in inbounds if item["tag"] == entry_tag), None)
    rule = next((item for item in rules if item.get("inboundTag") == [entry_tag]), None)
    if not inbound or not rule:
        raise SystemExit("VLESS 或对应路由不存在。")
    prefix = f"socks5-{entry_tag}-"
    members = [out for out in outbounds if out["tag"].startswith(prefix)]
    # 将上一版一对一的出站纳入该入口，保持其他入口的路由不变。
    if not members:
        old = next((out for out in outbounds if out["tag"] == rule.get("outboundTag")), None)
        if not old or old["protocol"] != "socks":
            raise SystemExit("找不到该 VLESS 的 SOCKS5 出站。")
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
            raise SystemExit("至少需要一个 SOCKS5 出站。")
        add_outbounds(prefix)
    elif action == "switch-outbound":
        if not selected:
            raise SystemExit("出站不属于该 VLESS。")
        rule["outboundTag"] = selected["tag"]
    elif action == "edit-outbound":
        if not selected or len(nodes) != 1:
            raise SystemExit("选择一个出站并输入一条新的 SOCKS5 链接。")
        host, port, user, password = nodes[0].split("\x1f")
        server = {"address": host, "port": int(port)}
        if user:
            server["users"] = [{"user": user, "pass": password}]
        selected["settings"] = {"servers": [server]}
    elif action == "delete-outbound":
        if not selected:
            raise SystemExit("出站不属于该 VLESS。")
        if len(members) == 1:
            raise SystemExit("不能删除最后一个出站。")
        outbounds.remove(selected)
        if rule["outboundTag"] == selected["tag"]:
            rule["outboundTag"] = next(out["tag"] for out in members if out is not selected)
    elif action == "edit-vless":
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
    if output=$("$XRAY_BIN" run -test -config "$new_config" 2>&1); then
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
        CONFIG_BACKUP="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S-%N)"
        cp -a "$CONFIG_FILE" "$CONFIG_BACKUP" || return 1
        chmod 600 "$CONFIG_BACKUP" || return 1
    fi
    mv -f "$new_config" "$CONFIG_FILE"
}

start_service() {
    local unit_tmp
    unit_tmp=$(mktemp "${SERVICE_FILE}.XXXXXX") || return 1
    cat > "$unit_tmp" <<EOF || return 1
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
    chmod 644 "$unit_tmp" || return 1
    mv -f "$unit_tmp" "$SERVICE_FILE" || return 1
    systemctl daemon-reload || return 1
    systemctl enable xray-relay || return 1
    restart_with_rollback
}

restart_with_rollback() {
    local since output
    since=$(date +%s)
    echo "正在启动 xray-relay 服务..."
    if systemctl restart xray-relay; then
        sleep 2
        if systemctl is-active --quiet xray-relay; then
            echo "xray-relay 服务运行中。"
            return 0
        fi
    fi
    echo "xray-relay 启动失败，服务日志：" >&2
    output=$(journalctl -u xray-relay --since "@$since" -n 15 --no-pager 2>&1 || true)
    show_xray_error "$CONFIG_FILE" "$output"
    if [[ -n "$CONFIG_BACKUP" ]]; then
        cp -a "$CONFIG_BACKUP" "$CONFIG_FILE" || return 1
        apply_config_permissions "$CONFIG_FILE" || return 1
        if systemctl restart xray-relay; then
            sleep 2
            if systemctl is-active --quiet xray-relay; then
                echo "启动失败，已恢复原中转配置。" >&2
                return 1
            fi
        fi
        echo "已恢复原中转配置，但服务未恢复，请检查 journalctl -u xray-relay。" >&2
    else
        if ! systemctl stop xray-relay; then
            echo "启动失败，且无法停止 xray-relay，请检查 journalctl -u xray-relay。" >&2
            return 1
        fi
        systemctl disable xray-relay || return 1
        rm -f -- "$CONFIG_FILE" || return 1
        echo "首次启动失败，已停止服务并撤销本次配置，可从部署菜单重试。" >&2
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
    name = inbound.get("_remark", f"VLESS-{index}")
    lines.append(f"vless://{uuid}@{host}:{inbound['port']}?{query}#{quote(name)}")
with open(sys.argv[2], "w") as file:
    file.write("\n".join(lines) + "\n")
os.chmod(sys.argv[2], 0o600)
print("节点链接：\n" + "\n\n".join(lines))
print(f"链接已保存到 {sys.argv[2]}")
print("请在云安全组及自定义防火墙中放行这些节点的 TCP 端口。")
PYEOF
}

show_nodes() {
    python3 - "$CONFIG_FILE" "${1:-}" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
for index, inbound in enumerate(config["inbounds"], 1):
    tag = inbound["tag"]
    if sys.argv[2] and tag != sys.argv[2]:
        continue
    rule = next(item for item in config["routing"]["rules"] if item.get("inboundTag") == [tag])
    members = [out for out in config["outbounds"] if out["tag"].startswith(f"socks5-{tag}-")]
    if not members:
        members = [out for out in config["outbounds"] if out["tag"] == rule["outboundTag"]]
    print(f"{index}) {inbound.get('_remark', tag)}  端口 {inbound['port']}")
    for number, outbound in enumerate(members, 1):
        server = outbound["settings"]["servers"][0]
        current = " [当前]" if outbound["tag"] == rule["outboundTag"] else ""
        print(f"   {number}) {server['address']}:{server['port']}{current}")
PYEOF
}

select_entry() {
    local number
    show_nodes || return 1
    prompt_read number -p "VLESS 编号: " || return 1
    if [[ ! "$number" =~ ^[1-9][0-9]*$ ]]; then
        echo "编号无效。" >&2
        return 1
    fi
    SELECTED_ENTRY=$(python3 - "$CONFIG_FILE" "$number" <<'PYEOF'
import json, sys
inbounds = json.load(open(sys.argv[1]))["inbounds"]
index = int(sys.argv[2]) - 1
if index >= len(inbounds):
    raise SystemExit("VLESS 编号无效。")
print(inbounds[index]["tag"])
PYEOF
) || return 1
}

select_outbound() {
    local number
    show_nodes "$SELECTED_ENTRY" || return 1
    prompt_read number -p "出站编号: " || return 1
    if [[ ! "$number" =~ ^[1-9][0-9]*$ ]]; then
        echo "编号无效。" >&2
        return 1
    fi
    SELECTED_OUTBOUND=$(python3 - "$CONFIG_FILE" "$SELECTED_ENTRY" "$number" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
tag = sys.argv[2]
members = [out for out in config["outbounds"] if out["tag"].startswith(f"socks5-{tag}-")]
if not members:
    rule = next(item for item in config["routing"]["rules"] if item.get("inboundTag") == [tag])
    members = [out for out in config["outbounds"] if out["tag"] == rule["outboundTag"]]
index = int(sys.argv[3]) - 1
if index >= len(members):
    raise SystemExit("出站编号无效。")
print(members[index]["tag"])
PYEOF
) || return 1
}

apply_change() {
    local action="$1"
    NEW_CONFIG=$(mktemp --suffix=.json "${CONFIG_FILE}.new.XXXXXX") || return 1
    if ! generate_config "$NEW_CONFIG" "$@" || ! validate_and_install_config "$NEW_CONFIG"; then
        rm -f -- "$NEW_CONFIG"
        return 1
    fi
    if [[ -f "$SERVICE_FILE" ]] && grep -Fxq "ExecStart=\"$XRAY_BIN\" run -config \"$CONFIG_FILE\"" "$SERVICE_FILE"; then
        restart_with_rollback || return 1
    else
        start_service || return 1
    fi
    if [[ "$action" == add-vless || "$action" == edit-vless ]]; then
        setup_firewall || return 1
        print_result || return 1
    fi
    echo "配置已更新。"
}

deploy_vless() {
    echo "创建一个 VLESS，输入的多个 SOCKS5 将作为它的出站，第一条为当前出口。"
    collect_nodes || return 1
    echo "正在获取 VPS 公网 IP..."
    VPS_IP=$(get_ip) || return 1
    echo "正在检查 Xray 核心..."
    install_xray || return 1
    echo "正在生成 VLESS UUID 和 REALITY 密钥..."
    generate_keys || return 1
    install -d -m 755 "$(dirname "$CONFIG_FILE")" || return 1
    echo "正在生成配置，从 ${START_PORT} 开始分配空闲端口..."
    apply_change add-vless
}

manage_menu() {
    local choice raw action
    while true; do
        echo
        echo "1) 查看 VLESS 和出站"
        echo "2) 新增 VLESS"
        echo "3) 为 VLESS 添加 SOCKS5 出站"
        echo "4) 切换当前出站"
        echo "5) 编辑 SOCKS5 出站"
        echo "6) 删除 SOCKS5 出站"
        echo "7) 修改 VLESS 名称和端口"
        echo "8) 查看节点链接"
        echo "0) 退出"
        prompt_read choice -p "选择: " || return 0
        case "$choice" in
            0) return 0 ;;
            1) show_nodes ;;
            2)
                if ! deploy_vless; then
                    echo "新增 VLESS 失败，请根据以上错误修正后重试。" >&2
                fi
                ;;
            3|4|5|6|7)
                select_entry || continue
                case "$choice" in
                    3)
                        collect_nodes || continue
                        action=add-outbounds
                        SELECTED_OUTBOUND=""
                        ;;
                    4|5|6)
                        if [[ "$choice" == 6 ]]; then
                            echo "删除当前出口后将切换到第一个剩余出站；最后一个出站不能删除。"
                        fi
                        select_outbound || continue
                        case "$choice" in
                            4) action=switch-outbound ;;
                            5)
                                prompt_read raw -s -p "新的 SOCKS5 链接: " || continue
                                echo
                                if ! parse_socks5_raw "$raw"; then
                                    echo "格式错误: $PARSE_ERROR" >&2
                                    continue
                                fi
                                NODES=("${PARSED_HOST}"$'\x1f'"${PARSED_PORT}"$'\x1f'"${PARSED_USER}"$'\x1f'"${PARSED_PASS}")
                                action=edit-outbound
                                ;;
                            6) action=delete-outbound ;;
                        esac
                        ;;
                    7)
                        prompt_read EDIT_NAME -p "新名称（回车保留）: " || continue
                        prompt_read EDIT_PORT -p "新端口（回车保留）: " || continue
                        VPS_IP=$(get_ip) || continue
                        action=edit-vless
                        SELECTED_OUTBOUND=""
                        ;;
                esac
                if ! apply_change "$action" "$SELECTED_ENTRY" "$SELECTED_OUTBOUND"; then
                    echo "操作失败。" >&2
                fi
                ;;
            8)
                if VPS_IP=$(get_ip); then print_result; fi
                ;;
            *) echo "选项无效。" >&2 ;;
        esac
    done
}

main() {
    local choice
    preflight_check
    trap '[[ -z "$NEW_CONFIG" ]] || rm -f -- "$NEW_CONFIG"' EXIT
    echo "Xray VLESS → SOCKS5"
    while true; do
        if [[ -f "$CONFIG_FILE" ]]; then
            install_xray
            echo "已检测到中转配置，进入管理菜单。"
            manage_menu
            return
        fi
        echo
        echo "1) 部署 VLESS + SOCKS5"
        echo "0) 退出"
        prompt_read choice -p "选择: " || return 0
        case "$choice" in
            0) return 0 ;;
            1)
                if deploy_vless; then
                    manage_menu
                    return
                fi
                echo "部署失败。请根据以上错误修正后选择 1 重试，或选择 0 退出。" >&2
                ;;
            *) echo "选项无效。" >&2 ;;
        esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
