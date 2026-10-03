#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
source ./xray_deploy.sh
TMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TMP_DIR"' EXIT
CONFIG_FILE="$TMP_DIR/config.json"
INFO_FILE="$TMP_DIR/nodes.txt"
SERVICE_FILE="$TMP_DIR/xray-relay.service"
CALLS="$TMP_DIR/systemctl.calls"
export XRAY_TEST_BIN="${XRAY_TEST_BIN:-}"

cat > "$TMP_DIR/xray" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    version) echo 'Xray test-core' ;;
    x25519)
        if [[ -n "$XRAY_TEST_BIN" ]]; then
            "$XRAY_TEST_BIN" x25519
        else
            printf '%s\n' 'PrivateKey: test-private' 'Password (PublicKey): test-public' 'Hash32: ignored'
        fi
        ;;
    run)
        if grep -q '"reject":true' "$4"; then exit 1; fi
        if [[ -n "$XRAY_TEST_BIN" ]]; then
            "$XRAY_TEST_BIN" "$@"
        else
            python3 -m json.tool "$4" >/dev/null
        fi
        ;;
    *) exit 1 ;;
esac
EOF
chmod 700 "$TMP_DIR/xray"
systemctl() {
    printf '%s\n' "$*" >> "$CALLS"
    case "$1" in
        show) printf '{ path=%s ; argv[]=%s run ; }\n' "$TMP_DIR/xray" "$TMP_DIR/xray" ;;
        restart)
            RESTARTS=$((RESTARTS + 1))
            [[ "$MODE" != rollback || "$RESTARTS" -gt 1 ]]
            ;;
        is-active) [[ "$MODE" != rollback || "$RESTARTS" -gt 1 ]] ;;
        daemon-reload|enable) return 0 ;;
        *) return 1 ;;
    esac
}
MODE=success RESTARTS=0
curl() { echo '不应重复下载核心' >&2; return 1; }
install_xray > "$TMP_DIR/detection.out"
[[ -x "$XRAY_BIN" ]]
XRAY_BIN="$TMP_DIR/xray"
generate_keys
[[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" && "$PUBLIC_KEY" != ignored ]]
apply_config_permissions() { chmod 640 "$1"; }
sleep() { :; }
ss() {
    printf '%s\n' 'LISTEN 0 4096 0.0.0.0:20000 0.0.0.0:*' 'LISTEN 0 4096 [::]:20002 [::]:*'
}
VPS_IP=203.0.113.10
collect_nodes > "$TMP_DIR/prompts.out" <<'EOF'
socks5://u:p%3A%40@proxy.example:1080
socks5://[2001:db8::1]:1081

EOF
[[ ${#NODES[@]} == 2 ]]
[[ -n "$PARSED_HOST" && -z "$PARSED_USER" && -z "$PARSED_PASS" ]]
generate_config "$TMP_DIR/new.json"
python3 - "$TMP_DIR/new.json" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
assert set(config) == {"log", "inbounds", "outbounds", "routing"}
assert len(config["inbounds"]) == len(config["outbounds"]) == 2
assert [node["port"] for node in config["inbounds"]] == [20001, 20003]
assert all(node["protocol"] == "vless" and node["listen"] == "0.0.0.0" for node in config["inbounds"])
assert all(node["protocol"] == "socks" for node in config["outbounds"])
servers = [out["settings"]["servers"][0] for out in config["outbounds"]]
assert servers[0]["users"] == [{"user": "u", "pass": "p:@"}]
assert servers[1]["address"] == "2001:db8::1" and "users" not in servers[1]
for inbound, outbound, rule in zip(config["inbounds"], config["outbounds"], config["routing"]["rules"]):
    assert rule["inboundTag"] == [inbound["tag"]] and rule["outboundTag"] == outbound["tag"]
assert config["routing"]["domainStrategy"] == "AsIs"
PYEOF
cp "$TMP_DIR/new.json" "$CONFIG_FILE"
cp "$CONFIG_FILE" "$TMP_DIR/original.json"
printf '%s\n' '{"reject":true}' > "$TMP_DIR/bad.json"
if validate_and_install_config "$TMP_DIR/bad.json" > "$TMP_DIR/error.out" 2>&1; then
    echo '校验失败应返回非零' >&2; exit 1
fi
cmp "$CONFIG_FILE" "$TMP_DIR/original.json"
validate_and_install_config "$TMP_DIR/new.json"
[[ -f "$CONFIG_BACKUP" && $(stat -c %a "$CONFIG_BACKUP") == 600 ]]
[[ $(stat -c %a "$CONFIG_FILE") == 640 ]]
start_service
[[ $(stat -c %a "$SERVICE_FILE") == 644 ]]
grep -Fq "ExecStart=\"$XRAY_BIN\" run -config \"$CONFIG_FILE\"" "$SERVICE_FILE"
if grep -Eq '^(restart|enable) xray$' "$CALLS"; then
    echo '不得修改原 Xray 服务' >&2; exit 1
fi
print_result > "$TMP_DIR/result.out"
[[ $(stat -c %a "$INFO_FILE") == 600 ]]
python3 - "$CONFIG_FILE" "$INFO_FILE" <<'PYEOF'
import json, sys
from urllib.parse import urlsplit, parse_qs
config = json.load(open(sys.argv[1]))
links = open(sys.argv[2]).read().splitlines()
assert len(links) == 2
for inbound, link in zip(config["inbounds"], links):
    url = urlsplit(link)
    assert url.scheme == "vless" and url.hostname == "203.0.113.10"
    assert url.port == inbound["port"]
    assert url.username == inbound["settings"]["clients"][0]["id"]
    query = parse_qs(url.query)
    assert query["security"] == ["reality"] and query["flow"] == ["xtls-rprx-vision"]
    assert query["pbk"] and query["sid"] == inbound["streamSettings"]["realitySettings"]["shortIds"]
PYEOF
MODE=rollback RESTARTS=0
printf '%s\n' '{"broken":true}' > "$CONFIG_FILE"
if restart_with_rollback > "$TMP_DIR/rollback.out" 2>&1; then
    echo '回滚应报告部署失败' >&2; exit 1
fi
[[ "$RESTARTS" == 2 ]]
cmp "$CONFIG_FILE" "$TMP_DIR/original.json"
[[ $(stat -c %a "$CONFIG_FILE") == 640 ]]
VPS_IP=2001:db8::10
generate_config "$TMP_DIR/ipv6.json"
python3 - "$TMP_DIR/ipv6.json" <<'PYEOF'
import json, sys
assert all(node["listen"] == "::" for node in json.load(open(sys.argv[1]))["inbounds"])
PYEOF
START_PORT=65535
ss() { printf '%s\n' 'LISTEN 0 4096 [::]:65535 [::]:*'; }
if generate_config "$TMP_DIR/full.json" > "$TMP_DIR/full.out" 2>&1; then
    echo '端口耗尽应失败' >&2; exit 1
fi
if collect_nodes </dev/null > "$TMP_DIR/eof.out" 2>&1; then
    echo '空输入不得部署' >&2; exit 1
fi
if [[ -n "$XRAY_TEST_BIN" ]]; then
    echo 'PASS: 配置通过真实 Xray 核心校验'
fi
echo 'PASS: 核心复用、多出口映射、端口避让、独立服务、链接和失败回滚'
