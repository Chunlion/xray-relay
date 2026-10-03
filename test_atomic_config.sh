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
exec 3>&2

cat > "$TMP_DIR/xray" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    version) echo 'Xray test-core' ;;
    x25519)
        if [[ -n "$XRAY_TEST_BIN" ]]; then
            "$XRAY_TEST_BIN" "$@"
        else
            printf '%s\n' 'PrivateKey: test-private' 'Password (PublicKey): test-public' 'Hash32: ignored'
        fi
        ;;
    run)
        if grep -q '"reject":true' "$4"; then exit 1; fi
        if [[ -n "$XRAY_TEST_BIN" ]]; then
            if ! "$XRAY_TEST_BIN" "$@" > "${4}.check.log" 2>&1; then
                cat "${4}.check.log" >&3
                exit 1
            fi
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
assert len(config["inbounds"]) == 1 and len(config["outbounds"]) == 2
assert [node["port"] for node in config["inbounds"]] == [20001]
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
assert len(links) == 1
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
MODE=success RESTARTS=0
cp "$INFO_FILE" "$TMP_DIR/original.links"
parse_socks5_raw 'socks5://third.example:1082'
NODES=("${PARSED_HOST}"$'\x1f'"${PARSED_PORT}"$'\x1f'"${PARSED_USER}"$'\x1f'"${PARSED_PASS}")
apply_change add-outbounds vless-in-1 > "$TMP_DIR/add.out"
print_result > "$TMP_DIR/links.out"
cmp "$INFO_FILE" "$TMP_DIR/original.links"
python3 - "$CONFIG_FILE" "$TMP_DIR/original.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
assert current["inbounds"] == original["inbounds"]
assert current["routing"] == original["routing"]
assert len(current["outbounds"]) == 3
PYEOF
generate_keys
setup_firewall() { :; }
apply_change add-vless > "$TMP_DIR/new-vless.out"
cp "$CONFIG_FILE" "$TMP_DIR/two-vless.json"
python3 - "$CONFIG_FILE" "$TMP_DIR/original.links" "$INFO_FILE" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
assert len(config["inbounds"]) == 2 and len(config["outbounds"]) == 4
assert [node["port"] for node in config["inbounds"]] == [20001, 20003]
assert open(sys.argv[3]).read().splitlines()[0] == open(sys.argv[2]).read().strip()
PYEOF
manage_menu > "$TMP_DIR/menu.out" <<'EOF'
4
1
2
3
1
socks5://fourth.example:1083

5
1
4
socks5://edited.example:1084
6
1
3
0
EOF
python3 - "$CONFIG_FILE" "$TMP_DIR/two-vless.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
assert current["inbounds"] == original["inbounds"]
assert current["routing"]["rules"][0]["outboundTag"] == "socks5-vless-in-1-2"
assert current["routing"]["rules"][1] == original["routing"]["rules"][1]
assert next(out for out in current["outbounds"] if out["tag"] == "socks5-vless-in-1-4")["settings"]["servers"][0] == {
    "address": "edited.example", "port": 1084}
assert not any(out["tag"] == "socks5-vless-in-1-3" for out in current["outbounds"])
assert next(out for out in current["outbounds"] if out["tag"] == "socks5-vless-in-2-1") == original["outbounds"][-1]
PYEOF
apply_change delete-outbound vless-in-1 socks5-vless-in-1-2 > "$TMP_DIR/delete-current.out"
python3 - "$CONFIG_FILE" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
assert config["routing"]["rules"][0]["outboundTag"] == "socks5-vless-in-1-1"
PYEOF
if apply_change delete-outbound vless-in-2 socks5-vless-in-2-1 > "$TMP_DIR/delete-last.out" 2>&1; then
    echo '不得删除最后一个出站' >&2; exit 1
fi
if apply_change switch-outbound vless-in-1 socks5-vless-in-2-1 > "$TMP_DIR/wrong-owner.out" 2>&1; then
    echo '不得选择其他 VLESS 的出站' >&2; exit 1
fi
cp "$CONFIG_FILE" "$TMP_DIR/before-port.json"
EDIT_PORT=20002 EDIT_NAME='Renamed VLESS'
if apply_change edit-vless vless-in-1 > "$TMP_DIR/occupied.out" 2>&1; then
    echo '不得使用占用端口' >&2; exit 1
fi
cmp "$CONFIG_FILE" "$TMP_DIR/before-port.json"
EDIT_PORT=21000
apply_change edit-vless vless-in-1 > "$TMP_DIR/port.out"
python3 - "$CONFIG_FILE" "$TMP_DIR/before-port.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
assert current["inbounds"][0]["port"] == 21000
assert current["inbounds"][0]["_remark"] == "Renamed VLESS"
assert current["inbounds"][0]["settings"] == original["inbounds"][0]["settings"]
assert current["inbounds"][0]["streamSettings"] == original["inbounds"][0]["streamSettings"]
assert current["inbounds"][1] == original["inbounds"][1]
assert current["outbounds"] == original["outbounds"]
PYEOF
EDIT_PORT="" EDIT_NAME=""
# 上一版一对一配置保留节点身份，只迁移被编辑的入口。
python3 - "$TMP_DIR/two-vless.json" "$CONFIG_FILE" <<'PYEOF'
import json, sys
config = json.load(open(sys.argv[1]))
previous = {out["tag"]: out for out in config["outbounds"]}
config["outbounds"] = []
for index, rule in enumerate(config["routing"]["rules"]):
    outbound = previous[rule["outboundTag"]]
    outbound["tag"] = f"socks5-out-{1 if index == 0 else 10}"
    rule["outboundTag"] = outbound["tag"]
    config["outbounds"].append(outbound)
json.dump(config, open(sys.argv[2], "w"))
PYEOF
cp "$CONFIG_FILE" "$TMP_DIR/legacy.json"
apply_change add-outbounds vless-in-1 > "$TMP_DIR/migrate.out"
python3 - "$CONFIG_FILE" "$TMP_DIR/legacy.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
assert current["inbounds"] == original["inbounds"]
assert current["routing"]["rules"][1] == original["routing"]["rules"][1]
assert original["outbounds"][1] in current["outbounds"]
assert current["routing"]["rules"][0]["outboundTag"] == "socks5-vless-in-1-1"
assert len([out for out in current["outbounds"] if out["tag"].startswith("socks5-vless-in-1-")]) == 2
PYEOF
VPS_IP=2001:db8::10
generate_config "$TMP_DIR/ipv6.json"
python3 - "$TMP_DIR/ipv6.json" <<'PYEOF'
import json, sys
assert json.load(open(sys.argv[1]))["inbounds"][-1]["listen"] == "::"
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
echo 'PASS: 核心复用、多出站、手动切换、菜单编辑、旧配置兼容、端口避让和失败回滚'
