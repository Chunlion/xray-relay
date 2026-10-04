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
        if [[ "${FAIL_DERIVE:-0}" == 1 && "$#" -gt 1 ]]; then exit 9; fi
        if [[ -n "$XRAY_TEST_BIN" ]]; then
            "$XRAY_TEST_BIN" "$@"
        else
            printf '%s\n' 'PrivateKey: test-private' 'Password (PublicKey): test-public' 'Hash32: ignored'
        fi
        ;;
    run)
        if grep -q '"reject":true' "$4"; then
            echo 'mock configuration rejected: diagnostic-user diagnostic-password diagnostic-id diagnostic-private' >&2
            exit 1
        fi
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
        daemon-reload|enable|stop|disable) return 0 ;;
        *) return 1 ;;
    esac
}
# 配置权限错误必须在 chmod 之前停止，即使调用方通过 if 检查返回值。
(
    chown() { return 1; }
    chmod() { touch "$TMP_DIR/unexpected-chmod"; }
    if apply_config_permissions "$TMP_DIR/permissions.json"; then
        echo '属组设置失败不得报告成功' >&2; exit 1
    fi
    [[ ! -e "$TMP_DIR/unexpected-chmod" ]]
)
# 核心安装失败不得继续设置 XRAY_BIN 或打印成功。
(
    systemctl() { return 1; }
    # 屏蔽宿主已有核心，使测试只进入安装分支。
    grep() { return 1; }
    curl() { :; }
    unzip() { :; }
    install() { return 1; }
    export TMPDIR="$TMP_DIR"
    XRAY_BIN=""
    if install_xray > "$TMP_DIR/install-failed.out" 2>&1; then
        echo '核心安装失败不得报告成功' >&2; exit 1
    fi
    [[ -z "$XRAY_BIN" ]]
)
MODE=success RESTARTS=0
curl() { echo '不应重复下载核心' >&2; return 1; }
install_xray > "$TMP_DIR/detection.out"
[[ -x "$XRAY_BIN" ]]
(
    systemctl() {
        if [[ "${*: -1}" == xray-relay ]]; then
            printf '{ path=%s ; }\n' "$TMP_DIR/xray"
        else
            printf '{ path=%s ; }\n' "$TMP_DIR/unused-xray"
        fi
    }
    install_xray > "$TMP_DIR/relay-detection.out"
    [[ "$XRAY_BIN" == "$TMP_DIR/xray" ]]
)
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
[[ -n "$PARSED_HOST" && "$PARSED_NODE" != *users* ]]
(
    START_PORT=""
    generate_config "$TMP_DIR/random-first.json"
    CONFIG_FILE="$TMP_DIR/random-first.json"
    generate_config "$TMP_DIR/random-second.json"
    python3 - "$CONFIG_FILE" "$TMP_DIR/random-second.json" <<'PYEOF'
import json, sys
first, second = (json.load(open(path)) for path in sys.argv[1:])
ports = [node["port"] for node in second["inbounds"]]
assert len(ports) == len(set(ports)) == 2
assert all(10000 <= port <= 65535 and port not in (20000, 20002) for port in ports)
assert second["inbounds"][0] == first["inbounds"][0]
PYEOF
)
START_PORT=20000
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
printf '%s\n' '{"reject":true,"user":"diagnostic-user","pass":"diagnostic-password","id":"diagnostic-id","privateKey":"diagnostic-private"}' > "$TMP_DIR/bad.json"
if validate_and_install_config "$TMP_DIR/bad.json" > "$TMP_DIR/error.out" 2>&1; then
    echo '校验失败应返回非零' >&2; exit 1
fi
grep -q 'mock configuration rejected' "$TMP_DIR/error.out"
grep -q '\[隐藏\]' "$TMP_DIR/error.out"
if grep -Eq 'diagnostic-(user|password|id|private)' "$TMP_DIR/error.out"; then
    echo '错误提示不得包含账号、密码、UUID 或私钥' >&2; exit 1
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
cp "$INFO_FILE" "$TMP_DIR/before-derive.links"
if FAIL_DERIVE=1 print_result > "$TMP_DIR/derive-failed.out" 2>&1; then
    echo '派生失败不得报告成功' >&2; exit 1
fi
grep -q '公钥派生失败' "$TMP_DIR/derive-failed.out"
if grep -Fq -- "$PRIVATE_KEY" "$TMP_DIR/derive-failed.out"; then
    echo '派生失败不得泄露私钥参数' >&2; exit 1
fi
cmp "$INFO_FILE" "$TMP_DIR/before-derive.links"
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
# 首次启动失败应停止重启循环、撤销新配置，返回首次部署菜单。
(
    CONFIG_FILE="$TMP_DIR/failed-first.json"
    cp "$TMP_DIR/original.json" "$CONFIG_FILE"
    CONFIG_BACKUP=""
    systemctl() {
        printf '%s\n' "$*" >> "$TMP_DIR/failed-first.calls"
        case "$1" in
            stop|disable) return 0 ;;
            *) return 1 ;;
        esac
    }
    journalctl() { echo 'test startup failure'; }
    if restart_with_rollback > "$TMP_DIR/failed-first.out" 2>&1; then exit 1; fi
    [[ ! -e "$CONFIG_FILE" ]]
    grep -qx 'stop xray-relay' "$TMP_DIR/failed-first.calls"
    grep -qx 'disable xray-relay' "$TMP_DIR/failed-first.calls"
)
# 已部署服务引用的核心被移除时，复用新核心后同步更新自身服务路径。
(
    SERVICE_FILE="$TMP_DIR/replaced-core.service"
    printf '%s\n' '[Service]' 'ExecStart=/missing/xray run -config /missing/config.json' > "$SERVICE_FILE"
    apply_change switch-outbound vless-in-1 socks5-vless-in-1-1 > "$TMP_DIR/replaced-core.out"
    grep -Fqx "ExecStart=\"$XRAY_BIN\" run -config \"$CONFIG_FILE\"" "$SERVICE_FILE"
)
cp "$INFO_FILE" "$TMP_DIR/original.links"
parse_outbound_raw 'socks5://third.example:1082'
NODES=("$PARSED_NODE")
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
if apply_change edit-inbound vless-in-1 > "$TMP_DIR/occupied.out" 2>&1; then
    echo '不得使用占用端口' >&2; exit 1
fi
cmp "$CONFIG_FILE" "$TMP_DIR/before-port.json"
EDIT_PORT=21000
apply_change edit-inbound vless-in-1 > "$TMP_DIR/port.out"
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
# SOCKS5 与 VLESS 共存，新增、切换和修改端口保留入站账号及其他入口。
(
    CONFIG_FILE="$TMP_DIR/socks.json"
    cp "$TMP_DIR/two-vless.json" "$CONFIG_FILE"
    INFO_FILE="$TMP_DIR/socks-links.txt"
    VPS_IP=203.0.113.10 START_PORT=22000
    ss() {
        if [[ "$*" == *-lun* ]]; then
            echo 'UNCONN 0 0 0.0.0.0:22000 0.0.0.0:*'
        fi
    }
    apply_change add-socks > "$TMP_DIR/socks-add.out"
    python3 - "$CONFIG_FILE" "$TMP_DIR/two-vless.json" "$INFO_FILE" <<'PYEOF'
import json, sys
from urllib.parse import urlsplit, unquote
current, original = (json.load(open(path)) for path in sys.argv[1:3])
assert current["inbounds"][:-1] == original["inbounds"]
node = current["inbounds"][-1]
assert node["protocol"] == "socks" and node["port"] == 22001
assert "streamSettings" not in node
assert node["settings"]["auth"] == "password" and node["settings"]["udp"] is True
assert node["settings"]["ip"] == "203.0.113.10"
account = node["settings"]["accounts"][0]
assert account["user"] and len(account["pass"]) >= 24
link = urlsplit(open(sys.argv[3]).read().splitlines()[-1])
assert link.scheme == "socks5" and link.port == 22001
assert unquote(link.username) == account["user"] and unquote(link.password) == account["pass"]
assert current["routing"]["rules"][-1]["outboundTag"] == "socks5-socks-in-1-1"
PYEOF
    cp "$CONFIG_FILE" "$TMP_DIR/socks-before.json"
    apply_change add-outbounds socks-in-1 > "$TMP_DIR/socks-append.out"
    apply_change switch-outbound socks-in-1 socks5-socks-in-1-2 > "$TMP_DIR/socks-switch.out"
    EDIT_PORT=22000
    if apply_change edit-inbound socks-in-1 > "$TMP_DIR/socks-conflict.out" 2>&1; then
        echo 'SOCKS5 不得占用已有 UDP 端口' >&2; exit 1
    fi
    EDIT_PORT=23000
    apply_change edit-inbound socks-in-1 > "$TMP_DIR/socks-port.out"
    python3 - "$CONFIG_FILE" "$TMP_DIR/socks-before.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
assert current["inbounds"][:-1] == original["inbounds"][:-1]
assert current["inbounds"][-1]["settings"] == original["inbounds"][-1]["settings"]
assert current["inbounds"][-1]["port"] == 23000
assert current["routing"]["rules"][-1]["outboundTag"] == "socks5-socks-in-1-2"
PYEOF
    if [[ -n "$XRAY_TEST_BIN" ]]; then
        python3 test_socks_relay.py "$XRAY_TEST_BIN" "$CONFIG_FILE"
    fi
    parse_outbound_raw 'vless://cb6b52d1-b85f-4e90-895a-c477e88a5139@127.0.0.1:443?type=tcp&security=none'
    NODES=("$PARSED_NODE")
    apply_change add-outbounds socks-in-1 > "$TMP_DIR/vless-out-add.out"
    apply_change switch-outbound socks-in-1 socks5-socks-in-1-3 > "$TMP_DIR/vless-out-switch.out"
    show_nodes > "$TMP_DIR/vless-out-list.out"
    grep -q 'VLESS 127.0.0.1:443 \[当前\]' "$TMP_DIR/vless-out-list.out"
    if [[ -n "$XRAY_TEST_BIN" ]]; then
        python3 test_socks_relay.py "$XRAY_TEST_BIN" "$CONFIG_FILE"
    fi
    test_reality_key="$PUBLIC_KEY"
    [[ ${#test_reality_key} == 43 ]] || test_reality_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    for query in \
        "type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.cloudflare.com&pbk=$test_reality_key&sid=0123" \
        'type=ws&security=tls&host=cdn.example&path=%2Frelay' \
        'type=grpc&security=tls&serviceName=relay' \
        'type=httpupgrade&security=tls&path=%2Frelay' \
        'type=xhttp&security=tls&mode=stream-up&path=%2Frelay'; do
        parse_outbound_raw "vless://cb6b52d1-b85f-4e90-895a-c477e88a5139@proxy.example:443?$query"
        NODES=("$PARSED_NODE")
        apply_change edit-outbound socks-in-1 socks5-socks-in-1-3 > "$TMP_DIR/vless-out-edit.out"
    done
    parse_outbound_raw 'socks5://restored.example:1080'
    NODES=("$PARSED_NODE")
    apply_change edit-outbound socks-in-1 socks5-socks-in-1-3 > "$TMP_DIR/socks-out-restored.out"
    python3 - "$CONFIG_FILE" "$TMP_DIR/socks-before.json" <<'PYEOF'
import json, sys
current, original = (json.load(open(path)) for path in sys.argv[1:])
outbound = next(out for out in current["outbounds"] if out["tag"] == "socks5-socks-in-1-3")
assert outbound["protocol"] == "socks" and "streamSettings" not in outbound
assert current["routing"]["rules"][-1]["outboundTag"] == outbound["tag"]
assert current["inbounds"][-1]["settings"] == original["inbounds"][-1]["settings"]
assert current["inbounds"][:-1] == original["inbounds"][:-1]
PYEOF
)
# OpenRC 使用独立服务，覆盖依赖安装、核心复用、启动和失败回滚。
(
    rc-service() {
        printf 'rc-service %s\n' "$*" >> "$CALLS"
        [[ "$1" == xray-relay ]]
        case "$2" in
            restart)
                RESTARTS=$((RESTARTS + 1))
                [[ "$MODE" != failed && ( "$MODE" != rollback || "$RESTARTS" -gt 1 ) ]]
                ;;
            status) [[ "$MODE" != failed ]] ;;
            stop) return 0 ;;
            *) return 1 ;;
        esac
    }
    rc-update() { printf 'rc-update %s\n' "$*" >> "$CALLS"; }
    apk() { printf 'apk %s\n' "$*" >> "$CALLS"; }
    command() {
        if [[ "$*" == '-v systemctl' || "$*" == '-v python3' ]]; then return 1; fi
        builtin command "$@"
    }
    preflight_check
    [[ "$SERVICE_MANAGER" == openrc && "$SERVICE_FILE" == /etc/init.d/xray-relay ]]
    grep -Fxq 'apk add --no-cache curl python3 iproute2 unzip ca-certificates' "$CALLS"
    SERVICE_FILE="$TMP_DIR/openrc-relay"
    SERVICE_LOG="$TMP_DIR/openrc.log"
    CONFIG_FILE="$TMP_DIR/openrc.json"
    cp "$TMP_DIR/socks.json" "$CONFIG_FILE"
    MODE=success RESTARTS=0
    start_service > "$TMP_DIR/openrc-start.out"
    sh -n "$SERVICE_FILE"
    [[ $(stat -c %a "$SERVICE_FILE") == 755 ]]
    grep -Fxq 'rc-update add xray-relay default' "$CALLS"
    grep -Fxq 'command_background=true' "$SERVICE_FILE"
    grep -Fxq 'pidfile="/run/xray-relay.pid"' "$SERVICE_FILE"
    install_xray > "$TMP_DIR/openrc-detection.out"
    [[ "$XRAY_BIN" == "$TMP_DIR/xray" ]]
    CONFIG_BACKUP="$TMP_DIR/openrc-backup.json"
    cp "$CONFIG_FILE" "$CONFIG_BACKUP"
    printf '%s\n' '{"pass":"openrc-test-secret"}' > "$CONFIG_FILE"
    printf '%s\n' 'startup failed: openrc-test-secret' > "$SERVICE_LOG"
    MODE=rollback RESTARTS=0
    if restart_with_rollback > "$TMP_DIR/openrc-rollback.out" 2>&1; then
        echo 'OpenRC 回滚后不得报告部署成功' >&2; exit 1
    fi
    cmp "$CONFIG_FILE" "$CONFIG_BACKUP"
    [[ "$RESTARTS" == 2 ]]
    grep -q 'startup failed:' "$TMP_DIR/openrc-rollback.out"
    if grep -q 'openrc-test-secret' "$TMP_DIR/openrc-rollback.out"; then
        echo 'OpenRC 日志不得泄露凭据' >&2; exit 1
    fi
    CONFIG_BACKUP="" MODE=failed RESTARTS=0
    printf '%s\n' '{"pass":"openrc-test-secret"}' > "$CONFIG_FILE"
    if restart_with_rollback > "$TMP_DIR/openrc-first-failed.out" 2>&1; then
        echo 'OpenRC 首次启动失败不得报告成功' >&2; exit 1
    fi
    [[ ! -f "$CONFIG_FILE" ]]
    grep -Fxq 'rc-service xray-relay stop' "$CALLS"
    grep -Fxq 'rc-update del xray-relay default' "$CALLS"
)
echo 'PASS: Alpine 依赖安装、OpenRC 服务生成、核心复用和启动失败回滚（模拟）'
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
# 首次运行展示菜单，失败后可重试，成功后进入管理菜单。
CONFIG_FILE="$TMP_DIR/first/config.json"
INFO_FILE="$TMP_DIR/first/nodes.txt"
SERVICE_FILE="$TMP_DIR/first/relay.service"
START_PORT=20000
MODE=success RESTARTS=0
preflight_check() { :; }
get_ip() { echo 203.0.113.10; }
ss() { :; }
# 两次部署复用同一核心，第一次模拟校验失败。
install_xray() { XRAY_BIN="$TMP_DIR/xray"; }
DEPLOY_ATTEMPTS=0
generate_config_original=$(declare -f generate_config)
eval "${generate_config_original/generate_config ()/generate_config_original ()}"
generate_config() {
    DEPLOY_ATTEMPTS=$((DEPLOY_ATTEMPTS + 1))
    if [[ "$DEPLOY_ATTEMPTS" == 1 ]]; then
        printf '%s\n' '{"reject":true,"user":"diagnostic-user","pass":"diagnostic-password","id":"diagnostic-id","privateKey":"diagnostic-private"}' > "$1"
    else
        generate_config_original "$@"
    fi
}
(main <<'EOF'
1
socks5://proxy.example:1080

1
socks5://proxy.example:1080

0
EOF
) > "$TMP_DIR/first.out" 2>&1
grep -q '1) 创建 VLESS 入站' "$TMP_DIR/first.out"
grep -q 'mock configuration rejected' "$TMP_DIR/first.out"
grep -q '部署失败。' "$TMP_DIR/first.out"
grep -q '配置校验通过。' "$TMP_DIR/first.out"
grep -q '3) 为入站添加出站' "$TMP_DIR/first.out"
if grep -Eq 'diagnostic-(user|password|id|private)' "$TMP_DIR/first.out"; then
    echo '首次部署错误提示不得泄露凭据' >&2; exit 1
fi
[[ -f "$CONFIG_FILE" ]]
if [[ -n "$XRAY_TEST_BIN" ]]; then
    echo 'PASS: 配置通过真实 Xray 核心校验'
fi
echo 'PASS: 首次部署菜单、失败重试、错误详情隐藏凭据、多出站编辑和失败回滚'
