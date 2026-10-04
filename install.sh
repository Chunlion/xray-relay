#!/bin/sh
set -eu

install_relay() {
    if [ "$(id -u)" != 0 ]; then
        echo "需要以 root 运行。" >&2
        return 1
    fi
    if ! command -v bash >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache bash ca-certificates
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bash ca-certificates
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash ca-certificates
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash ca-certificates
        else
            echo "请先安装 Bash。" >&2
            return 1
        fi
    fi

    umask 022
    mkdir -p /usr/local/bin
    relay_tmp=$(mktemp /usr/local/bin/.xrelay.XXXXXX)
    trap 'rm -f -- "$relay_tmp"' EXIT
    relay_url=https://raw.githubusercontent.com/Chunlion/xray-relay/main/xray_deploy.sh
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time 120 "$relay_url" -o "$relay_tmp"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$relay_tmp" "$relay_url"
    else
        echo "请先安装 curl 或 wget。" >&2
        return 1
    fi
    if [ ! -s "$relay_tmp" ] || ! bash -n "$relay_tmp"; then
        echo "下载的脚本无效，原管理命令未修改。" >&2
        return 1
    fi
    chmod 755 "$relay_tmp"
    mv -f "$relay_tmp" /usr/local/bin/xrelay
    trap - EXIT
    echo "已安装管理命令：xrelay"

    if [ -t 0 ]; then
        exec /usr/local/bin/xrelay
    elif ( : </dev/tty ) 2>/dev/null; then
        exec /usr/local/bin/xrelay </dev/tty
    fi
}

install_relay "$@"
