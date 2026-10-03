# xray-relay

VLESS + REALITY 入口 → SOCKS5 出站。逐行输入多个 SOCKS5 链接，每个出口生成一个独立端口的 VLESS 节点。

## 使用

在使用 systemd 的 Linux VPS 上，以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/Chunlion/xray-relay/main/xray_deploy.sh -o xray_deploy.sh
bash xray_deploy.sh
```

粘贴 SOCKS5 链接，全部输入后按空回车结束。输入隐藏，支持：

```text
socks5://user:password@host:1080
socks5://host:1080
socks5://user:password@[2001:db8::1]:1080
host:1080:user:password
```

用户名或密码中的特殊字符须进行 URL 编码，例如 `@` 写成 `%40`、`:` 写成 `%3A`。UDP 转发需要 SOCKS5 服务支持 UDP ASSOCIATE。

脚本自动生成 UUID、REALITY 密钥和节点链接，从 `20000` 开始分配空闲 TCP 端口。链接保存至 `/root/xray_nodes_info.txt`。活动的 UFW / firewalld 会自动放行；云安全组及自定义 nftables / iptables 需自行放行对应 TCP 端口。

可修改起始端口或 REALITY 目标：

```bash
START_PORT=30000 REALITY_SERVER_NAME=www.apple.com bash xray_deploy.sh
```

## 与已有 Xray 共存

自动检测 233boy 的 `/etc/xray/bin/xray`、官方安装的 `/usr/local/bin/xray` 及 `xray.service` 使用的核心，找到后直接复用。未找到时，仅下载 Xray 核心至 `/usr/local/lib/xray-relay/xray`，自动下载支持 x86_64 / ARM64。

使用独立的 `xray-relay.service` 和 `/usr/local/etc/xray-relay/config.json`，不修改或重启已有 `xray.service`，不占用已监听的端口。原脚本更新或卸载共享核心后，中转服务也需要该核心继续存在。

再次运行会重新生成本工具的全部中转节点，替换本工具配置并备份原配置；校验失败保留原配置，启动失败尝试恢复本次备份。旧节点链接随配置替换失效。

```bash
systemctl status xray-relay
systemctl restart xray-relay
journalctl -u xray-relay -n 30
```

## 检查

```bash
bash run_all_tests.sh
```

流程参考 [233boy/Xray](https://github.com/233boy/Xray)，配置使用 [Xray SOCKS 出站](https://xtls.github.io/en/config/outbounds/socks.html)。
