# xray-relay

VLESS + REALITY 或 SOCKS5 入站 → SOCKS5 或 VLESS 出站。一个入口可混合绑定多个出站，手动选择当前出口。客户端需使用对应代理协议接入，暂不提供 Realm 式任意 TCP/UDP 端口透传。

## 使用

支持使用 systemd 的 Linux VPS，以及使用 OpenRC 的 Alpine。以 root 执行，首次安装或更新只需一条命令，缺少 Bash 时会自动安装：

```sh
wget -qO- https://raw.githubusercontent.com/Chunlion/xray-relay/main/install.sh | sh
```

以后输入以下命令打开菜单：

```sh
xrelay
```

已有 curl 的系统也可用 `curl -fsSL https://raw.githubusercontent.com/Chunlion/xray-relay/main/install.sh | sh` 安装。

首次运行选择 `1` 创建 VLESS，或选择 `2` 创建 SOCKS5 入站。逐行粘贴 SOCKS5 或 VLESS 出站链接，全部输入后按空回车结束；第一条作为当前出口。输入隐藏，支持：

```text
socks5://user:password@host:1080
socks5://host:1080
socks5://user:password@[2001:db8::1]:1080
host:1080:user:password
vless://UUID@host:443?encryption=none&security=tls&type=tcp&sni=example.com
```

用户名或密码中的特殊字符须进行 URL 编码，例如 `@` 写成 `%40`、`:` 写成 `%3A`。UDP 转发需要 SOCKS5 服务支持 UDP ASSOCIATE。

VLESS 出站支持 TCP/RAW、WS、gRPC、HTTPUpgrade 和基础 XHTTP，安全类型支持 none、TLS、REALITY，可导入本脚本生成的 VLESS 链接。目前仅支持 `encryption=none`，不支持 TCP HTTP 伪装及 XHTTP `extra` 等扩展参数；无法解析的参数会提示错误。传输方式也需要已有 Xray 核心支持。

脚本自动生成 VLESS 的 UUID / REALITY 密钥，或 SOCKS5 的登录账号和密码。新建 VLESS 默认从 `10000–65535` 随机选择空闲端口，SOCKS5 从 `20000` 开始分配；已有节点端口保持不变。节点链接保存至 `/root/xray_nodes_info.txt`。活动的 UFW / firewalld 会自动放行；云安全组及自定义 nftables / iptables 需自行放行入站 TCP 端口，SOCKS5 入站还需放行同端口 UDP。

SOCKS5 入站启用账号密码认证，生成 `socks5://账号:密码@地址:端口` 链接。SOCKS5 传输不加密。

指定 `START_PORT` 时改为从该端口顺序寻找空闲端口；也可修改 REALITY 目标：

```bash
START_PORT=30000 REALITY_SERVER_NAME=www.apple.com xrelay
```

## 与已有 Xray 共存

优先复用已部署的 `xray-relay` 所用核心，再检测 233boy 的 `/etc/xray/bin/xray`、官方安装的 `/usr/local/bin/xray`、`xray.service` 使用的核心及 Alpine 的 `/usr/bin/xray`。未找到时，仅下载 Xray 核心至 `/usr/local/lib/xray-relay/xray`，自动下载支持 x86_64 / ARM64。更换核心路径后会同步更新中转服务。

使用独立的 `xray-relay` 服务和 `/usr/local/etc/xray-relay/config.json`，不修改或重启已有 Xray 服务，不占用已监听的端口。systemd 服务文件为 `/etc/systemd/system/xray-relay.service`，Alpine OpenRC 为 `/etc/init.d/xray-relay`，均设置开机启动。原脚本更新或卸载共享核心后，中转服务也需要该核心继续存在。

部署完成后进入管理菜单；再次执行 `xrelay` 也会进入菜单，保留已有节点。选择 `2` 新增 VLESS，选择 `9` 新增 SOCKS5 入站。两种入口都可追加出站、切换当前出口、编辑或删除出站，以及修改入口名称和端口。编辑出站时可在 SOCKS5 与 VLESS 之间更换协议。

菜单 `6` 删除整条节点：选择节点编号，一并删除它的专用出站和节点链接；删除最后一条节点会停止中转服务。菜单 `10` 仅删除一个出站：从带节点名称和端口的列表中选编号即可。输入 `0` 返回。

新增出站保留原入口的账号、UUID、密钥、端口及当前出口。备用出站需从菜单手动切换；删除当前出口会选择第一个剩余出站。唯一出站需随整条节点一起删除。修改端口后需重新导入节点链接。

上一版的一对一配置仍可管理，编辑时只转换选中的 VLESS。每次修改先校验并备份原配置，启动失败尝试恢复本次备份。首次启动失败会停止并禁用中转服务、撤销本次配置，返回部署菜单。校验失败会显示核心路径、退出码和隐藏凭据后的具体错误。

```bash
systemctl status xray-relay
systemctl restart xray-relay
journalctl -u xray-relay -n 30
```

Alpine 使用以下命令，日志保留本次启动后的内容：

```sh
rc-service xray-relay status
rc-service xray-relay restart
tail -n 30 /var/log/xray-relay.log
```

## 检查

```bash
bash run_all_tests.sh
```

指定 `XRAY_TEST_BIN=/完整路径/xray` 可额外使用真实核心校验配置，并在回环地址测试 SOCKS5 入站到 SOCKS5 / VLESS 出站的 TCP/UDP 两跳转发与认证。

流程参考 [233boy/Xray](https://github.com/233boy/Xray)，配置参考 [Xray SOCKS 出站](https://xtls.github.io/en/config/outbounds/socks.html)和 [VLESS 出站](https://xtls.github.io/en/config/outbounds/vless.html)。
