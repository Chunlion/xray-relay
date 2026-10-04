#!/usr/bin/env python3
"""直接测试主脚本中嵌入的 SOCKS5 / VLESS 解析器。"""
import os
import json
from pathlib import Path
import subprocess
import sys

script = Path(__file__).with_name("xray_deploy.sh").read_text()
parser = script.split("out=$(INPUT=\"$raw\" python3 - <<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
valid = [
    ("socks5://user:pass@proxy.example:1080", ["proxy.example", "1080", "user", "pass"]),
    ("socks5://proxy.example:1080", ["proxy.example", "1080", "", ""]),
    ("socks5://u:p%3A%40%2F%25@host:1234/", ["host", "1234", "u", "p:@/%"]),
    ("socks5://u:p@[2001:db8::1]:1080#label", ["2001:db8::1", "1080", "u", "p"]),
    ("[2001:db8::1]:1080:u:p", ["2001:db8::1", "1080", "u", "p"]),
    ("host:1080:u:p", ["host", "1080", "u", "p"]),
]
invalid = [
    "", "garbage", "https://host:1080", "socks5://u@host:1080",
    "socks5://:p@host:1080", "socks5://u:@host:1080", "socks5://u:p@host",
    "socks5://host:0", "socks5://host:65536", "socks5://host:abc",
    "socks5://u:p%0A@host:1080", "socks5://u:p%09@host:1080",
    "socks5://u:p%00@host:1080", "socks5://u:p%oops@host:1080",
    "socks5://host:1080/path", "socks5://host:1080?ignored=1",
    "socks5://u:p@bad host:1080", "host:1080::p", "host:1080:u:p:extra",
    "socks5://host:1080\x1fextra", "socks5://u:" + "p" * 256 + "@host:1080",
]
for value, expected in valid:
    result = subprocess.run([sys.executable, "-c", parser], env={**os.environ, "INPUT": value},
                            capture_output=True, text=True, check=True).stdout.rstrip("\n")
    assert result.startswith("OK\t"), "有效链接未被接受"
    host, port, payload = result[3:].split("\x1f")
    server = json.loads(payload)["settings"]["servers"][0]
    account = server.get("users", [{}])[0]
    assert [host, port, account.get("user", ""), account.get("pass", "")] == expected, "解析结果不正确"
for value in invalid:
    result = subprocess.run([sys.executable, "-c", parser], env={**os.environ, "INPUT": value},
                            capture_output=True, text=True, check=True).stdout
    assert result.startswith("ERR\t"), "无效链接未被拒绝"
print(f"PASS: SOCKS5 解析 {len(valid) + len(invalid)} 个用例")

base = "vless://cb6b52d1-b85f-4e90-895a-c477e88a5139@[2001:db8::1]:443?"
cases = [
    ("type=tcp&security=reality&pbk=" + "A" * 43 + "&sid=0123&flow=xtls-rprx-vision&sni=example.com", "tcp", "reality"),
    ("type=raw&security=tls&sni=example.com&alpn=h2%2Chttp%2F1.1", "tcp", "tls"),
    ("type=ws&security=tls&host=cdn.example&path=%2Frelay", "ws", "tls"),
    ("type=grpc&security=tls&serviceName=relay&mode=multi", "grpc", "tls"),
    ("type=httpupgrade&security=tls&path=%2Frelay", "httpupgrade", "tls"),
    ("type=xhttp&security=tls&path=%2Frelay&mode=stream-up", "xhttp", "tls"),
    ("type=tcp&security=none", "tcp", "none"),
]
for query, network, security in cases:
    result = subprocess.run([sys.executable, "-c", parser], env={**os.environ, "INPUT": base + query},
                            capture_output=True, text=True, check=True).stdout.rstrip("\n")
    assert result.startswith("OK\t"), "有效 VLESS 链接未被接受"
    host, port, payload = result[3:].split("\x1f")
    node = json.loads(payload)
    assert (host, port) == ("2001:db8::1", "443")
    assert node["protocol"] == "vless"
    assert node["streamSettings"]["network"] == network and node["streamSettings"]["security"] == security
    stream = node["streamSettings"]
    if security == "reality":
        assert stream["realitySettings"]["publicKey"] == "A" * 43
        assert stream["realitySettings"]["shortId"] == "0123"
    if network == "ws":
        assert stream["wsSettings"] == {"path": "/relay", "headers": {"Host": "cdn.example"}}
    if network == "grpc":
        assert stream["grpcSettings"]["serviceName"] == "relay" and stream["grpcSettings"]["multiMode"]
    if security == "tls":
        assert stream["tlsSettings"]["allowInsecure"] is False
bad = ["type=kcp", "security=xtls", "encryption=unsupported", "security=reality", "path=%00",
       "type=tcp&type=ws", "extra=unsupported", "headerType=http", "flow=xtls-rprx-vision",
       "type=grpc&mode=invalid", "type=xhttp&mode=invalid", "security=tls&allowInsecure=yes",
       "security=reality&pbk=" + "A" * 43 + "&sid=123"]
for query in bad:
    result = subprocess.run([sys.executable, "-c", parser], env={**os.environ, "INPUT": base + query},
                            capture_output=True, text=True, check=True).stdout
    assert result.startswith("ERR\t"), "无效 VLESS 链接未被拒绝"
print(f"PASS: VLESS 解析 {len(cases) + len(bad)} 个用例")
