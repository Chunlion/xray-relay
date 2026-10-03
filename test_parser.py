#!/usr/bin/env python3
"""直接测试主脚本中嵌入的 SOCKS5 解析器。"""
import os
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
    assert result[3:].split("\x1f") == expected, "解析结果不正确"
for value in invalid:
    result = subprocess.run([sys.executable, "-c", parser], env={**os.environ, "INPUT": value},
                            capture_output=True, text=True, check=True).stdout
    assert result.startswith("ERR\t"), "无效链接未被拒绝"
print(f"PASS: SOCKS5 解析 {len(valid) + len(invalid)} 个用例")
