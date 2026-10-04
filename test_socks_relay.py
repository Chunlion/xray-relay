#!/usr/bin/env python3
"""用真实 Xray 核心验证 SOCKS5 入站到 SOCKS5 / VLESS 出站的两跳转发。"""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def receive(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        assert chunk, "连接提前关闭"
        data += chunk
    return data


def authenticate(port, account, reject=False):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    sock.sendall(b"\x05\x01\x02")
    assert receive(sock, 2) == b"\x05\x02", "未要求账号密码认证"
    user = account["user"].encode()
    password = ("wrong-password" if reject else account["pass"]).encode()
    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
    result = receive(sock, 2)
    assert (result[1] != 0) if reject else (result == b"\x01\x00"), "认证结果错误"
    return sock


def request(sock, command, port):
    sock.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", port))
    assert receive(sock, 4) == b"\x05\x00\x00\x01", "SOCKS5 请求失败"
    return socket.inet_ntoa(receive(sock, 4)), struct.unpack("!H", receive(sock, 2))[0]


source = json.loads(Path(sys.argv[2]).read_text())
inbound = next(node for node in source["inbounds"] if node["protocol"] == "socks")
rule = next(rule for rule in source["routing"]["rules"] if rule["inboundTag"] == [inbound["tag"]])
outbound = next(node for node in source["outbounds"] if node["tag"] == rule["outboundTag"])
account = inbound["settings"]["accounts"][0]
processes, sockets = [], []
with tempfile.TemporaryDirectory(prefix="xray-socks-test-") as directory:
    try:
        reservations = []
        for _ in range(2):
            tcp = socket.socket()
            tcp.bind(("127.0.0.1", 0))
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.extend([tcp, udp])
            udp.bind(tcp.getsockname())
            reservations.append((tcp, udp))
        relay_port, upstream_port = (pair[0].getsockname()[1] for pair in reservations)
        upstream_account = {"user": "test-upstream", "pass": "test-upstream-password"}
        inbound.update(listen="127.0.0.1", port=relay_port)
        inbound["settings"]["ip"] = "127.0.0.1"
        server = outbound["settings"]["vnext" if outbound["protocol"] == "vless" else "servers"][0]
        server.update(address="127.0.0.1", port=upstream_port)
        if outbound["protocol"] == "socks":
            server["users"] = [upstream_account]
        relay = {"log": {"loglevel": "none"}, "inbounds": [inbound], "outbounds": [outbound],
                 "routing": {"rules": [rule]}}
        upstream = {"log": {"loglevel": "none"}, "inbounds": [{
            "listen": "127.0.0.1", "port": upstream_port, "protocol": "socks",
            "settings": {"auth": "password", "accounts": [upstream_account], "udp": True,
                         "ip": "127.0.0.1"}}], "outbounds": [{"protocol": "freedom"}]}
        if outbound["protocol"] == "vless":
            upstream["inbounds"][0].update(protocol="vless", settings={
                "clients": [{"id": server["users"][0]["id"]}], "decryption": "none"})
        for pair in reservations:
            for sock in pair:
                sock.close()
        for name, config, port in (("upstream", upstream, upstream_port), ("relay", relay, relay_port)):
            path = Path(directory, name + ".json")
            path.write_text(json.dumps(config))
            process = subprocess.Popen([sys.argv[1], "run", "-config", str(path)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            for _ in range(60):
                assert process.poll() is None, "Xray 测试进程启动失败"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Xray 监听超时")
        with socket.create_connection(("127.0.0.1", relay_port), timeout=3) as client:
            client.sendall(b"\x05\x01\x00")
            assert receive(client, 2) == b"\x05\xff", "匿名访问未被拒绝"
        with authenticate(relay_port, account, reject=True):
            pass

        tcp_echo = socket.socket()
        sockets.append(tcp_echo)
        tcp_echo.bind(("127.0.0.1", 0))
        tcp_echo.listen()
        tcp_echo.settimeout(4)

        def echo_tcp():
            with tcp_echo.accept()[0] as connection:
                connection.settimeout(3)
                connection.sendall(receive(connection, 9))

        thread = threading.Thread(target=echo_tcp, daemon=True)
        thread.start()
        with authenticate(relay_port, account) as client:
            request(client, 1, tcp_echo.getsockname()[1])
            client.sendall(b"tcp-relay")
            assert receive(client, 9) == b"tcp-relay", "TCP 两跳转发失败"
        thread.join(timeout=4)

        udp_echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockets.append(udp_echo)
        udp_echo.bind(("127.0.0.1", 0))
        udp_echo.settimeout(4)

        def echo_udp():
            data, peer = udp_echo.recvfrom(2048)
            udp_echo.sendto(data, peer)

        thread = threading.Thread(target=echo_udp, daemon=True)
        thread.start()
        with authenticate(relay_port, account) as control:
            endpoint = request(control, 3, 0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                packet = (b"\0\0\0\1" + socket.inet_aton("127.0.0.1")
                          + struct.pack("!H", udp_echo.getsockname()[1]) + b"udp-relay")
                client.sendto(packet, endpoint)
                data = client.recv(2048)
                assert data[:4] == b"\0\0\0\1" and data[10:] == b"udp-relay", "UDP 两跳转发失败"
        thread.join(timeout=4)
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for sock in sockets:
            sock.close()
print(f"PASS: 真实 Xray SOCKS5 → {outbound['protocol'].upper()} 认证及两跳 TCP/UDP 转发")
