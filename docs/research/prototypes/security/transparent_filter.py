#!/usr/bin/env python3
import select
import socket
import struct
import sys
import threading

SOL_IP = 0
SO_ORIGINAL_DST = 80
ALLOW = {"example.com", "www.example.com"}


def log(msg):
    print(msg, flush=True)


def original_dst(conn):
    data = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, raw_ip = struct.unpack_from("!HH4s", data)
    return socket.inet_ntoa(raw_ip), port


def tls_sni(buf):
    try:
        if len(buf) < 5 or buf[0] != 0x16:
            return None
        pos = 5
        if buf[pos] != 0x01:
            return None
        pos += 4 + 2 + 32
        sid_len = buf[pos]
        pos += 1 + sid_len
        cs_len = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2 + cs_len
        comp_len = buf[pos]
        pos += 1 + comp_len
        ext_len = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_len
        while pos + 4 <= end:
            etype = int.from_bytes(buf[pos:pos + 2], "big")
            elen = int.from_bytes(buf[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0:
                p = pos + 2
                name_type = buf[p]
                name_len = int.from_bytes(buf[p + 1:p + 3], "big")
                if name_type == 0:
                    return buf[p + 3:p + 3 + name_len].decode("ascii", "ignore").lower()
            pos += elen
    except Exception:
        return None
    return None


def http_host(buf):
    try:
        text = buf.decode("iso-8859-1", "ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip().split(":", 1)[0].lower()
    except Exception:
        pass
    return None


def relay(a, b):
    sockets = [a, b]
    while True:
        r, _, _ = select.select(sockets, [], [], 30)
        if not r:
            break
        for s in r:
            try:
                data = s.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                (b if s is a else a).sendall(data)
            except OSError:
                return


def handle(conn, addr):
    try:
        dst_ip, dst_port = original_dst(conn)
        first = conn.recv(8192, socket.MSG_PEEK)
        host = tls_sni(first) if dst_port == 443 else http_host(first)
        decision = "ALLOW" if host in ALLOW else "BLOCK"
        log(f"TCP {decision} client={addr[0]} original={dst_ip}:{dst_port} host={host!r}")
        if decision == "BLOCK":
            conn.close()
            return
        upstream = socket.create_connection((dst_ip, dst_port), timeout=10)
        relay(conn, upstream)
    except Exception as e:
        log(f"TCP ERROR {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 15001))
    s.listen(128)
    log("transparent TCP filter listening on :15001")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
