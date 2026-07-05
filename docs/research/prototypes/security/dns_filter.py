#!/usr/bin/env python3
import socket
import struct

ALLOW = {"example.com", "www.example.com"}


def parse_qname(packet):
    labels = []
    i = 12
    while i < len(packet):
        ln = packet[i]
        if ln == 0:
            return ".".join(labels).lower(), i + 1
        labels.append(packet[i + 1:i + 1 + ln].decode("ascii", "ignore"))
        i += 1 + ln
    return "", i


def response(query, allowed, ip="93.184.216.34"):
    tid = query[:2]
    flags = b"\x81\x80" if allowed else b"\x81\x83"
    qdcount = query[4:6]
    header = tid + flags + qdcount + (b"\x00\x01" if allowed else b"\x00\x00") + b"\x00\x00\x00\x00"
    qname, qend = parse_qname(query)
    question = query[12:qend + 4]
    if not allowed:
        return header + question
    answer = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack("!I", 60) + b"\x00\x04" + socket.inet_aton(ip)
    return header + question + answer


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 15053))
    print("DNS filter listening on :15053", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        qname, _ = parse_qname(data)
        allowed = qname in ALLOW
        print(f"DNS {'ALLOW' if allowed else 'BLOCK'} client={addr[0]} qname={qname!r}", flush=True)
        sock.sendto(response(data, allowed), addr)


if __name__ == "__main__":
    main()
