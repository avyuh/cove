#!/usr/bin/env python3
import socket
import ssl
import threading


def log(msg):
    print(msg, flush=True)


def handle(raw, addr, ctx):
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = tls.recv(8192)
            if not chunk:
                break
            data += chunk
        text = data.decode("iso-8859-1", "replace")
        lines = text.split("\r\n")
        request_line = lines[0] if lines else ""
        host = next((x for x in lines if x.lower().startswith("host:")), "")
        auth = next((x for x in lines if x.lower().startswith("authorization:")), "")
        api_key = next((x for x in lines if x.lower().startswith("x-api-key:")), "")
        log(f"MITM_HTTP client={addr[0]} request={request_line!r} {host!r} auth_present={bool(auth)} x_api_key_present={bool(api_key)}")
        body = b'{"type":"error","error":{"type":"authentication_error","message":"MITM test response after TLS accept"}}\n'
        tls.sendall(
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"content-type: application/json\r\n"
            b"connection: close\r\n"
            + f"content-length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
    except ssl.SSLError as e:
        log(f"MITM_TLS_FAIL client={addr[0]} error={e}")
    except Exception as e:
        log(f"MITM_ERROR client={addr[0]} error={e}")
    finally:
        try:
            raw.close()
        except Exception:
            pass


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/cove-mitm-api-anthropic.crt", "/tmp/cove-mitm-api-anthropic.key")
    ctx.set_alpn_protocols(["http/1.1"])

    def sni_cb(sock, server_name, _ctx):
        log(f"MITM_TLS_CLIENT_HELLO sni={server_name!r}")

    ctx.set_servername_callback(sni_cb)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 15002))
    s.listen(128)
    log("Anthropic transparent MITM listening on :15002")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, ctx), daemon=True).start()


if __name__ == "__main__":
    main()
