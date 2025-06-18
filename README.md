# RTSP Digest Brute-Forcer (Socket Version)

A lightweight Python script that brute-forces RTSP endpoints using **Digest Authentication**, implemented entirely with raw sockets for greater control and transparency over the request process.

> ⚠️ **Legal Notice:** This tool is for **authorized testing and educational purposes only**. Do not use it without explicit permission from the system owner.

---

## 🚀 Features

- Fully socket-based RTSP communication — no third-party HTTP libraries.
- Parses and handles Digest Authentication challenges (`WWW-Authenticate` header).
- Accepts custom username and password wordlists.
- Supports **throttling** between attempts to avoid detection or rate-limiting.
- Useful for testing IP cameras, NVRs, and other embedded RTSP devices.

---

## 📦 Requirements

- Python 3.x  
No external libraries required — works with standard Python libraries only.

---

## 🔧 Usage

```bash
python rtsp_bruteforce.py <IP> <path> [options]
```

### Example

```bash
python rtsp_bruteforce.py 192.168.0.100 Streaming/Channels/1 -U users.txt -P passwords.txt -t 0.5
```

### Parameters

| Argument             | Description                                              |
|----------------------|----------------------------------------------------------|
| `ip`                 | Target IP address                                        |
| `path`               | RTSP resource path (e.g., `Streaming/Channels/1`)        |
| `-p`, `--port`       | RTSP port (default: `554`)                               |
| `-U`, `--userlist`   | Path to a username wordlist (optional, recommended*)                   |
| `-P`, `--passlist`   | Path to a password wordlist (optional, recommended*)                   |
| `-t`, `--throttle`   | Delay (in seconds) between login attempts (default: `0`) |

*If no username/password list is selected, it will try the most simple user/pass combinations (e.g., admin:admin)

---

## 🔍 How It Works

1. Sends a socket-based `OPTIONS` request to retrieve Digest Authentication parameters (`realm`, `nonce`).
2. Uses `MD5` to compute valid digest responses for each username:password combo.
3. Sends a `DESCRIBE` request using computed digest headers.
4. Reports credentials if `200 OK` is received from the target.

---

## 🧠 Default Credentials

If no wordlists are provided, the script falls back to:

- **Usernames:** `admin`, `user`, `root`
- **Passwords:** `admin`, `1234`, `password`, `toor`

---

## ✅ Example Output

```
[*] Connecting to rtsp://192.168.0.100:554/Streaming/Channels/1
[*] Starting brute-force...
[*] Tried admin:admin - Response Length: 452
[*] Tried admin:1234 - Response Length: 689
[+] SUCCESS: admin:1234
```

---

## ⚠️ Disclaimer

This tool must only be used in environments where you have **explicit authorization**. Misuse can be illegal and unethical.

---
