# RTSP Digest Auth Bruteforcer


A Python-based tool to brute-force RTSP endpoints protected with **Digest Authentication**. This script targets RTSP URLs by trying combinations of usernames and passwords, either from wordlists or default values, to identify valid credentials.

> **⚠️ Legal Warning:** This tool is intended for **authorized testing and educational purposes only**. Do not use it against systems without explicit permission.

---

## 🔧 Features

- Supports **Digest Auth** for RTSP `DESCRIBE` requests.
- Accepts custom **username** and **password** wordlists.
- Includes a fallback to common default credentials.
- Prints status codes and reports valid credentials upon success.

---

## 🧪 Usage

```bash
python rtsp_bruteforce.py <IP> <path> [options]
```

### Example

```bash
python rtsp_bruteforce.py 192.168.1.10 live.sdp -U users.txt -P passwords.txt
```

### Parameters

| Argument           | Description                                       |
|--------------------|---------------------------------------------------|
| `ip`               | Target IP address                                 |
| `path`             | RTSP path (e.g., `live.sdp`)                      |
| `-p`, `--port`     | RTSP port (default: `554`)                        |
| `-U`, `--userlist` | Path to username wordlist (optional)              |
| `-P`, `--passlist` | Path to password wordlist (optional)              |

---

## 📦 Requirements

- Python 3.x
- `requests`
- `urllib3`

Install dependencies using:

```bash
pip install requests urllib3
```

---

## 🧠 How It Works

1. Sends a `DESCRIBE` request to the target RTSP URL.
2. Extracts `WWW-Authenticate` digest parameters like `realm` and `nonce`.
3. Iterates over all username/password combinations to compute digest responses.
4. Sends authenticated requests and checks for `200 OK`.

---

## 🛑 Disclaimer

This tool is provided **as is** for ethical hacking and security research. Unauthorized access to systems is **illegal**. Always obtain proper authorization before conducting any tests.

---
```
