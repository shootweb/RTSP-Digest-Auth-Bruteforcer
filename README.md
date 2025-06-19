# RTSP Digest Brute-Forcer (Advanced Version)

A powerful RTSP Digest Authentication brute-force tool built using raw sockets for stealthy probing. This version includes adaptive retry handling, request throttling, randomized delays, and cooldowns to help bypass rate-limiting or temporary bans from RTSP servers.

> ⚠️ **Legal Warning:** Use this tool **only on systems you are authorized to test**. Unauthorized use is illegal and unethical.

---

## 🔧 Features

- ✅ Raw socket-based RTSP communication
- 🔄 Automatic retry logic for dropped or empty responses
- 🕒 Custom **throttle delay** and **random jitter** between attempts
- 🛑 **Cooldown** period after configurable number of attempts
- 📂 Accepts custom username and password wordlists

---

## 🧪 Usage

```bash
python rtsp_bruteforce.py <IP> <path> [options]
```

### Example

```bash
python rtsp_bruteforce.py 192.168.0.150 Streaming/Channels/1 -U users.txt -P passwords.txt -t 0.2 --random 0.1 --cooldown-after 4 --cooldown-duration 60
```

---

## 🧾 Arguments

| Argument                | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `ip`                    | Target IP address                                                           |
| `path`                  | RTSP path (e.g., `Streaming/Channels/1`)                                    |
| `-p`, `--port`          | RTSP port (default: `554`)                                                  |
| `-U`, `--userlist`      | Path to username wordlist                                                   |
| `-P`, `--passlist`      | Path to password wordlist                                                   |
| `-t`, `--throttle`      | Static delay between attempts in seconds (default: `0.0`)                   |
| `--random`              | Adds random delay of 0 to N seconds (e.g., `--random 0.2`)                  |
| `--cooldown-after`      | Number of attempts before cooldown is triggered (e.g., `4`)                |
| `--cooldown-duration`   | Cooldown duration in seconds (default: `60`)                                |

*If no username/password list is selected, it will try the most simple user/pass combinations (e.g., admin:admin)

---

## 🔍 Default Wordlists

If not specified, the script uses built-in defaults:

- **Usernames:** `admin`, `user`, `root`
- **Passwords:** `admin`, `1234`, `password`, `P@ssw0rd`

---

## 🧠 How It Works

1. Sends an `OPTIONS` RTSP request to trigger the `WWW-Authenticate: Digest` challenge.
2. Parses the `realm` and `nonce` values from the challenge.
3. Brute-forces `username:password` pairs by computing valid digest responses.
4. Implements:
   - **Retry logic** for empty responses
   - **Increasing delay** on repeated failure
   - **Cooldown** after N attempts
   - **Random delay** for anti-detection purposes
5. Detects success when server responds with `200 OK`.

---

## ✅ Sample Output

```
[*] Connecting to rtsp://192.168.0.150:554/Streaming/Channels/1
[*] Starting brute-force...
[*] Tried admin:1234 - Response Length: 421
[!] Empty response, retrying admin:1234 once...
[!] Still empty. Increasing delay to 0.1s (Attempt 2)
[*] Tried admin:1234 - Response Length: 782
[+] SUCCESS: admin:1234
```

---

## ⚠️ Disclaimer

This tool is intended for **ethical hacking**, **red teaming**, and **research** on systems you **own or are permitted to test**. Misuse may result in legal consequences.

---
