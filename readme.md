# HackMind

> The localhost hacker AI. Free. Offline. No API keys.

HackMind is a single-file, DigAI-style hacking assistant that runs on your own
machine and opens in your browser at `http://127.0.0.1:8000`. Paste a URL or an
`@username` and it does the boring 90% of "hacking" for you.

No OpenAI key. No Claude key. No monthly bill. No signup.

---

## Features

| Command | What it does |
|---|---|
| `scan <url>` | Full recon: status, headers, tech stack, forms, admin links, robots/sitemap, exposed `.env` / `.git` |
| `admin <url>` | Checks 30+ common admin / login / panel / API paths |
| `ports <host>` | TCP port scan of 31 common ports + banner grabbing |
| `dns <domain>` | A, AAAA, MX, NS, TXT, CNAME, SOA records |
| `subs <domain>` | Subdomain enumeration via certificate transparency (crt.sh) |
| `ssl <host>` | TLS certificate details: issuer, validity, SANs |
| `ip <host>` | Geolocation, ISP, ASN, reverse DNS |
| `insta <username>` | Instagram profile intel: followers, posts, bio, private/verified |
| `crack <url> [user]` | Brute-forces a login form using a built-in wordlist |
| `help` / `status` | Command list / brain + environment status |

Anything that isn't a command goes to the **AI brain**. If Ollama is installed
you get a real local LLM; if not, HackMind falls back to a built-in rule engine
so it always works out of the box.

---

## Requirements

- Python 3.8+
- That's it. Optional: [Ollama](https://ollama.com) for the real AI brain.

---

## Installation

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install --upgrade pip
pip install -r requirements.txt
python3 main.py