# NetTactix – iOS recon & offensive-security toolkit  ·  by OathSec

A native SwiftUI app for network reconnaissance, OSINT and authorised offensive security, built to be sideloaded onto your own iPhone with Xcode. (Internal Xcode target/scheme is still `ReconKit`.)

> **Use only on systems you own or are explicitly authorised to test.** Active tools send traffic to the target. The app makes you acknowledge this on first launch.

## Install on your iPhone

Requirements: a Mac with Xcode 16+, an iPhone on iOS 16+, a free Apple ID is enough (free profiles expire after 7 days; re-run from Xcode).

```bash
git clone https://github.com/OwenCosta/IOSReconAPP.git && cd IOSReconAPP
git checkout claude/elegant-pascal-v17aky
./setup.sh            # installs XcodeGen via Homebrew, generates ReconKit.xcodeproj, opens it
```

In Xcode:
1. Select the **ReconKit** target → *Signing & Capabilities* → pick your **Team** and change the bundle ID to something unique (e.g. `com.yourname.reconkit`).
2. Plug in the iPhone, enable *Settings › Privacy & Security › Developer Mode*, trust the computer.
3. Choose your iPhone as the run destination and press **Run**.
4. First launch of a developer-signed app: *Settings › General › VPN & Device Management* → trust your Apple ID.
5. When a scan first touches your LAN, allow **Local Network** access.

## What it does

| Area | Capabilities |
|---|---|
| **Port scanner** | TCP connect scan (Network.framework) of hosts, IPs, CIDR blocks and ranges; presets Top 20/100/1–1024/all/custom; banner grabbing with service + version identification; UDP probes (DNS, NTP, SNMP, SSDP, mDNS, NetBIOS); live results; exposure risk rating per port |
| **LAN discovery** | Sweeps your Wi-Fi subnet with ICMP echo + TCP probes (an RST proves a host is up); tap a host to scan it; Bonjour/mDNS service browser (printers, Apple TV, HomeKit, SMB, SSH, Chromecast…) |
| **Full Recon** | One tap pipeline for a domain or IP: DNS records → SPF/DKIM/DMARC/MTA-STS/CAA/DNSSEC → RDAP → geo/ASN/Shodan InternetDB → CT-log + archive subdomains (+optional brute force) with takeover detection → HTTP security grade, cookies, tech stack, exposed files (`.git`, `.env`, backups, consoles), CORS → TLS chain & protocol support → top-100 port scan → Wayback mining. Findings are risk-ranked and saved as a report |
| **DNS tools** | All record types over DoH, reverse DNS, email-security posture, wildcard-aware subdomain brute force |
| **OSINT** | RDAP domain/IP, IP intelligence, Certificate Transparency, Wayback Machine, reverse IP, username search (~40 sites), email OSINT (MX, Gravatar, EmailRep, HIBP), GitHub profile + commit-email leak finder, k-anonymity breached-password check, optional Shodan & VirusTotal |
| **Web** | HTTP security analyzer (A–F grade), redirect chain, 50+ technology fingerprints, exposed-path discovery with soft-404 calibration, CORS misconfiguration test, TLS/certificate inspector (own X.509 parser, SANs, expiry, key strength, TLS 1.0–1.3 probing); a **curl-style HTTP request sender** (any method/headers/body, full response) and a **CeWL-style wordlist builder** that harvests a page's vocabulary |
| **Network** | ICMP ping, traceroute, subnet calculator, public IP; **Camera Auto-Discovery** (finds cameras on your joined Wi-Fi automatically — WS-Discovery/ONVIF multicast + mDNS/Bonjour, zero address guessing — then runs full recon on every host found); **IP camera recon** (fingerprint a camera/NVR brand, then its default credentials + RTSP stream URLs + ports — Hikvision, Dahua/Amcrest, Axis, Foscam, Reolink, Vivotek, Ubiquiti, …); **Wi-Fi & router recon** (honest about iOS's Wi-Fi sandbox, plus router default-credential list and gateway attack paths) |
| **Bluetooth** | nRF Connect–style BLE scanner (CoreBluetooth): live discovery with device classification (flags cameras/IoT beaconing nearby — no network needed), filtering (name/vendor/UUID search, min-RSSI slider, connectable/named/cameras toggles) and sorting (signal/name/last-seen). Tap a device for the full advertising breakdown (manufacturer data, service data, Tx power) and **Connect to explore its GATT** services and characteristics with Bluetooth-SIG names, auto-read values, and full interaction — **Read**, **Subscribe/Unsubscribe** to notifications (live-updating as they arrive), and **Write** a hex value with- or without-response. Classic Bluetooth and Wi-Fi scanning are not exposed to apps by iOS |
| **CTF / crypto** | Magic Decoder (recursive Base64/32/58/85, hex, binary, decimal, URL, ROT13, Morse, reverse with auto flag detection); single-byte XOR brute-force; Caesar/ROT47/Atbash breaker; **Vigenère cryptanalysis** (Index-of-Coincidence + chi-squared key recovery); **substitution-cipher solver** (trigram hill-climbing); **RSA toolkit** (own big-integer: factor n via trial/Fermat/Pollard-rho, **Wiener's attack** for small d, recover d, decrypt c, low-exponent attack, weak-key detection); **RSA multi-key attacks** (common-modulus, Håstad broadcast via CRT); **repeating-key XOR breaker** (Hamming key-size + per-column) and **two-time-pad crib dragging**; **dictionary hash cracker** (MD5/SHA-1/SHA-256 + PIN space). Magic Decoder also covers Base45/Base62/basE91; **zero-width steganography** (hide/reveal), **Bacon / A1Z26 / Braille / NATO / tap-code** decoders; plus a **homoglyph (IDN phishing) detector** and playful text transforms (leetspeak, upside-down, full-width, mocking case); **JWT secret cracker** (HS256/384/512 HMAC brute, verifies the real signature); "What Is This?" encoding/cipher identifier; flag extractor; base/number converter |
| **Red team** | Reverse-shell one-liner generator (bash, sh, nc, python, php, perl, ruby, PowerShell, socat, Go, Lua) with matching listeners and TTY-upgrade steps; PowerShell `-EncodedCommand` builder; default-credentials database (~50 products); payload cheat-sheet (XSS/SQLi/SSTI/LFI/SSRF/XXE/command/NoSQL); nmap command builder; hashcat/John command builder; username/email permutator; **WAF-bypass payload encoder** (URL/double-URL/HTML/unicode/hex/mixed-case/SQL-comment chains). For authorised engagements / CTFs — nothing executes |
| **Deep recon** | Favicon hashing (Shodan/Censys pivot, MurmurHash3 matched to `mmh3`); endpoint extractor that pulls hidden paths & APIs from a page and its JavaScript; Google-dork generator (16 ready dorks per domain). Reports are organised into **folders** (one per target) you can rename, move between, and delete |
| **SSH terminal** | A real SSH client (Citadel / SwiftNIO-SSH): save servers and open a live interactive shell on your phone — password or OpenSSH private-key auth (ed25519/RSA, passphrase-protected keys supported), persistent shell (cd/env/history survive), streamed output, Ctrl-C/D/Z/Tab/Esc/arrow keys, trust-on-first-use host keys. Credentials are kept only in the device Keychain. Run commands, triage boxes and pivot without a laptop. Includes an **SFTP file browser** over the same connection — navigate the remote filesystem and download files to your phone to view or share |
| **Generators** | On-device CSPRNG password & passphrase generator (with strength), random hex/Base64/Base64URL token & UUID v4 generator, Unix-epoch ⇄ ISO-8601 timestamp converter, xxd-style hex dump, CVSS v3.1 base-score calculator, JWT forge |
| **AI Copilot** | In-app chat assistant that connects to a local model (LM Studio / Ollama on your computer) or any API key (OpenAI, OpenRouter, Anthropic, Groq, Together — OpenAI-compatible or Anthropic shapes). Replies **stream token-by-token** over server-sent events, same as the real apps. Fully saved on-device (conversations in Documents, keys in Keychain). Pre-prompted as a recon/CTF copilot that knows the app's tools |
| **MITRE ATT&CK** | Offline ATT&CK Enterprise browser: all 14 tactics and 54 high-use techniques with plain descriptions, detection ideas, mitigations and reference links; lookup by technique id, tactic id or keyword |
| **Learn** | Built-in field guide: ~60 plain-language definitions across networking, DNS, web, TLS, crypto, OSINT, red team and scoring — searchable, offline |
| **Secrets** | Credential scanner over 20+ token formats (AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio, SendGrid, OpenAI, private-key blocks, basic-auth URLs) plus a Shannon-entropy sweep — paste text, or fetch a page and its JavaScript and scan both |
| **Utilities** | Hash identifier (hashcat modes), hash generator and portable MD5/SHA-1/SHA-256/HMAC (work offline, no system crypto needed), smart decoder, JWT analyzer |
| **Reports** | Everything exports as Markdown or JSON; history stored on-device (file-protected) |

API keys (Shodan, VirusTotal, HIBP, GitHub) are optional, stored in the iOS Keychain, and only sent to their own service.

## Platform limits (honest list)

iOS does not allow third-party apps to open raw sockets, so compared with desktop `nmap`:

- No SYN/FIN/Xmas/ACK scans – scans are full TCP `connect()` scans (accurate, but noisier and slower).
- No TCP/IP stack OS fingerprinting; the app offers a role *hint* from open-port patterns instead.
- No arbitrary packet crafting, no monitor-mode Wi-Fi, no ARP table access.
- Wi-Fi SSID/BSSID needs an entitlement that sideloaded apps can't get.
- Scans pause if the app is backgrounded – keep it in the foreground.
- ICMP ping/traceroute use unprivileged datagram ICMP sockets, which iOS allows.

## Project layout

```
project.yml              XcodeGen definition (Info.plist, Bonjour types, local-network permission)
App/                     SwiftUI app: dashboard, scanner, full recon, tools, reports, settings
ReconCore/               Swift package with all recon logic (no UI)
  Sources/ReconCore/
    Net/                 targets, scanner, host discovery, ICMP, Bonjour, interfaces, service DB
    DNS/                 DoH client, email security, subdomain brute-force + takeover checks
    Web/                 HTTP analysis, fingerprinting, content discovery, CORS
    TLS/                 DER/X.509 parser, TLS inspector
    OSINT/               RDAP, IP intel, CT logs, Wayback, people/email/GitHub, keyed services
    Utils/               hashes, encoders, JWT, hash identification
    Recon/               Full Recon orchestrator
    Tools/ToolCatalog    registry the Tools tab is generated from – add a tool in one place
  Tests/                 unit tests (parsers, X.509 vs real openssl certs) + macOS loopback scanner tests
.github/workflows/ci.yml Linux unit tests + macOS build of the real iOS target
```

### Adding a tool

Append a `ToolSpec` in `ToolCatalog.all` that returns a `ToolOutput` (sections + findings). The UI, saving, sharing and export come for free.

### Running core tests without a Mac

```bash
cd ReconCore && swift test      # works on Linux; Apple-only code is compiled out
```
