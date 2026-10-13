# ReconKit – iOS recon & OSINT toolkit

A native SwiftUI app for network reconnaissance and open-source intelligence, built to be sideloaded onto your own iPhone with Xcode.

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
| **Web** | HTTP security analyzer (A–F grade), redirect chain, 50+ technology fingerprints, exposed-path discovery with soft-404 calibration, CORS misconfiguration test, TLS/certificate inspector (own X.509 parser, SANs, expiry, key strength, TLS 1.0–1.3 probing) |
| **Network** | ICMP ping, traceroute, subnet calculator, public IP |
| **Utilities** | Hash identifier (hashcat modes), hash generator, smart decoder, JWT analyzer |
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
