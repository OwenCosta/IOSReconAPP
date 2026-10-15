import Foundation

public struct LearnEntry: Identifiable, Sendable, Hashable {
    public let id = UUID()
    public let term: String
    public let definition: String
    public init(_ term: String, _ definition: String) { self.term = term; self.definition = definition }
}

public struct LearnSection: Identifiable, Sendable, Hashable {
    public let id = UUID()
    public let title: String
    public let icon: String
    public let entries: [LearnEntry]
    public init(_ title: String, icon: String, _ entries: [LearnEntry]) { self.title = title; self.icon = icon; self.entries = entries }
}

/// The in-app reference ("Learn") — plain-language explanations of the concepts and jargon behind
/// every tool. Content only, so it is unit-testable for completeness.
public enum LearnContent {
    public static let sections: [LearnSection] = [
        LearnSection("Getting started", icon: "sparkles", [
            LearnEntry("What is reconnaissance?", "Recon is the first phase of a security assessment: gathering information about a target before testing it. Passive recon uses public data and never touches the target; active recon (scanning, probing) sends traffic to it and needs authorisation."),
            LearnEntry("Passive vs. active", "Passive tools (WHOIS, DNS, certificate logs, OSINT) query third parties, so the target never sees you. Active tools (port scan, TLS probe, path discovery, ping) talk to the target directly. Only run them on systems you own or are authorised to test. Active tools are marked ACTIVE in the toolkit."),
            LearnEntry("Scope & authorisation", "“Scope” is the set of systems you are allowed to test, usually written into a contract or CTF rules. Testing outside scope, even accidentally, can be illegal. When in doubt, don't."),
            LearnEntry("CTF (Capture The Flag)", "A security competition where you solve challenges to recover hidden “flags” (strings like flag{...}). Categories include web, crypto, forensics, reversing, pwn, and OSINT. This app's CTF tab targets web, crypto and encoding challenges."),
            LearnEntry("Flag format", "Flags usually look like name{some_text}, e.g. flag{}, CTF{}, picoCTF{}, HTB{}. The Flag Extractor and most solvers auto-detect this pattern.")
        ]),
        LearnSection("Networking", icon: "network", [
            LearnEntry("IP address", "A number identifying a device on a network. IPv4 looks like 192.168.1.10 (4 bytes); IPv6 looks like 2001:db8::1 (16 bytes). Private ranges (10.x, 172.16-31.x, 192.168.x) are only routable inside a LAN."),
            LearnEntry("Port", "A numbered channel (0-65535) on a host. Each listening service uses a port: 80 for HTTP, 443 for HTTPS, 22 for SSH. “Open” means something is listening; a port scan finds these."),
            LearnEntry("TCP vs. UDP", "TCP is connection-oriented and reliable (handshake, ordered delivery), used by web, SSH, email. UDP is fire-and-forget and fast, used by DNS, NTP, SNMP, video. This app does TCP connect scans and a few UDP probes."),
            LearnEntry("Subnet / CIDR", "A block of IP addresses written like 192.168.1.0/24. The /24 means the first 24 bits are the network, leaving 8 bits (254 usable hosts). Smaller number = bigger block. Use the Subnet Calculator."),
            LearnEntry("Port scan", "Checking which ports are open on a host. A TCP connect scan completes the handshake (accurate but noisy). iOS can't send raw packets, so there's no SYN scan or OS fingerprint: the app infers a device “role” from the open-port pattern instead."),
            LearnEntry("Banner grabbing", "Reading the greeting a service sends when you connect (e.g. “SSH-2.0-OpenSSH_9.6”). It reveals the software and version, which maps to known vulnerabilities."),
            LearnEntry("Ping / ICMP", "ICMP echo request/reply tests whether a host is reachable and measures round-trip time. Traceroute sends packets with increasing TTL to map each hop along the route."),
            LearnEntry("mDNS / Bonjour", "Zero-configuration service discovery on a LAN. Devices announce services (printers, Apple TV, file shares) over multicast DNS. The Bonjour browser lists them.")
        ]),
        LearnSection("DNS", icon: "point.3.connected.trianglepath.dotted", [
            LearnEntry("DNS", "The Domain Name System maps names (example.com) to IP addresses and other records. This app queries it over DNS-over-HTTPS (DoH) so lookups work even on restrictive networks."),
            LearnEntry("Record types", "A/AAAA = IPv4/IPv6 address; CNAME = alias; MX = mail server; NS = nameserver; TXT = free text (SPF, verification); SOA = zone authority; CAA = which CAs may issue certs; PTR = reverse (IP→name)."),
            LearnEntry("Subdomain enumeration", "Finding a domain's subdomains (mail., dev., vpn.). Passive sources (certificate logs, passive DNS) reveal real ones that ever had a cert or were observed; brute-force guesses common names. More subdomains = bigger attack surface."),
            LearnEntry("Subdomain takeover", "When a subdomain's DNS still points to a third-party service (GitHub Pages, S3, Heroku) that has been deleted, an attacker can re-register it and serve content from your domain. The finder flags dangling CNAMEs."),
            LearnEntry("SPF / DKIM / DMARC", "Email-authentication records. SPF lists who may send mail for a domain; DKIM signs messages; DMARC tells receivers what to do with failures (none/quarantine/reject). Weak or missing records enable spoofing."),
            LearnEntry("DNSSEC", "Cryptographic signatures on DNS records that prevent tampering/poisoning. Unsigned domains are easier to spoof.")
        ]),
        LearnSection("Web security", icon: "globe", [
            LearnEntry("HTTP headers", "Metadata sent with every response. Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) harden the site; the analyzer grades them A-F."),
            LearnEntry("CSP (Content-Security-Policy)", "Tells the browser which sources of scripts/styles/images are allowed, mitigating XSS. 'unsafe-inline' or wildcards weaken it."),
            LearnEntry("HSTS", "Strict-Transport-Security forces HTTPS for a domain, preventing downgrade/SSL-strip attacks. Should have a long max-age and includeSubDomains."),
            LearnEntry("Cookies & flags", "Secure (HTTPS only), HttpOnly (hidden from JavaScript), and SameSite (blocks cross-site sending) protect session cookies. Missing flags on an auth cookie is a real risk."),
            LearnEntry("CORS", "Cross-Origin Resource Sharing controls which other sites may read responses. Reflecting any Origin with credentials=true lets a malicious site read authenticated data."),
            LearnEntry("XSS", "Cross-Site Scripting: injecting JavaScript that runs in another user's browser. Reflected, stored and DOM variants. Mitigated by output encoding and CSP."),
            LearnEntry("SQL injection", "Injecting SQL through unsanitised input to read/modify a database. Mitigated by parameterised queries."),
            LearnEntry("Content discovery", "Requesting well-known paths (/.git, /.env, /admin, backups) to find files that shouldn't be public. The app verifies content to avoid false positives on catch-all servers."),
            LearnEntry("Secrets in code", "API keys, tokens and private keys accidentally shipped in HTML/JS or config. The secret scanner matches 20+ formats plus high-entropy strings."),
            LearnEntry("Homoglyph / IDN phishing", "Using lookalike Unicode characters (Cyrillic 'а' for Latin 'a') to register deceptive domains. The detector shows the ASCII skeleton and flags mixed scripts.")
        ]),
        LearnSection("TLS & certificates", icon: "lock.shield", [
            LearnEntry("TLS/SSL", "The encryption layer under HTTPS. A handshake negotiates a version (TLS 1.2/1.3 are current; 1.0/1.1 are deprecated) and a cipher suite, then authenticates the server with a certificate."),
            LearnEntry("X.509 certificate", "The server's identity document, signed by a Certificate Authority. It lists the subject, valid dates, public key and the names (SANs) it's valid for. The inspector parses all of this."),
            LearnEntry("SAN (Subject Alternative Name)", "The list of hostnames a certificate is valid for. If the site's hostname isn't in the SANs, browsers reject it."),
            LearnEntry("Certificate Transparency", "Public, append-only logs of every certificate issued. Because almost every subdomain gets a cert, CT logs are the best passive source for subdomain discovery.")
        ]),
        LearnSection("Cryptography", icon: "function", [
            LearnEntry("Encoding vs. encryption vs. hashing", "Encoding (Base64, hex) is reversible and provides no secrecy. Encryption is reversible with a key. Hashing (MD5, SHA) is one-way, used for integrity and password storage."),
            LearnEntry("Base64 / Base32 / Base58", "Ways to represent binary as text. Base64 uses A-Z a-z 0-9 + / ; Base32 uses A-Z 2-7; Base58 (Bitcoin) drops ambiguous characters. The Magic Decoder peels layered encodings automatically."),
            LearnEntry("XOR", "A reversible bitwise operation. Single-byte XOR is trivially brute-forced; repeating-key XOR is broken by finding the key length (Hamming distance) then solving each column."),
            LearnEntry("Caesar / ROT / Vigenère", "Classical ciphers. Caesar shifts letters by a fixed amount (ROT13 = shift 13). Vigenère uses a repeating keyword and is broken with Index of Coincidence + frequency analysis."),
            LearnEntry("Substitution cipher", "Each letter maps to another consistently. Broken by frequency analysis / hill-climbing against English statistics (the solver uses a trigram model)."),
            LearnEntry("RSA", "Public-key crypto. Security rests on the difficulty of factoring n = p·q. If n is small or the primes are close, it factors; small private exponent d falls to Wiener's attack; key reuse enables common-modulus and Håstad attacks."),
            LearnEntry("JWT", "JSON Web Token: header.payload.signature, base64url-encoded. 'alg=none' means unsigned; HS256 uses a shared secret that can be brute-forced if weak. The app decodes, cracks and forges them."),
            LearnEntry("Hash cracking", "Recovering the input of a hash by trying candidates (dictionary, PINs) and comparing. Works on weak/unsalted hashes; strong salted hashes (bcrypt, argon2) resist it."),
            LearnEntry("Entropy", "A measure of randomness (bits per character). High entropy suggests encryption, compression or a strong key; low entropy suggests structured text.")
        ]),
        LearnSection("OSINT", icon: "eye", [
            LearnEntry("OSINT", "Open-Source Intelligence: building a picture of a target from public data (WHOIS, DNS, social media, leaks, archives) without touching their systems."),
            LearnEntry("WHOIS / RDAP", "Registration data for a domain or IP: registrar, dates, nameservers, owning organisation. RDAP is the modern, structured replacement for WHOIS."),
            LearnEntry("ASN", "Autonomous System Number: identifies the network/organisation that owns a block of IPs (e.g. an ISP or cloud provider)."),
            LearnEntry("Reverse IP", "Finding other domains hosted on the same IP, useful for mapping shared infrastructure."),
            LearnEntry("Breach data", "Credentials exposed in past data breaches. Have I Been Pwned checks an email against known breaches; Pwned Passwords checks a password via k-anonymity so the full password never leaves the device."),
            LearnEntry("Wayback Machine", "A public archive of historical web pages. Old snapshots reveal endpoints, parameters, backups and admin paths that may still exist.")
        ]),
        LearnSection("Red team", icon: "flame", [
            LearnEntry("Red team vs. pentest", "A penetration test finds as many vulnerabilities as possible in a scope. A red-team engagement emulates a specific adversary end-to-end (initial access → persistence → objectives), testing detection and response too."),
            LearnEntry("Reverse shell", "The target connects back to the attacker's listener, giving command-line access. Preferred over a bind shell because outbound connections usually get through firewalls/NAT. The generator produces one-liners for many languages."),
            LearnEntry("Listener / handler", "The attacker side that catches a reverse shell: netcat (nc -lvnp), ncat with TLS, socat, or Metasploit's multi/handler."),
            LearnEntry("TTY upgrade", "A raw reverse shell lacks job control and tab-completion. Upgrading to a full PTY (python3 pty.spawn, then stty raw) makes it usable."),
            LearnEntry("Privilege escalation", "Going from a low-privileged shell to root/admin by abusing misconfigurations (SUID binaries, sudo rules, kernel bugs, weak service permissions)."),
            LearnEntry("Lateral movement", "Using a foothold on one machine to reach others: reusing credentials, abusing SMB/WinRM/SSH, pass-the-hash."),
            LearnEntry("Persistence", "Maintaining access after a reboot: cron jobs, services, SSH keys, scheduled tasks, startup scripts."),
            LearnEntry("Default credentials", "Factory usernames/passwords (admin/admin, root/calvin) left unchanged. Often the fastest way in; the lookup lists common ones by product."),
            LearnEntry("Payload encoding", "Transforming a command to evade quoting, filters or basic detection, e.g. PowerShell -EncodedCommand (UTF-16LE base64). Not a substitute for real evasion.")
        ]),
        LearnSection("Scoring & reporting", icon: "chart.bar.doc.horizontal", [
            LearnEntry("CVSS", "Common Vulnerability Scoring System: a 0-10 severity score computed from a vector (attack vector, complexity, privileges, impact). 9.0+ is Critical. Use the CVSS calculator."),
            LearnEntry("CVE", "Common Vulnerabilities and Exposures: a unique ID (CVE-2021-44228) for a publicly known vulnerability."),
            LearnEntry("Severity ratings", "This app ranks findings Info / Low / Medium / High / Critical with colour. The executive summary rolls them into an overall exposure score."),
            LearnEntry("Exporting", "Every result and saved report exports as Markdown or JSON from the share button: drop it straight into your notes or a writeup.")
        ])
    ]

    public static var termCount: Int { sections.reduce(0) { $0 + $1.entries.count } }
}
