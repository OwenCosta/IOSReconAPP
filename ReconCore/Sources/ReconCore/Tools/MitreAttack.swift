import Foundation

/// A curated, offline MITRE ATT&CK (Enterprise) knowledge base: the 14 tactics
/// and a strong set of the most-used techniques, each with a plain description,
/// detection ideas and mitigations. For planning and understanding adversary
/// behaviour on authorised engagements / CTFs.
public enum MitreAttack {
    public struct Technique: Identifiable, Sendable {
        public let id: String            // e.g. T1059
        public let name: String
        public let tactic: String        // tactic id, e.g. TA0002
        public let summary: String
        public let detection: String
        public let mitigation: String
        public init(_ id: String, _ name: String, _ tactic: String, _ summary: String, detect: String, mitigate: String) {
            self.id = id; self.name = name; self.tactic = tactic; self.summary = summary
            self.detection = detect; self.mitigation = mitigate
        }
    }

    public struct Tactic: Identifiable, Sendable {
        public let id: String            // e.g. TA0001
        public let name: String
        public let summary: String
    }

    public static let tactics: [Tactic] = [
        Tactic(id: "TA0043", name: "Reconnaissance", summary: "Gathering information to plan future operations."),
        Tactic(id: "TA0042", name: "Resource Development", summary: "Establishing resources to support operations."),
        Tactic(id: "TA0001", name: "Initial Access", summary: "Getting into the network."),
        Tactic(id: "TA0002", name: "Execution", summary: "Running adversary-controlled code."),
        Tactic(id: "TA0003", name: "Persistence", summary: "Maintaining a foothold across restarts."),
        Tactic(id: "TA0004", name: "Privilege Escalation", summary: "Gaining higher-level permissions."),
        Tactic(id: "TA0005", name: "Defense Evasion", summary: "Avoiding detection."),
        Tactic(id: "TA0006", name: "Credential Access", summary: "Stealing account names and passwords."),
        Tactic(id: "TA0007", name: "Discovery", summary: "Learning about the environment."),
        Tactic(id: "TA0008", name: "Lateral Movement", summary: "Moving through the environment."),
        Tactic(id: "TA0009", name: "Collection", summary: "Gathering data of interest."),
        Tactic(id: "TA0011", name: "Command and Control", summary: "Communicating with compromised systems."),
        Tactic(id: "TA0010", name: "Exfiltration", summary: "Stealing data out of the network."),
        Tactic(id: "TA0040", name: "Impact", summary: "Manipulating, interrupting or destroying systems/data."),
    ]

    public static let techniques: [Technique] = [
        // Reconnaissance
        Technique("T1595", "Active Scanning", "TA0043", "Probe target infrastructure via network scans (ports, services, vuln scans) before access.", detect: "IDS on scan patterns; connection spikes from one source.", mitigate: "Minimise exposed services; this is pre-compromise — focus on hardening."),
        Technique("T1592", "Gather Victim Host Information", "TA0043", "Collect host details (OS, hardware, software) from public or active sources.", detect: "Hard to detect; monitor for banner-grabbing.", mitigate: "Limit info disclosure in banners/headers."),
        Technique("T1589", "Gather Victim Identity Information", "TA0043", "Collect emails, usernames, credentials from OSINT and leaks.", detect: "Monitor for credential reuse; breach alerting.", mitigate: "Security awareness; monitor paste/leak sites."),
        Technique("T1590", "Gather Victim Network Information", "TA0043", "Enumerate domains, IP ranges, DNS, topology via RDAP/DNS/CT logs.", detect: "DNS query anomalies.", mitigate: "Reduce public DNS/WHOIS detail where possible."),
        Technique("T1596", "Search Open Technical Databases", "TA0043", "Use Shodan, Censys, CT logs, scan DBs to find exposed assets.", detect: "Not detectable on target.", mitigate: "Monitor your own exposure in these DBs."),
        // Resource Development
        Technique("T1583", "Acquire Infrastructure", "TA0042", "Buy/rent domains, servers, VPS for staging and C2.", detect: "Newly registered domain intel.", mitigate: "Block newly-seen domains; threat-intel feeds."),
        Technique("T1587", "Develop Capabilities", "TA0042", "Build malware, exploits, certificates for operations.", detect: "N/A pre-compromise.", mitigate: "Keep software patched against known exploits."),
        Technique("T1588", "Obtain Capabilities", "TA0042", "Acquire tools, exploits, stolen certs from third parties.", detect: "N/A.", mitigate: "Patch; revoke abused certificates."),
        // Initial Access
        Technique("T1566", "Phishing", "TA0001", "Send malicious email/links/attachments to gain access.", detect: "Mail gateway sandboxing; URL rewriting; user reports.", mitigate: "Email filtering; MFA; user training; attachment sandboxing."),
        Technique("T1190", "Exploit Public-Facing Application", "TA0001", "Exploit a vuln in an internet-facing app (web, VPN, camera, NVR).", detect: "WAF logs; IDS; anomalous app errors.", mitigate: "Patch; WAF; network segmentation; least privilege."),
        Technique("T1133", "External Remote Services", "TA0001", "Abuse VPN, RDP, SSH, or admin portals exposed to the internet.", detect: "Auth logs; impossible-travel; new source IPs.", mitigate: "MFA; VPN; disable unused services; allowlist."),
        Technique("T1078", "Valid Accounts", "TA0001", "Use legitimate credentials (default, stolen, reused) to log in.", detect: "Unusual login times/locations; default-cred use.", mitigate: "Change defaults; MFA; disable dormant accounts."),
        Technique("T1200", "Hardware Additions", "TA0001", "Introduce rogue devices (drop boxes, keyloggers, rogue AP).", detect: "NAC; port-security; physical inspection.", mitigate: "802.1X NAC; disable unused ports; physical security."),
        // Execution
        Technique("T1059", "Command and Scripting Interpreter", "TA0002", "Run commands via bash, PowerShell, Python, cmd, JS.", detect: "Process/command-line logging; EDR; PowerShell logs.", mitigate: "Constrained language mode; app control; disable unused shells."),
        Technique("T1203", "Exploitation for Client Execution", "TA0002", "Exploit a client app (browser, Office, PDF) to run code.", detect: "EDR; exploit-mitigation telemetry.", mitigate: "Patch; attack-surface reduction; sandboxing."),
        Technique("T1053", "Scheduled Task/Job", "TA0002", "Use cron, at, Task Scheduler to run code (also persistence).", detect: "Monitor task/cron creation.", mitigate: "Restrict who can create tasks; audit."),
        Technique("T1569", "System Services", "TA0002", "Execute via service managers (systemd, services.exe, sc).", detect: "Service-creation events.", mitigate: "Restrict service creation; least privilege."),
        // Persistence
        Technique("T1543", "Create or Modify System Process", "TA0003", "Install a service/daemon (systemd, launchd, Windows service) for persistence.", detect: "New service/daemon monitoring.", mitigate: "Restrict admin; file integrity monitoring."),
        Technique("T1136", "Create Account", "TA0003", "Create a new local/domain/cloud account to keep access.", detect: "Account-creation auditing.", mitigate: "Alert on new privileged accounts; least privilege."),
        Technique("T1098", "Account Manipulation", "TA0003", "Add keys, change passwords, add roles to retain access.", detect: "Monitor authorized_keys, IAM changes, group membership.", mitigate: "MFA; audit key/role changes."),
        Technique("T1547", "Boot or Logon Autostart Execution", "TA0003", "Registry Run keys, startup folders, login items for persistence.", detect: "Autoruns monitoring.", mitigate: "App control; restrict registry/startup writes."),
        // Privilege Escalation
        Technique("T1068", "Exploitation for Privilege Escalation", "TA0004", "Exploit a kernel/software flaw to gain higher privileges.", detect: "EDR; exploit telemetry.", mitigate: "Patch; least privilege; exploit protection."),
        Technique("T1548", "Abuse Elevation Control Mechanism", "TA0004", "Bypass UAC, sudo, setuid to elevate.", detect: "Sudo logs; UAC bypass patterns.", mitigate: "Harden sudoers; UAC max; remove setuid where possible."),
        Technique("T1055", "Process Injection", "TA0004", "Inject code into another process to evade and elevate.", detect: "EDR injection detection.", mitigate: "App control; EDR; protected processes."),
        // Defense Evasion
        Technique("T1070", "Indicator Removal", "TA0005", "Delete logs, history, artifacts to hide activity.", detect: "Log-clearing events (e.g., 1102); centralised logging.", mitigate: "Forward logs off-host; restrict log access."),
        Technique("T1027", "Obfuscated Files or Information", "TA0005", "Encode/encrypt/pack payloads to evade detection.", detect: "Entropy analysis; EDR unpacking.", mitigate: "App control; behavioural detection."),
        Technique("T1562", "Impair Defenses", "TA0005", "Disable AV/EDR/firewall/logging.", detect: "Alert on security-tool tampering.", mitigate: "Tamper protection; monitor service stops."),
        Technique("T1218", "System Binary Proxy Execution", "TA0005", "Abuse signed LOLBins (rundll32, mshta, regsvr32) to run code.", detect: "Command-line + parent/child process analysis.", mitigate: "App control; block risky LOLBins."),
        // Credential Access
        Technique("T1110", "Brute Force", "TA0006", "Guess passwords: spraying, stuffing, dictionary.", detect: "Failed-login spikes; lockouts.", mitigate: "MFA; lockout; strong passwords; rate limiting."),
        Technique("T1003", "OS Credential Dumping", "TA0006", "Dump LSASS, SAM, /etc/shadow, hashes.", detect: "LSASS access; suspicious reads of shadow/SAM.", mitigate: "Credential Guard; least privilege; LAPS."),
        Technique("T1552", "Unsecured Credentials", "TA0006", "Find creds in files, history, env vars, cloud metadata.", detect: "Secret scanning; honeytokens.", mitigate: "Secret managers; scan repos; rotate exposed."),
        Technique("T1555", "Credentials from Password Stores", "TA0006", "Steal from browsers, keychains, password managers.", detect: "Access to credential stores.", mitigate: "Disable browser password save; EDR."),
        Technique("T1557", "Adversary-in-the-Middle", "TA0006", "LLMNR/NBT-NS poisoning, ARP spoof, rogue proxy to capture creds.", detect: "ARP anomalies; unexpected LLMNR responders.", mitigate: "Disable LLMNR/NBT-NS; SMB signing; 802.1X."),
        // Discovery
        Technique("T1046", "Network Service Discovery", "TA0007", "Port/service scan to find reachable services.", detect: "Scan detection; connection bursts.", mitigate: "Segmentation; host firewalls."),
        Technique("T1018", "Remote System Discovery", "TA0007", "Enumerate other hosts (ping sweep, ARP, AD).", detect: "Sweeps; unusual enumeration.", mitigate: "Segmentation; limit discovery protocols."),
        Technique("T1087", "Account Discovery", "TA0007", "Enumerate local/domain/cloud accounts.", detect: "Mass account queries.", mitigate: "Restrict directory read; monitor."),
        Technique("T1082", "System Information Discovery", "TA0007", "Collect OS, hardware, patch level of a host.", detect: "systeminfo/uname bursts.", mitigate: "Limited; focus on later stages."),
        Technique("T1016", "System Network Configuration Discovery", "TA0007", "ipconfig/ifconfig, routes, ARP, DNS to map the network.", detect: "Command telemetry.", mitigate: "Limited; detect patterns."),
        // Lateral Movement
        Technique("T1021", "Remote Services", "TA0008", "Move via SSH, RDP, SMB, WinRM, VNC using valid creds.", detect: "Lateral auth patterns; new admin sessions.", mitigate: "MFA; segmentation; restrict admin protocols."),
        Technique("T1570", "Lateral Tool Transfer", "TA0008", "Copy tools between hosts (SMB, SCP, admin shares).", detect: "File transfers to admin shares.", mitigate: "Disable admin shares; monitor transfers."),
        Technique("T1550", "Use Alternate Authentication Material", "TA0008", "Pass-the-hash / pass-the-ticket / stolen tokens.", detect: "Anomalous ticket use; hash reuse.", mitigate: "Credential Guard; least privilege; tiering."),
        // Collection
        Technique("T1005", "Data from Local System", "TA0009", "Collect files of interest from a host.", detect: "Mass file access; staging.", mitigate: "DLP; least privilege; encryption at rest."),
        Technique("T1119", "Automated Collection", "TA0009", "Scripted gathering of files across systems.", detect: "Bulk read patterns.", mitigate: "DLP; access controls."),
        Technique("T1056", "Input Capture", "TA0009", "Keylogging, credential prompts to capture input.", detect: "Hook/keylogger detection by EDR.", mitigate: "EDR; credential-guard; app control."),
        // Command and Control
        Technique("T1071", "Application Layer Protocol", "TA0011", "C2 over HTTP(S), DNS, or mail to blend with traffic.", detect: "Beaconing analysis; TLS JA3; DNS anomalies.", mitigate: "Proxy inspection; DNS filtering; egress control."),
        Technique("T1572", "Protocol Tunneling", "TA0011", "Tunnel C2 inside another protocol (DNS, ICMP, SSH).", detect: "Unusual tunneling; large DNS/ICMP volume.", mitigate: "Egress filtering; inspect/limit tunneling protocols."),
        Technique("T1090", "Proxy", "TA0011", "Route C2 through proxies/relays to hide origin.", detect: "Known proxy/Tor intel.", mitigate: "Block anonymisers; egress allowlist."),
        Technique("T1105", "Ingress Tool Transfer", "TA0011", "Download tools/payloads from C2 to the victim.", detect: "Unexpected downloads from new hosts.", mitigate: "Egress control; app control; block uncategorised."),
        // Exfiltration
        Technique("T1041", "Exfiltration Over C2 Channel", "TA0010", "Steal data over the same channel used for C2.", detect: "Outbound volume anomalies.", mitigate: "DLP; egress limits; proxy inspection."),
        Technique("T1048", "Exfiltration Over Alternative Protocol", "TA0010", "Exfil via DNS, FTP, cloud, email separate from C2.", detect: "Large DNS/FTP/cloud uploads.", mitigate: "Egress filtering; DLP; block unsanctioned cloud."),
        Technique("T1567", "Exfiltration Over Web Service", "TA0010", "Upload to Dropbox, GitHub, pastebin, cloud storage.", detect: "Uploads to web services.", mitigate: "CASB; block/allowlist web services; DLP."),
        // Impact
        Technique("T1486", "Data Encrypted for Impact", "TA0040", "Ransomware: encrypt data to disrupt or extort.", detect: "Mass file writes/renames; shadow-copy deletion.", mitigate: "Offline backups; least privilege; EDR; segmentation."),
        Technique("T1498", "Network Denial of Service", "TA0040", "Flood a target to deny availability.", detect: "Traffic spikes; SYN floods.", mitigate: "DDoS protection; rate limiting; upstream scrubbing."),
        Technique("T1485", "Data Destruction", "TA0040", "Wipe/overwrite files or disks to destroy data.", detect: "Mass delete/overwrite patterns.", mitigate: "Backups; least privilege; immutability."),
        Technique("T1529", "System Shutdown/Reboot", "TA0040", "Shut down or reboot systems to disrupt operations.", detect: "Unexpected shutdown events.", mitigate: "Restrict shutdown rights; alerting."),
    ]

    public static func tactic(_ id: String) -> Tactic? { tactics.first { $0.id.caseInsensitiveCompare(id) == .orderedSame } }
    public static func technique(_ id: String) -> Technique? { techniques.first { $0.id.caseInsensitiveCompare(id) == .orderedSame } }
    public static func techniques(in tacticID: String) -> [Technique] { techniques.filter { $0.tactic.caseInsensitiveCompare(tacticID) == .orderedSame } }

    public static func search(_ query: String) -> [Technique] {
        let q = query.lowercased()
        return techniques.filter { $0.name.lowercased().contains(q) || $0.summary.lowercased().contains(q)
            || $0.detection.lowercased().contains(q) || $0.mitigation.lowercased().contains(q) || $0.id.lowercased().contains(q) }
    }

    public static func run(_ input: String) -> ToolOutput {
        let q = input.trimmed()
        // Technique id → detail
        if let t = technique(q) { return detail(t) }
        // Tactic id → techniques in it
        if let ta = tactic(q) {
            var s = ReportSection("\(ta.id) — \(ta.name)", note: ta.summary)
            for t in techniques(in: ta.id) { s.add(t.id, t.name) }
            return ToolOutput(sections: [s])
        }
        // Keyword search
        if !q.isEmpty {
            let hits = search(q)
            if hits.isEmpty {
                return ToolOutput(sections: [ReportSection("ATT&CK", items: [ReportItem("No match", "try a tactic (TA0002), a technique (T1059) or a keyword (phishing, brute, exfil)", .low)])])
            }
            var out = ToolOutput()
            var s = ReportSection("Matches for “\(q)” (\(hits.count))")
            for t in hits.prefix(40) { s.add(t.id, "\(t.name) — \(tactic(t.tactic)?.name ?? t.tactic)") }
            out.sections.append(s)
            return out
        }
        // Empty → the matrix overview
        var out = ToolOutput()
        var s = ReportSection("MITRE ATT&CK — Enterprise tactics", note: "Enter a tactic id (TA0001), technique id (T1059) or keyword. \(techniques.count) techniques covered.")
        for ta in tactics { s.add("\(ta.id) · \(ta.name)", "\(techniques(in: ta.id).count) techniques") }
        out.sections.append(s)
        return out
    }

    static func detail(_ t: Technique) -> ToolOutput {
        var s = ReportSection("\(t.id) — \(t.name)", note: "Tactic: \(tactic(t.tactic)?.name ?? t.tactic)")
        s.add("What", t.summary)
        s.add("Detect", t.detection, .low)
        s.add("Mitigate", t.mitigation, .low)
        s.add("Reference", "https://attack.mitre.org/techniques/\(t.id.replacingOccurrences(of: ".", with: "/"))/")
        return ToolOutput(sections: [s])
    }
}
