import Foundation

/// Port → service names, "top ports" lists and exposure-risk rules.
public enum ServiceDB {
    public static let top20: [UInt16] = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                                         1723, 3306, 3389, 5900, 8080]

    /// Approximation of nmap's most frequently open TCP ports.
    public static let top100: [UInt16] = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179,
        199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
        1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000,
        3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
        6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
        49153, 49154, 49155, 49156, 49157
    ]

    /// Ports where the service speaks TLS from the first byte.
    public static let tlsPorts: Set<UInt16> = [443, 465, 636, 853, 989, 990, 993, 995, 2376, 3269, 5986, 8443, 9443]

    public static let httpPorts: Set<UInt16> = [80, 81, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000, 9090, 10000]

    static let names: [UInt16: String] = [
        7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        26: "rsftp", 37: "time", 53: "domain", 67: "dhcps", 69: "tftp", 79: "finger", 80: "http", 81: "http-alt",
        88: "kerberos", 106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
        135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 144: "news", 161: "snmp",
        179: "bgp", 199: "smux", 389: "ldap", 427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds",
        465: "smtps", 500: "isakmp", 513: "login", 514: "shell", 515: "printer", 543: "klogin", 544: "kshell",
        548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync",
        990: "ftps", 993: "imaps", 995: "pop3s", 1025: "NFS-or-IIS", 1080: "socks", 1110: "nfsd-status",
        1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle", 1720: "h323q931", 1723: "pptp", 1755: "wms",
        1883: "mqtt", 1900: "upnp", 2000: "cisco-sccp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
        2121: "ccproxy-ftp", 2375: "docker", 2376: "docker-tls", 3000: "ppp/dev-http", 3128: "squid-http",
        3306: "mysql", 3389: "ms-wbt-server", 3478: "stun", 3690: "svn", 4369: "epmd", 4444: "krb524/metasploit",
        4899: "radmin", 5000: "upnp/http", 5060: "sip", 5222: "xmpp", 5357: "wsdapi", 5432: "postgresql",
        5601: "kibana", 5631: "pcanywheredata", 5666: "nrpe", 5672: "amqp", 5800: "vnc-http", 5900: "vnc",
        5984: "couchdb", 5985: "wsman", 5986: "wsmans", 6000: "x11", 6379: "redis", 6443: "kubernetes-api",
        6646: "unknown", 7001: "weblogic", 7070: "realserver", 8000: "http-alt", 8008: "http",
        8009: "ajp13", 8080: "http-proxy", 8081: "blackice-icecap", 8086: "influxdb", 8443: "https-alt",
        8500: "consul", 8888: "sun-answerbook", 9000: "cslistener", 9042: "cassandra", 9090: "zeus-admin",
        9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch", 9300: "es-transport", 9418: "git",
        9999: "abyss", 10000: "snet-sensor-mgmt", 11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
        27018: "mongodb", 32768: "filenet-tms", 50000: "ibm-db2", 62078: "iphone-sync"
    ]

    public static func name(port: UInt16, proto: String = "tcp") -> String {
        names[port] ?? (port >= 49152 ? "dynamic" : "unknown")
    }

    public struct Risk: Sendable {
        public let severity: Severity
        public let why: String
    }

    /// Exposure rules: what it means when this port is reachable.
    public static func risk(port: UInt16) -> Risk? {
        switch port {
        case 23: return Risk(severity: .high, why: "Telnet transmits credentials in cleartext.")
        case 21: return Risk(severity: .medium, why: "FTP is unencrypted; check for anonymous login.")
        case 69: return Risk(severity: .medium, why: "TFTP has no authentication.")
        case 79: return Risk(severity: .low, why: "Finger leaks user information.")
        case 111: return Risk(severity: .medium, why: "rpcbind exposes RPC service map.")
        case 135, 139: return Risk(severity: .medium, why: "Windows RPC/NetBIOS exposed; common lateral-movement path.")
        case 445: return Risk(severity: .high, why: "SMB exposed; historically exploited (EternalBlue, relay attacks).")
        case 512, 513, 514: return Risk(severity: .high, why: "BSD r-services are unauthenticated/cleartext.")
        case 873: return Risk(severity: .medium, why: "rsync may allow unauthenticated module listing.")
        case 1433, 1521, 3306, 5432, 27017, 27018, 9042, 50000:
            return Risk(severity: .high, why: "Database port reachable; should not be internet-facing.")
        case 2049: return Risk(severity: .medium, why: "NFS exposed; check export permissions.")
        case 2375: return Risk(severity: .critical, why: "Docker API without TLS = remote root on the host.")
        case 3389: return Risk(severity: .high, why: "RDP exposed; brute-force & BlueKeep-class risk.")
        case 4369, 6379, 11211, 9200, 5984, 2181:
            return Risk(severity: .high, why: "Datastore/cluster port often deployed without authentication.")
        case 5900, 5800: return Risk(severity: .high, why: "VNC remote desktop exposed.")
        case 5985: return Risk(severity: .medium, why: "WinRM exposed.")
        case 6000: return Risk(severity: .medium, why: "X11 exposed; may allow screen capture/keylogging.")
        case 6443, 10250: return Risk(severity: .medium, why: "Kubernetes control endpoint exposed.")
        case 161: return Risk(severity: .medium, why: "SNMP exposed; default community strings are common.")
        case 1900: return Risk(severity: .low, why: "UPnP/SSDP exposed.")
        case 9100: return Risk(severity: .low, why: "Raw printing port exposed.")
        case 8009: return Risk(severity: .medium, why: "AJP connector exposed (Ghostcat class bugs).")
        case 5601, 15672, 8500, 9090: return Risk(severity: .medium, why: "Admin/monitoring UI exposed.")
        default: return nil
        }
    }

    /// Cheap device guess from the set of open ports (no raw packets on iOS, so no TCP/IP stack fingerprint).
    public static func deviceHint(openPorts: Set<UInt16>) -> String? {
        if openPorts.contains(62078) { return "Apple iOS device (lockdownd / iphone-sync)" }
        if openPorts.contains(3389) || (openPorts.contains(445) && openPorts.contains(135)) { return "Windows host" }
        if openPorts.contains(548) || (openPorts.contains(5900) && openPorts.contains(631)) { return "macOS host" }
        if openPorts.contains(9100) || openPorts.contains(515) || openPorts.contains(631) { return "Network printer" }
        if openPorts.contains(554) { return "IP camera / media server (RTSP)" }
        if openPorts.contains(22) && openPorts.contains(80) && openPorts.contains(53) { return "Router / gateway" }
        if openPorts.contains(22) { return "Unix-like host (SSH)" }
        return nil
    }
}
