import Foundation

public struct SubdomainHit: Codable, Hashable, Identifiable, Sendable {
    public var name: String
    public var ips: [String]
    public var cname: String?
    public var source: String
    public var id: String { name }
}

public enum Subdomains {
    /// Brute-force with a built-in wordlist over DNS-over-HTTPS, with wildcard detection.
    public static func bruteForce(domain: String, words: [String] = Wordlist.subdomains, concurrency: Int = 24,
                                  ctx: ToolContext = .silent) async -> [SubdomainHit] {
        let probe = "zz\(UInt32.random(in: 100_000...999_999))-nx"
        let wildcardIPs = Set(await DNSClient.resolveIPs("\(probe).\(domain)"))
        if !wildcardIPs.isEmpty { ctx.log("Wildcard DNS detected (\(wildcardIPs.sorted().joined(separator: ", "))) – filtering") }

        let counter = Counter()
        let total = words.count
        let hits = await boundedMap(words, limit: concurrency) { word -> SubdomainHit? in
            let name = "\(word).\(domain)"
            let ips = await DNSClient.resolveIPs(name)
            let n = counter.next()
            if n % 50 == 0 { ctx.log("Brute-force \(n)/\(total)…") }
            guard !ips.isEmpty, Set(ips) != wildcardIPs else { return nil }
            return SubdomainHit(name: name, ips: ips, cname: nil, source: "brute-force")
        }
        return hits.compactMap { $0 }.sorted { $0.name < $1.name }
    }

    /// Resolve a list of names (from CT logs / archives) and attach CNAME info.
    public static func resolve(_ names: [String], source: String, concurrency: Int = 24) async -> [SubdomainHit] {
        let hits = await boundedMap(names, limit: concurrency) { name -> SubdomainHit in
            async let ips = DNSClient.resolveIPs(name)
            async let cn = DNSClient.records(name, .CNAME)
            return SubdomainHit(name: name, ips: await ips, cname: (await cn).first?.data, source: source)
        }
        return hits.sorted { $0.name < $1.name }
    }

    // MARK: Takeover heuristics

    struct TakeoverSignature { let suffix: String; let service: String }
    static let takeoverServices: [TakeoverSignature] = [
        .init(suffix: "github.io", service: "GitHub Pages"),
        .init(suffix: "herokuapp.com", service: "Heroku"),
        .init(suffix: "herokudns.com", service: "Heroku"),
        .init(suffix: "s3.amazonaws.com", service: "AWS S3"),
        .init(suffix: "s3-website", service: "AWS S3 website"),
        .init(suffix: "elasticbeanstalk.com", service: "AWS Elastic Beanstalk"),
        .init(suffix: "azurewebsites.net", service: "Azure App Service"),
        .init(suffix: "cloudapp.net", service: "Azure Cloud Service"),
        .init(suffix: "trafficmanager.net", service: "Azure Traffic Manager"),
        .init(suffix: "blob.core.windows.net", service: "Azure Blob"),
        .init(suffix: "netlify.app", service: "Netlify"),
        .init(suffix: "surge.sh", service: "Surge"),
        .init(suffix: "pantheonsite.io", service: "Pantheon"),
        .init(suffix: "ghost.io", service: "Ghost"),
        .init(suffix: "readme.io", service: "Readme"),
        .init(suffix: "statuspage.io", service: "Statuspage"),
        .init(suffix: "zendesk.com", service: "Zendesk"),
        .init(suffix: "myshopify.com", service: "Shopify"),
        .init(suffix: "fastly.net", service: "Fastly"),
        .init(suffix: "wordpress.com", service: "WordPress.com"),
        .init(suffix: "bitbucket.io", service: "Bitbucket"),
        .init(suffix: "unbouncepages.com", service: "Unbounce")
    ]

    /// Dangling CNAMEs: points at a claimable third-party service but the target no longer resolves.
    public static func takeoverCandidates(_ hits: [SubdomainHit]) async -> [Finding] {
        let candidates = hits.compactMap { h -> (SubdomainHit, String)? in
            guard let cn = h.cname?.lowercased(), let sig = takeoverServices.first(where: { cn.contains($0.suffix) }) else { return nil }
            return (h, sig.service)
        }
        let checked = await boundedMap(candidates, limit: 8) { (pair) -> Finding? in
            let (hit, service) = pair
            guard let cn = hit.cname else { return nil }
            let alive = !(await DNSClient.resolveIPs(cn)).isEmpty
            if !alive {
                return Finding(.high, "Possible subdomain takeover: \(hit.name)",
                               "CNAME → \(cn) (\(service)) no longer resolves. If the \(service) resource is unclaimed an attacker can register it.",
                               source: "dns")
            }
            return nil
        }
        return checked.compactMap { $0 }
    }

    public static func section(_ hits: [SubdomainHit], title: String = "Subdomains") -> ReportSection {
        var s = ReportSection("\(title) (\(hits.count))")
        for h in hits {
            var v = h.ips.isEmpty ? "does not resolve" : h.ips.joined(separator: ", ")
            if let c = h.cname { v = "→ \(c)  " + v }
            s.add(h.name, v, h.ips.isEmpty ? .low : .info)
        }
        return s
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func next() -> Int { lock.lock(); defer { lock.unlock() }; n += 1; return n }
}

public enum Wordlist {
    public static let subdomains: [String] = """
    www mail remote blog webmail server ns1 ns2 smtp secure vpn m shop ftp mail2 test portal ns dev admin api
    cdn staging app beta stage demo docs support status git gitlab github jenkins ci build jira confluence wiki
    intranet internal corp office owa exchange autodiscover autoconfig imap pop pop3 mx mx1 mx2 relay gateway
    gw fw firewall proxy cache static assets img images media files download downloads upload uploads video
    stream live chat forum community help kb training learn lms hr crm erp sso auth login id accounts account
    oauth idp ldap ad dc dns dns1 dns2 ntp db database sql mysql postgres mongo redis elastic kibana grafana
    prometheus monitor monitoring nagios zabbix logs log splunk graylog sentry backup bak old new v1 v2 v3
    api2 apis rest graphql ws websocket socket mobile ios android wap store pay payment payments billing
    checkout cart order orders invoice shopify magento wordpress wp cms drupal joomla sandbox uat qa qa1 test1
    test2 dev1 dev2 stage1 preprod prod production edge origin lb lb1 lb2 haproxy nginx apache tomcat k8s
    kube kubernetes docker registry harbor nexus artifactory sonar sonarqube vault consul rancher argocd
    airflow jupyter notebook bastion jump ssh sftp rdp vnc citrix vdi horizon webvpn ra access connect meet
    zoom teams slack mattermost rocketchat video conf calendar cal booking marketing mkt news newsletter
    email mailer bounce track tracking click go link links short url s s3 bucket storage cloud aws azure gcp
    office365 o365 lyncdiscover sip sipdir dialin enterpriseregistration enterpriseenrollment adfs fs sts
    cpanel whm plesk webdisk cpcalendars cpcontacts panel dashboard console manage manager management admin2
    administrator root secure2 ssl tls pki ca crl ocsp print printer scanner camera cam nvr dvr voip pbx
    asterisk tv iptv radio games game play partner partners vendor vendors supplier client clients customer
    customers affiliate dev-api api-dev api-staging api-test dev-www www2 www3 web web1 web2 host ns3 ns4
    """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
}
