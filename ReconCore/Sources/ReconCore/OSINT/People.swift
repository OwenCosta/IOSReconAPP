import Foundation

// MARK: - Username search

public enum UsernameSearch {
    enum Detect {
        case status                       // 200 = exists, 404 = missing
        case bodyMissing(String)          // 200 but body contains marker when user is missing
        case bodyPresent(String)          // exists only if body contains marker
    }
    struct Site { let name: String; let url: String; let detect: Detect }

    static let sites: [Site] = [
        Site(name: "GitHub", url: "https://github.com/{}", detect: .status),
        Site(name: "GitLab", url: "https://gitlab.com/api/v4/users?username={}", detect: .bodyMissing("[]")),
        Site(name: "Bitbucket", url: "https://bitbucket.org/{}/", detect: .status),
        Site(name: "Reddit", url: "https://www.reddit.com/user/{}/about.json", detect: .status),
        Site(name: "Hacker News", url: "https://hacker-news.firebaseio.com/v0/user/{}.json", detect: .bodyMissing("null")),
        Site(name: "Keybase", url: "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", detect: .bodyMissing("\"them\":[null]")),
        Site(name: "npm", url: "https://registry.npmjs.org/-/user/org.couchdb.user:{}", detect: .status),
        Site(name: "PyPI", url: "https://pypi.org/user/{}/", detect: .status),
        Site(name: "Docker Hub", url: "https://hub.docker.com/v2/users/{}/", detect: .status),
        Site(name: "DEV Community", url: "https://dev.to/{}", detect: .status),
        Site(name: "Medium", url: "https://medium.com/@{}", detect: .status),
        Site(name: "Gravatar", url: "https://en.gravatar.com/{}.json", detect: .status),
        Site(name: "Steam", url: "https://steamcommunity.com/id/{}", detect: .bodyMissing("The specified profile could not be found")),
        Site(name: "Telegram", url: "https://t.me/{}", detect: .bodyPresent("tgme_page_title")),
        Site(name: "Pinterest", url: "https://www.pinterest.com/{}/", detect: .status),
        Site(name: "SoundCloud", url: "https://soundcloud.com/{}", detect: .status),
        Site(name: "Flickr", url: "https://www.flickr.com/people/{}/", detect: .status),
        Site(name: "About.me", url: "https://about.me/{}", detect: .status),
        Site(name: "Behance", url: "https://www.behance.net/{}", detect: .status),
        Site(name: "Dribbble", url: "https://dribbble.com/{}", detect: .status),
        Site(name: "CodePen", url: "https://codepen.io/{}", detect: .status),
        Site(name: "Replit", url: "https://replit.com/@{}", detect: .status),
        Site(name: "HackerOne", url: "https://hackerone.com/{}", detect: .status),
        Site(name: "Bugcrowd", url: "https://bugcrowd.com/{}", detect: .status),
        Site(name: "TryHackMe", url: "https://tryhackme.com/api/user/exist/{}", detect: .bodyPresent("\"success\":true")),
        Site(name: "Lichess", url: "https://lichess.org/api/user/{}", detect: .status),
        Site(name: "Chess.com", url: "https://api.chess.com/pub/player/{}", detect: .status),
        Site(name: "Vimeo", url: "https://vimeo.com/{}", detect: .status),
        Site(name: "Mastodon.social", url: "https://mastodon.social/@{}", detect: .status),
        Site(name: "YouTube", url: "https://www.youtube.com/@{}", detect: .status),
        Site(name: "Linktree", url: "https://linktr.ee/{}", detect: .status),
        Site(name: "Patreon", url: "https://www.patreon.com/{}", detect: .status),
        Site(name: "Wikipedia", url: "https://en.wikipedia.org/wiki/User:{}", detect: .status),
        Site(name: "Spotify", url: "https://open.spotify.com/user/{}", detect: .status),
        Site(name: "Last.fm", url: "https://www.last.fm/user/{}", detect: .status),
        Site(name: "Letterboxd", url: "https://letterboxd.com/{}/", detect: .status),
        Site(name: "Product Hunt", url: "https://www.producthunt.com/@{}", detect: .status),
        Site(name: "Kaggle", url: "https://www.kaggle.com/{}", detect: .status),
        Site(name: "Hugging Face", url: "https://huggingface.co/{}", detect: .status),
        Site(name: "Codeberg", url: "https://codeberg.org/{}", detect: .status)
    ]

    public static func validUsername(_ u: String) -> Bool {
        !u.isEmpty && u.count <= 40 && u.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." }
    }

    public static func run(_ username: String, ctx: ToolContext = .silent) async throws -> ToolOutput {
        let user = username.trimmed().replacingOccurrences(of: "@", with: "")
        guard validUsername(user) else { throw ReconError.invalidInput("username may only contain letters, digits, _ - .") }
        let counter = Counter()
        let total = sites.count
        let results = await boundedMap(sites, limit: 8) { site -> (Site, Bool?) in
            let n = counter.next()
            if n % 10 == 0 { ctx.log("Checked \(n)/\(total) sites…") }
            guard let url = URL(string: site.url.replacingOccurrences(of: "{}", with: HTTP.q(user))) else { return (site, nil) }
            guard let r = try? await HTTP.request(url, timeout: 10, followRedirects: true, maxBytes: 300_000) else { return (site, nil) }
            switch site.detect {
            case .status:
                if r.status == 200 { return (site, true) }
                if r.status == 404 || r.status == 410 { return (site, false) }
                return (site, nil)
            case .bodyMissing(let marker):
                guard r.status == 200 else { return (site, r.status == 404 ? false : nil) }
                let t = r.text.replacingOccurrences(of: " ", with: "")
                return (site, !t.contains(marker.replacingOccurrences(of: " ", with: "")))
            case .bodyPresent(let marker):
                guard r.status == 200 else { return (site, r.status == 404 ? false : nil) }
                return (site, r.text.replacingOccurrences(of: " ", with: "").contains(marker.replacingOccurrences(of: " ", with: "")))
            }
        }
        var found = ReportSection("Profiles found for “\(user)”",
                                  note: "Presence only means the handle is registered, not that it belongs to the same person. Verify manually.")
        var unknown = ReportSection("Could not determine")
        for (site, hit) in results.sorted(by: { $0.0.name < $1.0.name }) {
            let u = site.url.replacingOccurrences(of: "{}", with: user)
            if hit == true { found.add(site.name, u) } else if hit == nil { unknown.add(site.name, "blocked / rate-limited / error", .low) }
        }
        if found.items.isEmpty { found.add("Result", "no profiles detected on \(sites.count) sites") }
        var out = ToolOutput(sections: [found])
        if !unknown.items.isEmpty { out.sections.append(unknown) }
        return out
    }
}

// MARK: - Email OSINT

public enum EmailOSINT {
    static let disposable: Set<String> = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com",
                                         "trashmail.com", "sharklasers.com", "getnada.com", "throwawaymail.com", "dispostable.com",
                                         "maildrop.cc", "temp-mail.org", "fakeinbox.com", "mailnesia.com"]

    public static func validEmail(_ e: String) -> Bool {
        e.range(of: #"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"#, options: .regularExpression) != nil
    }

    public static func run(_ input: String, ctx: ToolContext) async throws -> ToolOutput {
        let email = input.trimmed().lowercased()
        guard validEmail(email) else { throw ReconError.invalidInput("not a valid email address") }
        let domain = String(email.split(separator: "@").last ?? "")
        let local = String(email.split(separator: "@").first ?? "")
        var out = ToolOutput()

        var basics = ReportSection("Email: \(email)")
        async let mx = DNSClient.records(domain, .MX)
        let mxs = await mx
        basics.add("Mail servers", mxs.isEmpty ? "none: address cannot receive mail" : mxs.map(\.data).joined(separator: "\n"), mxs.isEmpty ? .high : .info)
        if disposable.contains(domain) { basics.add("Disposable provider", "yes", .medium) }
        let free = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com"].contains(domain)
        basics.add("Provider type", free ? "free consumer mailbox" : "custom / corporate domain")
        out.sections.append(basics)

        // Gravatar
        if let hash = Digests.hex(.md5, email), let url = URL(string: "https://en.gravatar.com/\(hash).json"),
           let r = try? await HTTP.request(url, timeout: 10), r.status == 200,
           let o = (try? JSONSerialization.jsonObject(with: r.body)) as? [String: Any],
           let entry = o.dicts("entry").first {
            var g = ReportSection("Gravatar profile")
            if let n = entry.str("displayName") { g.add("Display name", n) }
            if let n = entry.dict("name")?.str("formatted") { g.add("Real name", n) }
            if let l = entry.str("currentLocation") { g.add("Location", l) }
            if let a = entry.str("aboutMe") { g.add("About", a) }
            g.add("Profile", entry.str("profileUrl") ?? "")
            g.add("Avatar", "https://gravatar.com/avatar/\(hash)")
            for acc in entry.dicts("accounts") { g.add(acc.str("shortname") ?? "account", acc.str("url") ?? "") }
            out.sections.append(g)
        }

        // EmailRep
        if let url = URL(string: "https://emailrep.io/\(HTTP.q(email))"), let r = try? await HTTP.request(url, headers: ["Accept": "application/json"], timeout: 12) {
            if r.status == 200, let o = (try? JSONSerialization.jsonObject(with: r.body)) as? [String: Any] {
                var s = ReportSection("EmailRep reputation")
                s.add("Reputation", o.str("reputation") ?? "unknown")
                if let sus = o["suspicious"] as? Bool { s.add("Suspicious", sus ? "yes" : "no", sus ? .medium : .info) }
                if let refs = o.int("references") { s.add("References seen", "\(refs)") }
                if let d = o.dict("details") {
                    for (k, label) in [("credentials_leaked", "Credentials leaked"), ("data_breach", "Appears in data breach"),
                                       ("malicious_activity", "Malicious activity"), ("blacklisted", "Blacklisted"),
                                       ("spam", "Spam"), ("disposable", "Disposable"), ("deliverable", "Deliverable")] {
                        if let v = d[k] as? Bool {
                            let bad = ["credentials_leaked", "data_breach", "malicious_activity", "blacklisted", "spam"].contains(k) && v
                            s.add(label, v ? "yes" : "no", bad ? .high : .info)
                        }
                    }
                    if let first = d.str("first_seen"), first != "never" { s.add("First seen", first) }
                    let profiles = d.strs("profiles")
                    if !profiles.isEmpty { s.add("Registered profiles", profiles.joined(separator: ", ")) }
                }
                out.sections.append(s)
            } else if r.status == 429 {
                out.sections.append(ReportSection("EmailRep reputation", items: [ReportItem("Status", "rate-limited (free tier), try again later", .low)]))
            }
        }

        // HIBP (needs user key)
        if let key = ctx.secrets.secret("hibp") {
            out.merge(await KeyedServices.hibpAccount(email, key: key))
        } else {
            out.sections.append(ReportSection("Breach lookup", items: [ReportItem("Have I Been Pwned", "add an API key in Settings to enable breach lookups for this address", .info)]))
        }

        var cand = ReportSection("Username candidates (feed into Username Search)")
        var cands = [local]
        if local.contains(".") { cands.append(local.replacingOccurrences(of: ".", with: "")); cands.append(local.replacingOccurrences(of: ".", with: "_")) }
        for c in Array(Set(cands)).sorted() { cand.add("", c) }
        out.sections.append(cand)
        return out
    }
}

// MARK: - GitHub OSINT

public enum GitHubOSINT {
    public static func run(_ input: String, ctx: ToolContext) async throws -> ToolOutput {
        let user = input.trimmed().replacingOccurrences(of: "@", with: "")
        guard UsernameSearch.validUsername(user) else { throw ReconError.invalidInput("bad GitHub username") }
        var headers = ["Accept": "application/vnd.github+json"]
        if let t = ctx.secrets.secret("github") { headers["Authorization"] = "Bearer \(t)" }

        let profileURL = try HTTP.url("https://api.github.com/users/\(user)")
        let p = try await HTTP.json(profileURL, headers: headers)
        guard let prof = p as? [String: Any] else { throw ReconError.parse("GitHub profile") }

        var out = ToolOutput()
        var s = ReportSection("GitHub: \(prof.str("login") ?? user)")
        for (k, label) in [("name", "Name"), ("company", "Company"), ("location", "Location"), ("email", "Public email"),
                           ("blog", "Website"), ("bio", "Bio"), ("twitter_username", "Twitter/X"), ("created_at", "Created"),
                           ("type", "Account type")] {
            if let v = prof.str(k), !v.isEmpty { s.add(label, v) }
        }
        s.add("Followers / following", "\(prof.int("followers") ?? 0) / \(prof.int("following") ?? 0)")
        s.add("Public repos / gists", "\(prof.int("public_repos") ?? 0) / \(prof.int("public_gists") ?? 0)")
        out.sections.append(s)

        // Emails leaked through commit metadata in public push events
        var emails: [String: Set<String>] = [:]
        if let ev = try? await HTTP.json(try HTTP.url("https://api.github.com/users/\(user)/events/public?per_page=100"), headers: headers),
           let events = ev as? [[String: Any]] {
            for e in events where e.str("type") == "PushEvent" {
                for c in (e.dict("payload")?.dicts("commits") ?? []) {
                    if let a = c.dict("author"), let mail = a.str("email"), !mail.isEmpty, !mail.hasSuffix("users.noreply.github.com") {
                        emails[mail, default: []].insert(a.str("name") ?? "")
                    }
                }
            }
        }
        var es = ReportSection("Emails exposed in public commits",
                               note: "Git commit metadata is public. Users can hide it with a noreply address.")
        for (mail, names) in emails.sorted(by: { $0.key < $1.key }) { es.add(mail, names.filter { !$0.isEmpty }.sorted().joined(separator: ", "), .low) }
        if emails.isEmpty { es.add("Result", "none in recent public events") }
        else { out.findings.append(Finding(.low, "GitHub user \(user) exposes \(emails.count) email address(es) in commits", emails.keys.sorted().joined(separator: ", "), source: "github")) }
        out.sections.append(es)

        if let repos = try? await HTTP.json(try HTTP.url("https://api.github.com/users/\(user)/repos?per_page=100&sort=pushed"), headers: headers),
           let list = repos as? [[String: Any]] {
            var rs = ReportSection("Recently pushed repositories (\(list.count))")
            var langs: [String: Int] = [:]
            for r in list.prefix(40) {
                let lang = r.str("language") ?? "unknown"
                langs[lang, default: 0] += 1
                rs.add(r.str("name") ?? "", "\(lang) · ★\(r.int("stargazers_count") ?? 0) · pushed \(r.str("pushed_at") ?? "")" +
                       ((r["fork"] as? Bool) == true ? " · fork" : ""))
            }
            out.sections.append(rs)
        }
        return out
    }
}
