import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Thin async wrapper over URLSession that exposes what recon tooling needs:
/// raw headers, redirect control, optional TLS-verification bypass (for inspecting broken certs).
public enum HTTP {
    public static let userAgent =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"

    public struct Response: Sendable {
        public var status: Int
        public var headers: [String: String]      // lower-cased names
        public var setCookies: [String]
        public var body: Data
        public var url: URL?
        public var elapsed: TimeInterval

        public var text: String {
            String(data: body, encoding: .utf8) ?? String(data: body, encoding: .isoLatin1) ?? ""
        }
    }

    private final class Delegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
        let follow: Bool
        let insecure: Bool
        init(follow: Bool, insecure: Bool) { self.follow = follow; self.insecure = insecure }

        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(follow ? request : nil)
        }

        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            #if !canImport(FoundationNetworking)
            if insecure,
               challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
               let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
            #endif
            completionHandler(.performDefaultHandling, nil)
        }
    }

    public static func request(_ url: URL,
                               method: String = "GET",
                               headers: [String: String] = [:],
                               body: Data? = nil,
                               timeout: TimeInterval = 15,
                               followRedirects: Bool = true,
                               maxBytes: Int = 4_000_000,
                               insecureTLS: Bool = false) async throws -> Response {
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: timeout)
        req.httpMethod = method
        req.httpBody = body
        req.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 2
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        let delegate = Delegate(follow: followRedirects, insecure: insecureTLS)
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let start = Date()
        return try await withCheckedThrowingContinuation { cont in
            let task = session.dataTask(with: req) { data, resp, err in
                if let err = err {
                    cont.resume(throwing: ReconError.network(err.localizedDescription))
                    return
                }
                guard let http = resp as? HTTPURLResponse else {
                    cont.resume(throwing: ReconError.network("no HTTP response"))
                    return
                }
                var headers: [String: String] = [:]
                for (k, v) in http.allHeaderFields {
                    headers[String(describing: k).lowercased()] = String(describing: v)
                }
                let cookies = splitSetCookie(headers["set-cookie"])
                var payload = data ?? Data()
                if payload.count > maxBytes { payload = payload.prefix(maxBytes) }
                cont.resume(returning: Response(status: http.statusCode, headers: headers,
                                                setCookies: cookies, body: payload,
                                                url: http.url, elapsed: Date().timeIntervalSince(start)))
            }
            task.resume()
        }
    }

    /// GET and parse JSON; throws `.http` for non-2xx.
    public static func json(_ url: URL, headers: [String: String] = [:], timeout: TimeInterval = 15,
                            maxBytes: Int = 4_000_000) async throws -> Any {
        var h = headers
        if h["Accept"] == nil { h["Accept"] = "application/json" }
        let r = try await request(url, headers: h, timeout: timeout, maxBytes: maxBytes)
        guard (200..<300).contains(r.status) else { throw ReconError.http(r.status) }
        do { return try JSONSerialization.jsonObject(with: r.body) }
        catch { throw ReconError.parse("invalid JSON from \(url.host ?? "server")") }
    }

    /// Foundation folds multiple Set-Cookie headers into one comma-joined string; undo that
    /// without splitting on the comma inside `Expires=Wed, 21 Oct ...`.
    static func splitSetCookie(_ joined: String?) -> [String] {
        guard let joined = joined, !joined.isEmpty else { return [] }
        guard let re = try? NSRegularExpression(pattern: ",\\s*(?=[A-Za-z0-9_\\-\\.]+=)") else { return [joined] }
        let ns = joined as NSString
        let marked = re.stringByReplacingMatches(in: joined, range: NSRange(location: 0, length: ns.length),
                                                 withTemplate: "\u{1}")
        return marked.split(separator: "\u{1}").map { String($0).trimmed() }
    }

    public static func url(_ s: String) throws -> URL {
        guard let u = URL(string: s) else { throw ReconError.invalidInput("bad URL \(s)") }
        return u
    }

    /// Percent-encode a query value.
    public static func q(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? s
    }
}

extension CharacterSet {
    static let urlQueryValueAllowed: CharacterSet = {
        var cs = CharacterSet.urlQueryAllowed
        cs.remove(charactersIn: "&+=?#/:@")
        return cs
    }()
}

// MARK: - Tiny JSON navigation helpers used by the OSINT parsers

extension Dictionary where Key == String, Value == Any {
    func str(_ k: String) -> String? {
        if let s = self[k] as? String { return s }
        if let n = self[k] as? NSNumber { return n.stringValue }
        return nil
    }
    func int(_ k: String) -> Int? { (self[k] as? NSNumber)?.intValue }
    func dict(_ k: String) -> [String: Any]? { self[k] as? [String: Any] }
    func arr(_ k: String) -> [Any]? { self[k] as? [Any] }
    func dicts(_ k: String) -> [[String: Any]] { (self[k] as? [Any])?.compactMap { $0 as? [String: Any] } ?? [] }
    func strs(_ k: String) -> [String] { (self[k] as? [Any])?.compactMap { $0 as? String } ?? [] }
}
