using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ServerStatusApp;

public sealed class NetworkEngine
{
    private const string UserAgent = "ServerStatusDesktop/1.0";
    private static readonly HttpClient Http = CreateHttpClient();
    private static readonly SemaphoreSlim TorCacheLock = new(1, 1);
    private static HashSet<string>? _torExitCache;
    private static DateTimeOffset _torExitCacheAt;

    private static readonly IReadOnlyDictionary<int, string> CommonPorts = new Dictionary<int, string>
    {
        [21] = "FTP",
        [22] = "SSH",
        [25] = "SMTP",
        [53] = "DNS",
        [80] = "HTTP",
        [110] = "POP3",
        [143] = "IMAP",
        [443] = "HTTPS",
        [465] = "SMTPS",
        [587] = "SMTP submission",
        [993] = "IMAPS",
        [995] = "POP3S",
        [25565] = "Minecraft Java",
        [3306] = "MySQL",
        [5432] = "PostgreSQL",
        [6379] = "Redis",
        [8080] = "HTTP alt",
        [8443] = "HTTPS alt"
    };

    private static readonly IReadOnlyDictionary<int, string> ExtendedPorts = new Dictionary<int, string>(CommonPorts)
    {
        [20] = "FTP data",
        [23] = "Telnet",
        [81] = "HTTP alt",
        [111] = "RPC",
        [135] = "MS RPC",
        [139] = "NetBIOS",
        [389] = "LDAP",
        [445] = "SMB",
        [636] = "LDAPS",
        [1433] = "Microsoft SQL Server",
        [1521] = "Oracle DB",
        [1883] = "MQTT",
        [2375] = "Docker",
        [2376] = "Docker TLS",
        [3000] = "Web app",
        [3001] = "Web app alt",
        [3389] = "RDP",
        [5000] = "Web app",
        [5672] = "AMQP",
        [5900] = "VNC",
        [8000] = "HTTP alt",
        [8008] = "HTTP alt",
        [8081] = "HTTP alt",
        [8888] = "HTTP alt",
        [9000] = "App service",
        [9090] = "App service",
        [9200] = "Elasticsearch",
        [10000] = "Web admin",
        [11211] = "Memcached",
        [27017] = "MongoDB"
    };

    public async Task<JsonObject> LookupAsync(string input, bool ipOnly, AppSettings settings, CancellationToken ct, IProgress<LookupUpdate>? progress = null)
    {
        var started = Stopwatch.StartNew();
        var target = ParseTarget(input, ipOnly);
        progress?.Report(new LookupUpdate("meta", null, "Resolving public addresses"));

        var resolvedTask = ResolvePublicAsync(target.Host, ct);
        var dnsTask = GatherDnsAsync(target.Host, ct);
        var domainRdapTask = target.IsIp ? Task.FromResult<JsonObject?>(null) : FindDomainRdapAsync(target.Host, ct);
        var webTask = ProbeHttpAsync(target, ct);
        var tlsPort = target.ExplicitScheme && target.Port == 8443 ? 8443 : 443;
        var tlsTask = ProbeTlsAsync(target.Host, tlsPort, ct);

        var resolved = await resolvedTask;
        var primary = resolved.FirstOrDefault()?.ToString() ?? throw new InvalidOperationException("Target did not resolve to a public IP address.");

        var ipRdapTask = LookupIpRdapAsync(primary, ct);
        var ipIntelTask = BuildIpIntelAsync(primary, settings, ipRdapTask, ct);
        var routingTask = BuildRoutingAsync(primary, settings.DeepRouting, ct);
        var serviceTask = ScanServicesAsync(primary, settings.ScanMode, settings.ScanTimeoutMs, ct);
        var networkTask = BuildNetworkMeasurementsAsync(primary, settings.DeepRouting, ct);
        var reputationTask = BuildReputationAsync(primary, settings, ct);
        var minecraftTask = settings.MinecraftEnabled ? MinecraftLookupAsync(MinecraftAddress(target), ct) : Task.FromResult<JsonObject?>(new JsonObject { ["address"] = MinecraftAddress(target), ["skipped"] = true, ["cacheNote"] = "Disabled" });

        var dns = await dnsTask;
        progress?.Report(new LookupUpdate("dns", dns, "DNS complete"));

        var webProbe = await webTask;
        var web = webProbe.Report;
        progress?.Report(new LookupUpdate("web", web, web is null ? "HTTP probe returned no response" : "HTTP complete"));

        var tls = await tlsTask;
        progress?.Report(new LookupUpdate("tls", tls, tls?["available"]?.GetValue<bool>() == true ? "TLS complete" : "TLS probe finished"));

        var domainRdap = await domainRdapTask;
        var rootDomain = domainRdap?["rootDomain"]?.GetValue<string>();
        var emailTask = string.IsNullOrWhiteSpace(rootDomain) ? Task.FromResult<JsonObject?>(null) : EmailDnsAsync(rootDomain!, ct);
        var resourcesTask = webProbe.FinalUrl is null ? Task.FromResult<JsonObject?>(null) : ProbeSiteResourcesAsync(webProbe.FinalUrl, ct);

        var ipRdap = await ipRdapTask;
        var ipIntel = await ipIntelTask;
        progress?.Report(new LookupUpdate("ipIntel", ipIntel, "IP intelligence complete"));

        var routing = await routingTask;
        progress?.Report(new LookupUpdate("routing", routing, "Routing intelligence complete"));

        var network = await networkTask;
        network["resolvedAddresses"] = AddressesToArray(resolved);
        network["primaryIp"] = primary;
        network["ipRegistration"] = ipRdap?.DeepClone();
        progress?.Report(new LookupUpdate("network", network, "Network measurements complete"));

        var serviceScan = await serviceTask;
        progress?.Report(new LookupUpdate("serviceScan", serviceScan, "Service scan complete"));

        var reputation = await reputationTask;
        progress?.Report(new LookupUpdate("reputation", reputation, "Reputation checks complete"));

        var minecraft = await minecraftTask;
        progress?.Report(new LookupUpdate("minecraft", minecraft, "Minecraft check complete"));

        var email = await emailTask;
        progress?.Report(new LookupUpdate("email", email, "Mail DNS complete"));

        var resources = await resourcesTask;
        progress?.Report(new LookupUpdate("resources", resources, "Site file probes complete"));

        var headers = webProbe.Headers;
        var technologies = web is null ? new JsonArray() : DetectTechnology(headers, webProbe.Body);
        var edge = DetectEdge(headers, ipIntel, dns);
        var security = web is null ? null : AnalyzeSecurity(headers);
        var infrastructure = BuildInfrastructure(ipIntel, ipRdap, dns, email, web, edge, technologies);
        var registration = BuildRegistration(domainRdap, ipRdap);
        var dnssec = BuildDnssecSummary(dns);
        var summary = BuildSummary(target, primary, dns, web, tls, edge, infrastructure, serviceScan, ipIntel, registration, minecraft, dnssec);

        var result = new JsonObject
        {
            ["meta"] = new JsonObject
            {
                ["product"] = "ServerStatus",
                ["requestedTarget"] = input,
                ["normalizedHost"] = target.Host,
                ["rootDomain"] = rootDomain,
                ["generatedAt"] = DateTimeOffset.UtcNow.ToString("O"),
                ["durationMs"] = started.ElapsedMilliseconds,
                ["engine"] = "DNS + HTTP + TLS + RDAP + RIPEstat + TCP services + IP intelligence + Minecraft"
            },
            ["summary"] = summary,
            ["web"] = web?.DeepClone(),
            ["edge"] = edge,
            ["tls"] = tls?.DeepClone(),
            ["dns"] = dns.DeepClone(),
            ["dnssec"] = dnssec,
            ["network"] = network.DeepClone(),
            ["routing"] = routing.DeepClone(),
            ["ipIntel"] = ipIntel.DeepClone(),
            ["infrastructure"] = infrastructure,
            ["serviceScan"] = serviceScan.DeepClone(),
            ["reputation"] = reputation.DeepClone(),
            ["registration"] = registration,
            ["email"] = email?.DeepClone(),
            ["security"] = security,
            ["technologies"] = technologies,
            ["resources"] = resources?.DeepClone(),
            ["minecraft"] = minecraft?.DeepClone()
        };

        progress?.Report(new LookupUpdate("summary", summary, "Building report"));
        progress?.Report(new LookupUpdate("infrastructure", infrastructure, "Infrastructure classified"));
        progress?.Report(new LookupUpdate("edge", edge, "Edge detection complete"));
        if (security is not null) progress?.Report(new LookupUpdate("security", security, "Security header analysis complete"));
        progress?.Report(new LookupUpdate("technologies", technologies, "Technology fingerprinting complete"));
        progress?.Report(new LookupUpdate("registration", registration, "Registration records complete"));
        return result;
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(4),
            MaxConnectionsPerServer = 32
        };
        var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json,text/plain,*/*");
        return client;
    }

    private sealed record TargetInfo(string Raw, string Host, int Port, string Scheme, string Path, bool ExplicitScheme, string Url, bool IsIp, int? RequestedPort);
    private sealed record HttpOne(JsonObject Report, string Body, string Url, JsonObject Headers, int Status, string? Location);
    private sealed record WebProbe(JsonObject? Report, string Body, string? FinalUrl, JsonObject Headers);

    private static TargetInfo ParseTarget(string input, bool ipOnly)
    {
        var raw = input.Trim();
        if (raw.Length == 0) throw new ArgumentException("Enter a hostname, IP address or URL.");
        if (raw.Length > 300) throw new ArgumentException("Target is too long.");

        if (ipOnly)
        {
            if (!IPAddress.TryParse(raw.Trim('[', ']'), out var parsedIp) || !IsPublicIp(parsedIp))
                throw new ArgumentException("IP mode requires a public IPv4 or IPv6 address.");
            var ipHost = parsedIp.ToString();
            var bracketed = parsedIp.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{ipHost}]" : ipHost;
            return new TargetInfo(raw, ipHost, 443, "https", "/", false, $"https://{bracketed}/", true, null);
        }

        var explicitScheme = Regex.IsMatch(raw, "^https?://", RegexOptions.IgnoreCase);
        if (explicitScheme)
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) || string.IsNullOrWhiteSpace(uri.Host))
                throw new ArgumentException("That target is not a valid HTTP or HTTPS URL.");
            var port = uri.IsDefaultPort ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80) : uri.Port;
            if (port is not 80 and not 443 and not 8080 and not 8443)
                throw new ArgumentException("HTTP lookups are limited to ports 80, 443, 8080 and 8443.");
            ValidateHostname(uri.Host);
            var isIp = IPAddress.TryParse(uri.Host, out var ip);
            if (isIp && !IsPublicIp(ip!)) throw new ArgumentException("Private, local and reserved IP ranges are not allowed.");
            return new TargetInfo(raw, uri.Host.TrimEnd('.').ToLowerInvariant(), port, uri.Scheme, string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery, true, uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped), isIp, port);
        }

        var authority = raw.Split('/', 2)[0].Trim();
        string host;
        int? requestedPort = null;
        if (authority.StartsWith('['))
        {
            var end = authority.IndexOf(']');
            if (end < 0) throw new ArgumentException("Invalid IPv6 target.");
            host = authority[1..end];
            if (end + 1 < authority.Length && authority[end + 1] == ':' && int.TryParse(authority[(end + 2)..], out var p)) requestedPort = p;
        }
        else if (authority.Count(c => c == ':') == 1)
        {
            var split = authority.LastIndexOf(':');
            if (split > 0 && int.TryParse(authority[(split + 1)..], out var p))
            {
                host = authority[..split];
                requestedPort = p;
            }
            else host = authority;
        }
        else host = authority;

        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        ValidateHostname(host);
        var targetIsIp = IPAddress.TryParse(host, out var directIp);
        if (targetIsIp && !IsPublicIp(directIp!)) throw new ArgumentException("Private, local and reserved IP ranges are not allowed.");
        if (requestedPort is < 1 or > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
        var bracket = targetIsIp && directIp!.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]" : host;
        return new TargetInfo(raw, host, requestedPort ?? 443, "https", "/", false, $"https://{bracket}/", targetIsIp, requestedPort);
    }

    private static void ValidateHostname(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Target host is empty.");
        var h = host.TrimEnd('.').ToLowerInvariant();
        if (h == "localhost" || h.EndsWith(".localhost") || h.EndsWith(".local") || h.EndsWith(".internal") || h.EndsWith(".home") || h.EndsWith(".lan") || h.EndsWith(".test") || h.EndsWith(".invalid") || h.EndsWith(".example") || h == "metadata.google.internal")
            throw new ArgumentException("Private or local hostnames are not allowed.");
    }

    private static bool IsPublicIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] is >= 16 and <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 100 && b[1] is >= 64 and <= 127) return false;
            if (b[0] == 198 && b[1] is 18 or 19) return false;
            if (b[0] == 192 && b[1] == 0 && b[2] is 0 or 2) return false;
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
            return true;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal || ip.Equals(IPAddress.IPv6None)) return false;
            var b = ip.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return false;
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false;
            return true;
        }
        return false;
    }

    private static async Task<IPAddress[]> ResolvePublicAsync(string host, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var direct))
        {
            if (!IsPublicIp(direct)) throw new ArgumentException("Private, local and reserved IP ranges are not allowed.");
            return [direct];
        }
        ValidateHostname(host);
        var addresses = await Dns.GetHostAddressesAsync(host).WaitAsync(ct);
        if (addresses.Length == 0) throw new InvalidOperationException("Hostname did not resolve to an IP address.");
        if (addresses.Any(x => !IsPublicIp(x))) throw new InvalidOperationException("Hostname resolves to a private, local or reserved address.");
        return addresses.Distinct().ToArray();
    }

    private static JsonArray AddressesToArray(IEnumerable<IPAddress> addresses)
    {
        var arr = new JsonArray();
        foreach (var address in addresses)
            arr.Add(new JsonObject { ["address"] = address.ToString(), ["family"] = address.AddressFamily == AddressFamily.InterNetworkV6 ? 6 : 4 });
        return arr;
    }

    private static async Task<JsonNode?> FetchJsonAsync(string url, CancellationToken ct, IReadOnlyDictionary<string, string>? headers = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd(UserAgent);
        request.Headers.Accept.ParseAdd("application/json");
        if (headers is not null)
        {
            foreach (var pair in headers)
                request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        }
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            return new JsonObject { ["error"] = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}", ["status"] = (int)response.StatusCode, ["body"] = text.Length > 3000 ? text[..3000] : text };
        try
        {
            return JsonNode.Parse(text);
        }
        catch
        {
            return new JsonObject { ["raw"] = text };
        }
    }

    private static async Task<JsonNode?> SafeJsonAsync(string url, CancellationToken ct, IReadOnlyDictionary<string, string>? headers = null)
    {
        try
        {
            return await FetchJsonAsync(url, ct, headers);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new JsonObject { ["error"] = "Timed out" };
        }
        catch (Exception ex)
        {
            return new JsonObject { ["error"] = ex.Message };
        }
    }

    private static async Task<JsonObject> GatherDnsAsync(string host, CancellationToken ct)
    {
        var result = new JsonObject
        {
            ["a"] = new JsonArray(),
            ["aaaa"] = new JsonArray(),
            ["cname"] = new JsonArray(),
            ["mx"] = new JsonArray(),
            ["ns"] = new JsonArray(),
            ["txt"] = new JsonArray(),
            ["caa"] = new JsonArray(),
            ["soa"] = null,
            ["naptr"] = new JsonArray(),
            ["ptr"] = new JsonArray(),
            ["services"] = new JsonObject()
        };

        if (IPAddress.TryParse(host, out var directIp))
        {
            result["ptr"] = await DnsAnswersArrayAsync(ReversePointer(directIp), 12, ct);
            result["dnssec"] = new JsonObject { ["authenticatedData"] = false, ["note"] = "DNSSEC validation is not applicable to a direct IP target in this view." };
            return result;
        }

        var tasks = new Dictionary<string, Task<JsonObject>>
        {
            ["a"] = DnsQueryAsync(host, 1, ct),
            ["aaaa"] = DnsQueryAsync(host, 28, ct),
            ["cname"] = DnsQueryAsync(host, 5, ct),
            ["mx"] = DnsQueryAsync(host, 15, ct),
            ["ns"] = DnsQueryAsync(host, 2, ct),
            ["txt"] = DnsQueryAsync(host, 16, ct),
            ["caa"] = DnsQueryAsync(host, 257, ct),
            ["soa"] = DnsQueryAsync(host, 6, ct),
            ["naptr"] = DnsQueryAsync(host, 35, ct)
        };
        await Task.WhenAll(tasks.Values);

        result["a"] = AnswerStrings(tasks["a"].Result, 1);
        result["aaaa"] = AnswerStrings(tasks["aaaa"].Result, 28);
        result["cname"] = StripDotArray(AnswerStrings(tasks["cname"].Result, 5));
        result["ns"] = StripDotArray(AnswerStrings(tasks["ns"].Result, 2));
        result["txt"] = ParseTxtArray(AnswerStrings(tasks["txt"].Result, 16));
        result["mx"] = ParseMxArray(AnswerStrings(tasks["mx"].Result, 15));
        result["caa"] = ParseCaaArray(AnswerStrings(tasks["caa"].Result, 257));
        var soaRaw = AnswerStrings(tasks["soa"].Result, 6);
        result["soa"] = soaRaw.Count > 0 ? ParseSoa(soaRaw[0]?.GetValue<string>() ?? "") : null;
        result["naptr"] = AnswerStrings(tasks["naptr"].Result, 35);
        result["dnssec"] = new JsonObject
        {
            ["status"] = GetLong(tasks["a"].Result["Status"]),
            ["authenticatedData"] = GetBool(tasks["a"].Result["AD"]),
            ["checkingDisabled"] = GetBool(tasks["a"].Result["CD"]),
            ["truncated"] = GetBool(tasks["a"].Result["TC"]),
            ["comment"] = GetString(tasks["a"].Result["Comment"])
        };

        var servicePrefixes = new[] { "_minecraft._tcp", "_minecraft._udp", "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp" };
        var serviceTasks = servicePrefixes.ToDictionary(x => x, x => DnsQueryAsync($"{x}.{host}", 33, ct));
        await Task.WhenAll(serviceTasks.Values);
        var serviceObj = new JsonObject();
        foreach (var pair in serviceTasks)
        {
            var rows = ParseSrvArray(AnswerStrings(pair.Value.Result, 33));
            if (rows.Count > 0) serviceObj[pair.Key] = rows;
        }
        result["services"] = serviceObj;

        var first = (result["a"] as JsonArray)?.FirstOrDefault()?.GetValue<string>() ?? (result["aaaa"] as JsonArray)?.FirstOrDefault()?.GetValue<string>();
        if (first is not null && IPAddress.TryParse(first, out var ip))
            result["ptr"] = await DnsAnswersArrayAsync(ReversePointer(ip), 12, ct);
        return result;
    }

    private static async Task<JsonObject> DnsQueryAsync(string name, int type, CancellationToken ct)
    {
        var url = $"https://dns.google/resolve?name={Uri.EscapeDataString(name)}&type={type}&do=1";
        var node = await SafeJsonAsync(url, ct);
        return node as JsonObject ?? new JsonObject { ["error"] = "No DNS response" };
    }

    private static JsonArray AnswerStrings(JsonObject response, int type)
    {
        var arr = new JsonArray();
        if (response["Answer"] is not JsonArray answers) return arr;
        foreach (var item in answers.OfType<JsonObject>())
        {
            if (GetLong(item["type"]) == type && GetString(item["data"]) is { } data) arr.Add(data);
        }
        return arr;
    }

    private static async Task<JsonArray> DnsAnswersArrayAsync(string name, int type, CancellationToken ct)
    {
        return AnswerStrings(await DnsQueryAsync(name, type, ct), type);
    }

    private static JsonArray StripDotArray(JsonArray input)
    {
        var arr = new JsonArray();
        foreach (var item in input)
        {
            var s = GetString(item);
            if (s is not null) arr.Add(s.TrimEnd('.'));
        }
        return arr;
    }

    private static JsonArray ParseTxtArray(JsonArray input)
    {
        var arr = new JsonArray();
        foreach (var item in input)
        {
            var s = GetString(item) ?? "";
            var matches = Regex.Matches(s, "\"((?:\\\\.|[^\"\\\\])*)\"");
            if (matches.Count > 0)
            {
                var sb = new StringBuilder();
                foreach (Match match in matches) sb.Append(match.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\"));
                arr.Add(sb.ToString());
            }
            else arr.Add(s);
        }
        return arr;
    }

    private static JsonArray ParseMxArray(JsonArray input)
    {
        var rows = new List<JsonObject>();
        foreach (var item in input)
        {
            var parts = (GetString(item) ?? "").Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && int.TryParse(parts[0], out var priority))
                rows.Add(new JsonObject { ["priority"] = priority, ["exchange"] = parts[1].TrimEnd('.') });
        }
        var arr = new JsonArray();
        foreach (var row in rows.OrderBy(x => x["priority"]?.GetValue<int>() ?? 0)) arr.Add(row);
        return arr;
    }

    private static JsonArray ParseSrvArray(JsonArray input)
    {
        var arr = new JsonArray();
        foreach (var item in input)
        {
            var parts = (GetString(item) ?? "").Split(' ', 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 4 && int.TryParse(parts[0], out var priority) && int.TryParse(parts[1], out var weight) && int.TryParse(parts[2], out var port))
                arr.Add(new JsonObject { ["priority"] = priority, ["weight"] = weight, ["port"] = port, ["name"] = parts[3].TrimEnd('.') });
        }
        return arr;
    }

    private static JsonArray ParseCaaArray(JsonArray input)
    {
        var arr = new JsonArray();
        foreach (var item in input)
        {
            var s = GetString(item) ?? "";
            var match = Regex.Match(s, "^(\\d+)\\s+(\\S+)\\s+\"?(.*?)\"?$");
            if (match.Success)
                arr.Add(new JsonObject { ["critical"] = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture), ["tag"] = match.Groups[2].Value, ["value"] = match.Groups[3].Value.Trim('"') });
            else arr.Add(new JsonObject { ["raw"] = s });
        }
        return arr;
    }

    private static JsonObject ParseSoa(string value)
    {
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 7) return new JsonObject { ["raw"] = value };
        return new JsonObject
        {
            ["nsname"] = parts[0].TrimEnd('.'),
            ["hostmaster"] = parts[1].TrimEnd('.'),
            ["serial"] = ParseNumberOrString(parts[2]),
            ["refresh"] = ParseNumberOrString(parts[3]),
            ["retry"] = ParseNumberOrString(parts[4]),
            ["expire"] = ParseNumberOrString(parts[5]),
            ["minttl"] = ParseNumberOrString(parts[6])
        };
    }

    private static JsonNode ParseNumberOrString(string value) => long.TryParse(value, out var n) ? JsonValue.Create(n)! : JsonValue.Create(value)!;

    private static string ReversePointer(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return string.Join('.', ip.GetAddressBytes().Reverse()) + ".in-addr.arpa";
        var hex = Convert.ToHexString(ip.GetAddressBytes()).ToLowerInvariant();
        return string.Join('.', hex.Reverse()) + ".ip6.arpa";
    }

    private static async Task<JsonObject?> FindDomainRdapAsync(string host, CancellationToken ct)
    {
        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (var count = 2; count <= Math.Min(labels.Length, 5); count++)
        {
            var candidate = string.Join('.', labels[^count..]);
            var raw = await SafeJsonAsync($"https://rdap.org/domain/{Uri.EscapeDataString(candidate)}", ct);
            if (raw is JsonObject obj && string.IsNullOrWhiteSpace(GetString(obj["error"])))
            {
                var parsed = ParseDomainRdap(obj);
                if (!string.IsNullOrWhiteSpace(GetString(parsed["ldhName"])))
                {
                    return new JsonObject { ["rootDomain"] = GetString(parsed["ldhName"])?.ToLowerInvariant(), ["data"] = parsed };
                }
            }
        }
        return new JsonObject { ["rootDomain"] = labels.Length >= 2 ? string.Join('.', labels[^2..]) : host, ["data"] = null };
    }

    private static JsonObject ParseDomainRdap(JsonObject raw)
    {
        string? registrar = null;
        if (raw["entities"] is JsonArray entities)
        {
            foreach (var entity in entities.OfType<JsonObject>())
            {
                if (StringArray(entity["roles"]).Any(x => x.Equals("registrar", StringComparison.OrdinalIgnoreCase)))
                {
                    registrar = EntityName(entity);
                    break;
                }
            }
        }
        var nameservers = new JsonArray();
        if (raw["nameservers"] is JsonArray ns)
        {
            foreach (var item in ns.OfType<JsonObject>())
            {
                var name = GetString(item["ldhName"]) ?? GetString(item["unicodeName"]);
                if (name is not null) nameservers.Add(name);
            }
        }
        return new JsonObject
        {
            ["handle"] = GetString(raw["handle"]),
            ["ldhName"] = GetString(raw["ldhName"]),
            ["unicodeName"] = GetString(raw["unicodeName"]),
            ["status"] = raw["status"]?.DeepClone(),
            ["registrar"] = registrar,
            ["events"] = RdapEvents(raw),
            ["nameservers"] = nameservers,
            ["secureDns"] = raw["secureDNS"]?.DeepClone(),
            ["notices"] = raw["notices"]?.DeepClone(),
            ["raw"] = raw.DeepClone()
        };
    }

    private static async Task<JsonObject?> LookupIpRdapAsync(string ip, CancellationToken ct)
    {
        var raw = await SafeJsonAsync($"https://rdap.org/ip/{Uri.EscapeDataString(ip)}", ct);
        if (raw is not JsonObject obj) return null;
        if (!string.IsNullOrWhiteSpace(GetString(obj["error"]))) return obj;
        var entities = new JsonArray();
        if (obj["entities"] is JsonArray rawEntities)
        {
            foreach (var entity in rawEntities.OfType<JsonObject>())
            {
                entities.Add(new JsonObject { ["name"] = EntityName(entity), ["handle"] = GetString(entity["handle"]), ["roles"] = entity["roles"]?.DeepClone(), ["vcard"] = entity["vcardArray"]?.DeepClone() });
            }
        }
        return new JsonObject
        {
            ["handle"] = GetString(obj["handle"]),
            ["name"] = GetString(obj["name"]),
            ["type"] = GetString(obj["type"]),
            ["startAddress"] = GetString(obj["startAddress"]),
            ["endAddress"] = GetString(obj["endAddress"]),
            ["ipVersion"] = GetString(obj["ipVersion"]),
            ["country"] = GetString(obj["country"]),
            ["parentHandle"] = GetString(obj["parentHandle"]),
            ["status"] = obj["status"]?.DeepClone(),
            ["events"] = RdapEvents(obj),
            ["entities"] = entities,
            ["remarks"] = obj["remarks"]?.DeepClone(),
            ["notices"] = obj["notices"]?.DeepClone(),
            ["links"] = obj["links"]?.DeepClone(),
            ["raw"] = obj.DeepClone()
        };
    }

    private static string? EntityName(JsonObject entity)
    {
        if (entity["vcardArray"] is JsonArray vcard && vcard.Count > 1 && vcard[1] is JsonArray rows)
        {
            foreach (var row in rows.OfType<JsonArray>())
            {
                if (row.Count > 3 && GetString(row[0]) == "fn") return GetString(row[3]);
            }
        }
        return GetString(entity["handle"]);
    }

    private static JsonObject RdapEvents(JsonObject raw)
    {
        var events = new JsonObject();
        if (raw["events"] is not JsonArray arr) return events;
        foreach (var item in arr.OfType<JsonObject>())
        {
            var action = GetString(item["eventAction"]);
            var date = GetString(item["eventDate"]);
            if (action is not null && date is not null) events[action] = date;
        }
        return events;
    }

    private static async Task<WebProbe> ProbeHttpAsync(TargetInfo target, CancellationToken ct)
    {
        var candidates = new List<string>();
        if (target.ExplicitScheme) candidates.Add(target.Url);
        else
        {
            var bracketed = IPAddress.TryParse(target.Host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{target.Host}]" : target.Host;
            candidates.Add($"https://{bracketed}/");
            candidates.Add($"http://{bracketed}/");
        }

        Exception? last = null;
        foreach (var candidate in candidates)
        {
            try
            {
                var current = candidate;
                var chain = new JsonArray();
                HttpOne? final = null;
                for (var i = 0; i < 8; i++)
                {
                    var one = await RequestHttpOnceAsync(current, ct);
                    chain.Add(new JsonObject { ["url"] = one.Url, ["status"] = one.Status, ["location"] = one.Location, ["ttfbMs"] = one.Report["timings"]?["ttfbMs"]?.DeepClone() });
                    if (one.Status is 301 or 302 or 303 or 307 or 308 && !string.IsNullOrWhiteSpace(one.Location))
                    {
                        var next = new Uri(new Uri(current), one.Location!);
                        ValidateWebUri(next);
                        await ResolvePublicAsync(next.Host, ct);
                        current = next.ToString();
                        continue;
                    }
                    final = one;
                    break;
                }
                final ??= await RequestHttpOnceAsync(current, ct);
                var page = final.Report["page"] as JsonObject ?? new JsonObject();
                var report = new JsonObject
                {
                    ["finalUrl"] = final.Url,
                    ["status"] = final.Status,
                    ["statusMessage"] = GetString(final.Report["statusMessage"]),
                    ["httpVersion"] = GetString(final.Report["httpVersion"]),
                    ["remoteAddress"] = GetString(final.Report["remoteAddress"]),
                    ["remotePort"] = final.Report["remotePort"]?.DeepClone(),
                    ["timings"] = final.Report["timings"]?.DeepClone(),
                    ["redirects"] = chain,
                    ["headers"] = final.Headers.DeepClone(),
                    ["page"] = page.DeepClone()
                };
                return new WebProbe(report, final.Body, final.Url, final.Headers);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                last = ex;
            }
        }
        return new WebProbe(null, "", null, new JsonObject { ["error"] = last?.Message ?? "HTTP probe failed" });
    }

    private static async Task<HttpOne> RequestHttpOnceAsync(string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) throw new InvalidOperationException("Invalid HTTP URL.");
        ValidateWebUri(uri);
        var dnsWatch = Stopwatch.StartNew();
        var addresses = await ResolvePublicAsync(uri.Host, ct);
        dnsWatch.Stop();
        var chosen = addresses[0];
        var port = uri.IsDefaultPort ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80) : uri.Port;
        var tcpMs = await MeasureTcpConnectAsync(chosen, port, 3000, ct);

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd(UserAgent);
        request.Headers.Accept.ParseAdd("text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5");
        request.Headers.ConnectionClose = true;
        var watch = Stopwatch.StartNew();
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        var ttfb = watch.ElapsedMilliseconds;
        var bytes = await ReadAtMostAsync(await response.Content.ReadAsStreamAsync(ct), 650000, ct);
        watch.Stop();
        var body = DecodeBody(bytes, response.Content.Headers.ContentType?.CharSet);
        var headers = CollectHeaders(response);
        var page = BuildPageMetadata(headers, body, bytes.Length);
        var report = new JsonObject
        {
            ["status"] = (int)response.StatusCode,
            ["statusMessage"] = response.ReasonPhrase,
            ["httpVersion"] = response.Version.ToString(),
            ["remoteAddress"] = chosen.ToString(),
            ["remotePort"] = port,
            ["timings"] = new JsonObject
            {
                ["dnsMs"] = dnsWatch.ElapsedMilliseconds,
                ["tcpMs"] = tcpMs,
                ["ttfbMs"] = ttfb,
                ["totalMs"] = watch.ElapsedMilliseconds
            },
            ["page"] = page
        };
        return new HttpOne(report, body, uri.ToString(), headers, (int)response.StatusCode, response.Headers.Location?.ToString());
    }

    private static void ValidateWebUri(Uri uri)
    {
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) throw new InvalidOperationException("Unsupported redirect scheme.");
        var port = uri.IsDefaultPort ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80) : uri.Port;
        if (port is not 80 and not 443 and not 8080 and not 8443) throw new InvalidOperationException("HTTP probe redirected to a disallowed port.");
        ValidateHostname(uri.Host);
    }

    private static async Task<long?> MeasureTcpConnectAsync(IPAddress address, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            var watch = Stopwatch.StartNew();
            await client.ConnectAsync(address, port, linked.Token);
            watch.Stop();
            return watch.ElapsedMilliseconds;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<byte[]> ReadAtMostAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        using var ms = new MemoryStream(Math.Min(maxBytes, 65536));
        var buffer = new byte[16384];
        while (ms.Length < maxBytes)
        {
            var remaining = maxBytes - (int)ms.Length;
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), ct);
            if (read <= 0) break;
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
    }

    private static string DecodeBody(byte[] bytes, string? charset)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(charset)) return Encoding.GetEncoding(charset.Trim('"')).GetString(bytes);
        }
        catch
        {
        }
        return Encoding.UTF8.GetString(bytes);
    }

    private static JsonObject CollectHeaders(HttpResponseMessage response)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
        {
            if (!map.TryGetValue(header.Key, out var list)) map[header.Key] = list = [];
            list.AddRange(header.Value);
        }
        foreach (var header in response.Content.Headers)
        {
            if (!map.TryGetValue(header.Key, out var list)) map[header.Key] = list = [];
            list.AddRange(header.Value);
        }
        var obj = new JsonObject();
        foreach (var pair in map)
        {
            var key = pair.Key.ToLowerInvariant();
            if (key == "set-cookie")
            {
                var arr = new JsonArray();
                foreach (var value in pair.Value) arr.Add(value);
                obj[key] = arr;
            }
            else obj[key] = string.Join(", ", pair.Value);
        }
        return obj;
    }

    private static JsonObject BuildPageMetadata(JsonObject headers, string body, int bytesRead)
    {
        var contentType = Header(headers, "content-type");
        var title = Regex.Match(body, "<title[^>]*>([\\s\\S]*?)</title>", RegexOptions.IgnoreCase);
        var language = Regex.Match(body, "<html[^>]+lang=[\"']([^\"']+)", RegexOptions.IgnoreCase);
        var charset = Regex.Match(body, "<meta[^>]+charset=[\"']?([^\\s\"'/>]+)", RegexOptions.IgnoreCase);
        var description = ExtractMeta(body, "description");
        var generator = ExtractMeta(body, "generator");
        var clockSkew = ParseHttpDateSkew(Header(headers, "date"));
        return new JsonObject
        {
            ["title"] = title.Success ? Regex.Replace(WebUtility.HtmlDecode(title.Groups[1].Value), "\\s+", " ").Trim()[..Math.Min(240, Regex.Replace(WebUtility.HtmlDecode(title.Groups[1].Value), "\\s+", " ").Trim().Length)] : null,
            ["description"] = description,
            ["generator"] = generator,
            ["contentType"] = contentType,
            ["contentLengthHeader"] = Header(headers, "content-length"),
            ["bytesSampled"] = bytesRead,
            ["language"] = language.Success ? language.Groups[1].Value : null,
            ["charset"] = charset.Success ? charset.Groups[1].Value : ParseCharset(contentType),
            ["clockSkewSeconds"] = clockSkew,
            ["http3Advertised"] = Regex.IsMatch(Header(headers, "alt-svc") ?? "", "\\bh3(?:-|=|\\b)", RegexOptions.IgnoreCase),
            ["compression"] = Header(headers, "content-encoding") ?? "none/identity",
            ["cacheControl"] = Header(headers, "cache-control"),
            ["age"] = Header(headers, "age"),
            ["etag"] = Header(headers, "etag"),
            ["lastModified"] = Header(headers, "last-modified"),
            ["serverTiming"] = Header(headers, "server-timing"),
            ["sampleSha256"] = body.Length == 0 ? null : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant(),
            ["headersSha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(headers.ToJsonString()))).ToLowerInvariant()
        };
    }

    private static string? ExtractMeta(string html, string name)
    {
        var escaped = Regex.Escape(name);
        var patterns = new[]
        {
            $"<meta[^>]+(?:name|property)=[\"']{escaped}[\"'][^>]+content=[\"']([^\"']+)[\"']",
            $"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+(?:name|property)=[\"']{escaped}[\"']"
        };
        foreach (var pattern in patterns)
        {
            var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase);
            if (match.Success) return WebUtility.HtmlDecode(match.Groups[1].Value.Trim());
        }
        return null;
    }

    private static string? ParseCharset(string? contentType)
    {
        if (contentType is null) return null;
        var match = Regex.Match(contentType, "charset=([^;\\s]+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static long? ParseHttpDateSkew(string? value)
    {
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
            return (long)Math.Round((parsed.ToUniversalTime() - DateTimeOffset.UtcNow).TotalSeconds);
        return null;
    }

    private static async Task<JsonObject?> ProbeTlsAsync(string host, int port, CancellationToken ct)
    {
        if (port is not 443 and not 8443) return new JsonObject { ["available"] = false, ["reason"] = "TLS detail probe is limited to ports 443 and 8443." };
        try
        {
            var address = (await ResolvePublicAsync(host, ct))[0];
            using var client = new TcpClient(address.AddressFamily);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(TimeSpan.FromSeconds(7));
            await client.ConnectAsync(address, port, linked.Token);
            SslPolicyErrors policyErrors = SslPolicyErrors.None;
            using var ssl = new SslStream(client.GetStream(), false, (_, _, _, errors) =>
            {
                policyErrors = errors;
                return true;
            });
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]
            };
            await ssl.AuthenticateAsClientAsync(options, linked.Token);
            if (ssl.RemoteCertificate is null) return new JsonObject { ["available"] = false, ["reason"] = "No certificate returned." };
            using var cert = new X509Certificate2(ssl.RemoteCertificate);
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            var chainValid = chain.Build(cert);
            var chainRows = new JsonArray();
            foreach (var element in chain.ChainElements)
            {
                chainRows.Add(new JsonObject
                {
                    ["subject"] = element.Certificate.Subject,
                    ["issuer"] = element.Certificate.Issuer,
                    ["thumbprint"] = element.Certificate.Thumbprint,
                    ["validFrom"] = element.Certificate.NotBefore.ToUniversalTime().ToString("O"),
                    ["validTo"] = element.Certificate.NotAfter.ToUniversalTime().ToString("O")
                });
            }
            var chainErrors = new JsonArray();
            foreach (var status in chain.ChainStatus) chainErrors.Add(status.StatusInformation.Trim());
            var alpn = ssl.NegotiatedApplicationProtocol.Protocol.Length > 0 ? Encoding.ASCII.GetString(ssl.NegotiatedApplicationProtocol.Protocol.Span) : null;
            var keyBits = cert.GetRSAPublicKey()?.KeySize ?? cert.GetECDsaPublicKey()?.KeySize;
            return new JsonObject
            {
                ["available"] = true,
                ["authorized"] = policyErrors == SslPolicyErrors.None && chainValid,
                ["policyErrors"] = policyErrors.ToString(),
                ["chainValid"] = chainValid,
                ["chainErrors"] = chainErrors,
                ["protocol"] = ssl.SslProtocol.ToString(),
                ["alpn"] = alpn,
                ["cipherSuite"] = ssl.NegotiatedCipherSuite.ToString(),
                ["cipherStrength"] = ssl.CipherStrength,
                ["hashStrength"] = ssl.HashStrength,
                ["keyExchangeStrength"] = ssl.KeyExchangeStrength,
                ["certificate"] = new JsonObject
                {
                    ["subject"] = cert.Subject,
                    ["issuer"] = cert.Issuer,
                    ["commonName"] = cert.GetNameInfo(X509NameType.DnsName, false),
                    ["subjectAltName"] = cert.Extensions["2.5.29.17"]?.Format(true),
                    ["validFrom"] = cert.NotBefore.ToUniversalTime().ToString("O"),
                    ["validTo"] = cert.NotAfter.ToUniversalTime().ToString("O"),
                    ["daysRemaining"] = Math.Floor((cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays),
                    ["serialNumber"] = cert.SerialNumber,
                    ["signatureAlgorithm"] = cert.SignatureAlgorithm.FriendlyName,
                    ["publicKeyAlgorithm"] = cert.PublicKey.Oid.FriendlyName,
                    ["publicKeyBits"] = keyBits,
                    ["fingerprintSha1"] = FormatHex(SHA1.HashData(cert.RawData)),
                    ["fingerprintSha256"] = FormatHex(SHA256.HashData(cert.RawData))
                },
                ["chain"] = chainRows
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new JsonObject { ["available"] = false, ["reason"] = ex.Message };
        }
    }

    private static string FormatHex(byte[] bytes) => string.Join(':', bytes.Select(x => x.ToString("X2", CultureInfo.InvariantCulture)));

    private static async Task<JsonObject> BuildIpIntelAsync(string ip, AppSettings settings, Task<JsonObject?> rdapTask, CancellationToken ct)
    {
        var ipWhoTask = SafeJsonAsync($"https://ipwho.is/{Uri.EscapeDataString(ip)}", ct);
        var ipApiIsUrl = $"https://api.ipapi.is/?q={Uri.EscapeDataString(ip)}" + (string.IsNullOrWhiteSpace(settings.IpApiIsKey) ? "" : $"&key={Uri.EscapeDataString(settings.IpApiIsKey)}");
        var ipApiIsTask = SafeJsonAsync(ipApiIsUrl, ct);
        var ipApiCoTask = settings.LocationCrossCheck ? SafeJsonAsync($"https://ipapi.co/{Uri.EscapeDataString(ip)}/json/", ct) : Task.FromResult<JsonNode?>(new JsonObject { ["skipped"] = true });
        var reverseTask = ReverseDnsAsync(ip, ct);
        var torTask = IsTorExitAsync(ip, ct);
        await Task.WhenAll(ipWhoTask, ipApiIsTask, ipApiCoTask, reverseTask, torTask, rdapTask);

        var ipWho = ipWhoTask.Result;
        var ipApiIs = ipApiIsTask.Result;
        var ipApiCo = ipApiCoTask.Result;
        var rdap = rdapTask.Result;
        var locations = new JsonArray();
        AddLocation(locations, "ipwho.is", ipWho, "city", "region", "country", "latitude", "longitude", "postal", "timezone");
        AddLocation(locations, "ipapi.is", ipApiIs, "city", "region", "country", "lat", "lon", null, "timezone");
        AddLocation(locations, "ipapi.co", ipApiCo, "city", "region", "country_name", "latitude", "longitude", "postal", "timezone");
        var consensus = BuildGeoConsensus(locations);

        var asn = FirstNonEmpty(
            NodeString(ipWho, "connection", "asn"),
            NodeString(ipApiCo, "asn"),
            ParseAsn(NodeString(ipApiIs, "asn"))
        );
        var org = FirstNonEmpty(
            NodeString(ipWho, "connection", "org"),
            NodeString(ipApiCo, "org"),
            NodeString(ipApiIs, "company"),
            NodeString(ipApiIs, "company", "name"),
            rdap?["name"]?.GetValue<string>()
        );
        var isp = FirstNonEmpty(NodeString(ipWho, "connection", "isp"), NodeString(ipApiIs, "company", "name"));
        var domain = FirstNonEmpty(NodeString(ipWho, "connection", "domain"), NodeString(ipApiIs, "company", "domain"));
        var datacenter = NodeBool(ipApiIs, "is_datacenter");
        var proxy = NodeBool(ipApiIs, "is_proxy");
        var vpn = NodeBool(ipApiIs, "is_vpn");
        var abuser = NodeBool(ipApiIs, "is_abuser");
        var bogon = NodeBool(ipApiIs, "is_bogon") ?? false;
        var mobile = NodeBool(ipApiIs, "is_mobile");
        var tor = NodeBool(ipApiIs, "is_tor") ?? torTask.Result;
        var providerText = string.Join(' ', new[] { org, isp, domain }.Where(x => !string.IsNullOrWhiteSpace(x))).ToLowerInvariant();
        var hostingHeuristic = Regex.IsMatch(providerText, "cloudflare|amazon|aws|microsoft|azure|google cloud|digitalocean|hetzner|ovh|vultr|choopa|linode|akamai|fastly|leaseweb|contabo|oracle cloud|hostinger|datacenter|hosting|colo|cloud");
        var anycastLikely = Regex.IsMatch(providerText, "cloudflare|fastly|akamai|google|quad9|cloudfront");

        return new JsonObject
        {
            ["ip"] = ip,
            ["version"] = ip.Contains(':') ? 6 : 4,
            ["reverseDns"] = reverseTask.Result,
            ["ownership"] = new JsonObject
            {
                ["asn"] = asn,
                ["organization"] = org,
                ["isp"] = isp,
                ["networkDomain"] = domain,
                ["rdapName"] = rdap?["name"]?.DeepClone(),
                ["rdapHandle"] = rdap?["handle"]?.DeepClone(),
                ["rdapCountry"] = rdap?["country"]?.DeepClone()
            },
            ["classification"] = new JsonObject
            {
                ["isBogon"] = bogon,
                ["isDatacenter"] = datacenter,
                ["isTorExit"] = tor,
                ["isProxy"] = proxy,
                ["isVpn"] = vpn,
                ["isAbuser"] = abuser,
                ["isMobile"] = mobile,
                ["hostingAssessment"] = datacenter == true ? "datacenter" : hostingHeuristic ? "likely hosting/provider range" : datacenter == false ? "not classified as datacenter" : "unknown",
                ["anycastAssessment"] = anycastLikely ? "likely based on provider/network heuristic" : "unknown",
                ["note"] = "Proxy/VPN/datacenter flags depend on the selected public providers and may be unavailable without an API key."
            },
            ["geolocation"] = new JsonObject
            {
                ["consensus"] = consensus,
                ["sources"] = locations,
                ["accuracyNote"] = "IP geolocation is network-level estimation. Coordinates may identify a city centroid, ISP point of presence or datacenter rather than a device or building."
            },
            ["registration"] = rdap?.DeepClone(),
            ["providers"] = new JsonObject
            {
                ["ipwho.is"] = ipWho?.DeepClone(),
                ["ipapi.is"] = ipApiIs?.DeepClone(),
                ["ipapi.co"] = ipApiCo?.DeepClone(),
                ["rdap.org"] = rdap?.DeepClone()
            }
        };
    }

    private static void AddLocation(JsonArray target, string source, JsonNode? node, string city, string region, string country, string lat, string lon, string? postal, string timezone)
    {
        if (node is not JsonObject || !string.IsNullOrWhiteSpace(NodeString(node, "error"))) return;
        var latitude = NodeDouble(node, lat);
        var longitude = NodeDouble(node, lon);
        var countryValue = NodeString(node, country);
        if (latitude is null && longitude is null && string.IsNullOrWhiteSpace(countryValue)) return;
        target.Add(new JsonObject
        {
            ["source"] = source,
            ["city"] = NodeString(node, city),
            ["region"] = NodeString(node, region),
            ["country"] = countryValue,
            ["latitude"] = latitude,
            ["longitude"] = longitude,
            ["postal"] = postal is null ? null : NodeString(node, postal),
            ["timezone"] = NodeString(node, timezone)
        });
    }

    private static JsonObject BuildGeoConsensus(JsonArray locations)
    {
        var rows = locations.OfType<JsonObject>().ToList();
        if (rows.Count == 0) return new JsonObject { ["confidence"] = "none", ["sourceCount"] = 0 };
        var country = rows.Select(x => GetString(x["country"])).Where(x => !string.IsNullOrWhiteSpace(x)).GroupBy(x => x!, StringComparer.OrdinalIgnoreCase).OrderByDescending(x => x.Count()).Select(x => x.Key).FirstOrDefault();
        var city = rows.Select(x => GetString(x["city"])).Where(x => !string.IsNullOrWhiteSpace(x)).GroupBy(x => x!, StringComparer.OrdinalIgnoreCase).OrderByDescending(x => x.Count()).Select(x => x.Key).FirstOrDefault();
        var region = rows.Select(x => GetString(x["region"])).Where(x => !string.IsNullOrWhiteSpace(x)).GroupBy(x => x!, StringComparer.OrdinalIgnoreCase).OrderByDescending(x => x.Count()).Select(x => x.Key).FirstOrDefault();
        var coords = rows.Select(x => (Lat: GetDouble(x["latitude"]), Lon: GetDouble(x["longitude"]))).Where(x => x.Lat is not null && x.Lon is not null).Select(x => (Lat: x.Lat!.Value, Lon: x.Lon!.Value)).ToList();
        double? avgLat = coords.Count > 0 ? coords.Average(x => x.Lat) : null;
        double? avgLon = coords.Count > 0 ? coords.Average(x => x.Lon) : null;
        double maxSpread = 0;
        for (var i = 0; i < coords.Count; i++)
            for (var j = i + 1; j < coords.Count; j++)
                maxSpread = Math.Max(maxSpread, HaversineKm(coords[i].Lat, coords[i].Lon, coords[j].Lat, coords[j].Lon));
        var sameCountry = country is not null && rows.Count(x => string.Equals(GetString(x["country"]), country, StringComparison.OrdinalIgnoreCase)) >= Math.Max(1, (rows.Count + 1) / 2);
        var confidence = rows.Count == 1 ? "low" : sameCountry && maxSpread <= 50 ? "high" : sameCountry && maxSpread <= 250 ? "medium" : "low";
        return new JsonObject
        {
            ["city"] = city,
            ["region"] = region,
            ["country"] = country,
            ["latitude"] = avgLat,
            ["longitude"] = avgLon,
            ["sourceCount"] = rows.Count,
            ["coordinateSourceCount"] = coords.Count,
            ["maxCoordinateSpreadKm"] = Math.Round(maxSpread, 1),
            ["confidence"] = confidence
        };
    }

    private static double HaversineKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double r = 6371.0;
        var dLat = (lat2 - lat1) * Math.PI / 180;
        var dLon = (lon2 - lon1) * Math.PI / 180;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) + Math.Cos(lat1 * Math.PI / 180) * Math.Cos(lat2 * Math.PI / 180) * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return r * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
    }

    private static async Task<string?> ReverseDnsAsync(string ip, CancellationToken ct)
    {
        try
        {
            var task = Dns.GetHostEntryAsync(IPAddress.Parse(ip));
            var entry = await task.WaitAsync(TimeSpan.FromSeconds(2), ct);
            return entry.HostName;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> IsTorExitAsync(string ip, CancellationToken ct)
    {
        try
        {
            await TorCacheLock.WaitAsync(ct);
            try
            {
                if (_torExitCache is null || DateTimeOffset.UtcNow - _torExitCacheAt > TimeSpan.FromMinutes(30))
                {
                    var text = await Http.GetStringAsync("https://check.torproject.org/torbulkexitlist", ct);
                    _torExitCache = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
                    _torExitCacheAt = DateTimeOffset.UtcNow;
                }
                return _torExitCache.Contains(ip);
            }
            finally
            {
                TorCacheLock.Release();
            }
        }
        catch
        {
            return false;
        }
    }

    private static async Task<JsonObject> BuildRoutingAsync(string ip, bool deep, CancellationToken ct)
    {
        var endpoints = new Dictionary<string, Task<JsonNode?>>
        {
            ["networkInfo"] = RipeAsync("network-info", ip, ct),
            ["prefixOverview"] = RipeAsync("prefix-overview", ip, ct),
            ["routingStatus"] = RipeAsync("routing-status", ip, ct),
            ["abuseContactFinder"] = RipeAsync("abuse-contact-finder", ip, ct),
            ["ianaRegistryInfo"] = RipeAsync("iana-registry-info", ip, ct),
            ["rir"] = RipeAsync("rir", ip, ct),
            ["rirGeo"] = RipeAsync("rir-geo", ip, ct),
            ["maxMindGeoLite"] = RipeAsync("maxmind-geo-lite", ip, ct),
            ["reverseDnsIp"] = RipeAsync("reverse-dns-ip", ip, ct),
            ["whois"] = RipeAsync("whois", ip, ct)
        };
        if (deep)
        {
            endpoints["historicalWhois"] = RipeAsync("historical-whois", ip, ct);
            endpoints["routingHistory"] = RipeAsync("routing-history", ip, ct);
            endpoints["transferHistory"] = RipeAsync("transfer-history", ip, ct);
            endpoints["relatedPrefixes"] = RipeAsync("related-prefixes", ip, ct);
        }
        await Task.WhenAll(endpoints.Values);
        var networkInfo = endpoints["networkInfo"].Result;
        var prefix = NodeString(networkInfo, "data", "prefix");
        var asns = NodeAt(networkInfo, "data", "asns") as JsonArray;
        var asn = asns?.FirstOrDefault() is { } firstAsn ? GetLong(firstAsn)?.ToString(CultureInfo.InvariantCulture) : null;
        JsonNode? rpki = null;
        JsonNode? asOverview = null;
        JsonNode? peeringDb = null;
        JsonNode? asnNeighbours = null;
        if (!string.IsNullOrWhiteSpace(asn))
        {
            asOverview = await RipeAsync("as-overview", $"AS{asn}", ct);
            asnNeighbours = deep ? await RipeAsync("asn-neighbours", $"AS{asn}", ct) : null;
            peeringDb = await SafeJsonAsync($"https://www.peeringdb.com/api/net?asn={Uri.EscapeDataString(asn)}", ct);
            if (!string.IsNullOrWhiteSpace(prefix))
                rpki = await SafeJsonAsync($"https://stat.ripe.net/data/rpki-validation/data.json?resource={Uri.EscapeDataString(asn)}&prefix={Uri.EscapeDataString(prefix)}", ct);
        }
        var raw = new JsonObject();
        foreach (var pair in endpoints) raw[pair.Key] = pair.Value.Result?.DeepClone();
        raw["asOverview"] = asOverview?.DeepClone();
        raw["asnNeighbours"] = asnNeighbours?.DeepClone();
        return new JsonObject
        {
            ["prefix"] = prefix,
            ["asns"] = asns?.DeepClone(),
            ["rpki"] = rpki?.DeepClone(),
            ["peeringDb"] = peeringDb?.DeepClone(),
            ["abuseContact"] = endpoints["abuseContactFinder"].Result?["data"]?.DeepClone(),
            ["ripeStat"] = raw
        };
    }

    private static Task<JsonNode?> RipeAsync(string endpoint, string resource, CancellationToken ct)
    {
        return SafeJsonAsync($"https://stat.ripe.net/data/{endpoint}/data.json?resource={Uri.EscapeDataString(resource)}", ct);
    }

    private static async Task<JsonObject> BuildNetworkMeasurementsAsync(string ip, bool deep, CancellationToken ct)
    {
        var latencyTask = MeasurePingAsync(ip, ct);
        var traceTask = deep ? TraceRouteAsync(ip, ct) : Task.FromResult(new JsonArray());
        await Task.WhenAll(latencyTask, traceTask);
        return new JsonObject
        {
            ["latency"] = latencyTask.Result,
            ["traceroute"] = traceTask.Result,
            ["tracerouteEnabled"] = deep
        };
    }

    private static async Task<JsonObject> MeasurePingAsync(string ip, CancellationToken ct)
    {
        var address = IPAddress.Parse(ip);
        var replies = new List<long>();
        var attempts = 5;
        for (var i = 0; i < attempts; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(address, 1200, new byte[32]);
                if (reply.Status == IPStatus.Success) replies.Add(reply.RoundtripTime);
            }
            catch
            {
            }
        }
        var jitter = 0d;
        if (replies.Count > 1)
        {
            var diffs = replies.Zip(replies.Skip(1), (a, b) => Math.Abs(b - a)).ToList();
            jitter = diffs.Average();
        }
        return new JsonObject
        {
            ["attempts"] = attempts,
            ["received"] = replies.Count,
            ["lossPercent"] = Math.Round(100d * (attempts - replies.Count) / attempts, 1),
            ["minMs"] = replies.Count > 0 ? replies.Min() : null,
            ["maxMs"] = replies.Count > 0 ? replies.Max() : null,
            ["averageMs"] = replies.Count > 0 ? Math.Round(replies.Average(), 1) : null,
            ["jitterMs"] = replies.Count > 1 ? Math.Round(jitter, 1) : null
        };
    }

    private static async Task<JsonArray> TraceRouteAsync(string ip, CancellationToken ct)
    {
        var address = IPAddress.Parse(ip);
        var result = new JsonArray();
        var consecutiveTimeouts = 0;
        for (var ttl = 1; ttl <= 24; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var ping = new Ping();
                var options = new PingOptions(ttl, true);
                var reply = await ping.SendPingAsync(address, 400, new byte[24], options);
                if (reply.Status is IPStatus.TtlExpired or IPStatus.Success)
                {
                    consecutiveTimeouts = 0;
                    var hopAddress = reply.Address?.ToString();
                    string? host = null;
                    if (hopAddress is not null)
                    {
                        try
                        {
                            host = (await Dns.GetHostEntryAsync(reply.Address!).WaitAsync(TimeSpan.FromMilliseconds(500), ct)).HostName;
                        }
                        catch
                        {
                        }
                    }
                    result.Add(new JsonObject { ["hop"] = ttl, ["address"] = hopAddress, ["hostname"] = host, ["roundtripMs"] = reply.RoundtripTime, ["status"] = reply.Status.ToString() });
                    if (reply.Status == IPStatus.Success) break;
                }
                else
                {
                    consecutiveTimeouts++;
                    result.Add(new JsonObject { ["hop"] = ttl, ["address"] = null, ["roundtripMs"] = null, ["status"] = reply.Status.ToString() });
                }
            }
            catch
            {
                consecutiveTimeouts++;
                result.Add(new JsonObject { ["hop"] = ttl, ["address"] = null, ["roundtripMs"] = null, ["status"] = "error" });
            }
            if (consecutiveTimeouts >= 5) break;
        }
        return result;
    }

    private static async Task<JsonObject> ScanServicesAsync(string ip, string mode, int timeoutMs, CancellationToken ct)
    {
        mode = mode.ToLowerInvariant();
        if (mode is not "off" and not "common" and not "extended") mode = "common";
        timeoutMs = Math.Clamp(timeoutMs, 100, 1500);
        if (mode == "off") return new JsonObject { ["mode"] = "off", ["address"] = ip, ["checked"] = 0, ["open"] = 0, ["timeoutMs"] = timeoutMs, ["durationMs"] = 0, ["results"] = new JsonArray() };
        var ports = mode == "extended" ? ExtendedPorts : CommonPorts;
        var watch = Stopwatch.StartNew();
        var semaphore = new SemaphoreSlim(48, 48);
        var tasks = ports.Select(async pair =>
        {
            await semaphore.WaitAsync(ct);
            try { return await ScanPortAsync(ip, pair.Key, pair.Value, timeoutMs, ct); }
            finally { semaphore.Release(); }
        }).ToArray();
        var rows = await Task.WhenAll(tasks);
        var arr = new JsonArray();
        foreach (var row in rows.OrderBy(x => x["port"]?.GetValue<int>() ?? 0)) arr.Add(row);
        return new JsonObject
        {
            ["mode"] = mode,
            ["address"] = ip,
            ["checked"] = rows.Length,
            ["open"] = rows.Count(x => x["open"]?.GetValue<bool>() == true),
            ["timeoutMs"] = timeoutMs,
            ["durationMs"] = watch.ElapsedMilliseconds,
            ["results"] = arr
        };
    }

    private static async Task<JsonObject> ScanPortAsync(string ip, int port, string service, int timeoutMs, CancellationToken ct)
    {
        var address = IPAddress.Parse(ip);
        var watch = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(timeoutMs);
            await client.ConnectAsync(address, port, linked.Token);
            watch.Stop();
            var banner = await ReadPassiveBannerAsync(client, ct);
            return new JsonObject { ["port"] = port, ["service"] = service, ["open"] = true, ["latencyMs"] = Math.Round(watch.Elapsed.TotalMilliseconds, 1), ["banner"] = banner };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new JsonObject { ["port"] = port, ["service"] = service, ["open"] = false, ["latencyMs"] = null, ["banner"] = null };
        }
        catch
        {
            return new JsonObject { ["port"] = port, ["service"] = service, ["open"] = false, ["latencyMs"] = null, ["banner"] = null };
        }
    }

    private static async Task<string?> ReadPassiveBannerAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(220);
            var buffer = new byte[512];
            var stream = client.GetStream();
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), linked.Token);
            if (read <= 0) return null;
            var text = Encoding.UTF8.GetString(buffer, 0, read).Replace("\0", "").Trim();
            return text.Length > 300 ? text[..300] : text;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<JsonObject> BuildReputationAsync(string ip, AppSettings settings, CancellationToken ct)
    {
        var dnsBlocklistsTask = RipeAsync("dns-blocklists", ip, ct);
        var abuseTask = string.IsNullOrWhiteSpace(settings.AbuseIpDbKey)
            ? Task.FromResult<JsonNode?>(new JsonObject { ["skipped"] = true, ["reason"] = "No AbuseIPDB key configured" })
            : SafeJsonAsync($"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90&verbose", ct, new Dictionary<string, string> { ["Key"] = settings.AbuseIpDbKey, ["Accept"] = "application/json" });
        var shodanTask = string.IsNullOrWhiteSpace(settings.ShodanKey)
            ? Task.FromResult<JsonNode?>(new JsonObject { ["skipped"] = true, ["reason"] = "No Shodan key configured" })
            : SafeJsonAsync($"https://api.shodan.io/shodan/host/{Uri.EscapeDataString(ip)}?key={Uri.EscapeDataString(settings.ShodanKey)}&history=true&minify=false", ct);
        var vtTask = string.IsNullOrWhiteSpace(settings.VirusTotalKey)
            ? Task.FromResult<JsonNode?>(new JsonObject { ["skipped"] = true, ["reason"] = "No VirusTotal key configured" })
            : SafeJsonAsync($"https://www.virustotal.com/api/v3/ip_addresses/{Uri.EscapeDataString(ip)}", ct, new Dictionary<string, string> { ["x-apikey"] = settings.VirusTotalKey });
        await Task.WhenAll(dnsBlocklistsTask, abuseTask, shodanTask, vtTask);
        return new JsonObject
        {
            ["ripeDnsBlocklists"] = dnsBlocklistsTask.Result?.DeepClone(),
            ["abuseIpDb"] = abuseTask.Result?.DeepClone(),
            ["shodan"] = shodanTask.Result?.DeepClone(),
            ["virusTotal"] = vtTask.Result?.DeepClone()
        };
    }

    private static async Task<JsonObject?> MinecraftLookupAsync(string address, CancellationToken ct)
    {
        var encoded = Uri.EscapeDataString(address);
        var javaTask = SafeJsonAsync($"https://api.mcsrvstat.us/3/{encoded}", ct);
        var bedrockTask = SafeJsonAsync($"https://api.mcsrvstat.us/bedrock/3/{encoded}", ct);
        await Task.WhenAll(javaTask, bedrockTask);
        return new JsonObject
        {
            ["address"] = address,
            ["java"] = javaTask.Result?.DeepClone(),
            ["bedrock"] = bedrockTask.Result?.DeepClone(),
            ["cacheNote"] = "mcsrvstat.us status data may be cached upstream for several minutes."
        };
    }

    private static string MinecraftAddress(TargetInfo target)
    {
        if (target.RequestedPort is not null)
        {
            var bracket = IPAddress.TryParse(target.Host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{target.Host}]" : target.Host;
            return $"{bracket}:{target.RequestedPort}";
        }
        return target.Host;
    }

    private static async Task<JsonObject?> EmailDnsAsync(string domain, CancellationToken ct)
    {
        var mxTask = DnsQueryAsync(domain, 15, ct);
        var txtTask = DnsQueryAsync(domain, 16, ct);
        var dmarcTask = DnsQueryAsync($"_dmarc.{domain}", 16, ct);
        var mtaTask = DnsQueryAsync($"_mta-sts.{domain}", 16, ct);
        var bimiTask = DnsQueryAsync($"default._bimi.{domain}", 16, ct);
        await Task.WhenAll(mxTask, txtTask, dmarcTask, mtaTask, bimiTask);
        var rootTxt = ParseTxtArray(AnswerStrings(txtTask.Result, 16));
        var spf = new JsonArray();
        foreach (var item in rootTxt)
        {
            var s = GetString(item);
            if (s is not null && s.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)) spf.Add(s);
        }
        return new JsonObject
        {
            ["mx"] = ParseMxArray(AnswerStrings(mxTask.Result, 15)),
            ["spf"] = spf,
            ["dmarc"] = ParseTxtArray(AnswerStrings(dmarcTask.Result, 16)),
            ["mtaSts"] = ParseTxtArray(AnswerStrings(mtaTask.Result, 16)),
            ["bimi"] = ParseTxtArray(AnswerStrings(bimiTask.Result, 16))
        };
    }

    private static async Task<JsonObject?> ProbeSiteResourcesAsync(string baseUrl, CancellationToken ct)
    {
        var names = new Dictionary<string, string>
        {
            ["robots"] = "/robots.txt",
            ["sitemap"] = "/sitemap.xml",
            ["securityTxt"] = "/.well-known/security.txt",
            ["favicon"] = "/favicon.ico"
        };
        var tasks = names.ToDictionary(x => x.Key, x => ProbeSameHostResourceAsync(baseUrl, x.Value, ct));
        await Task.WhenAll(tasks.Values);
        var result = new JsonObject();
        foreach (var pair in tasks) result[pair.Key] = pair.Value.Result?.DeepClone();
        return result;
    }

    private static async Task<JsonObject?> ProbeSameHostResourceAsync(string baseUrl, string path, CancellationToken ct)
    {
        try
        {
            var baseUri = new Uri(baseUrl);
            var uri = new Uri(baseUri, path);
            if (!string.Equals(uri.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)) return null;
            var one = await RequestHttpOnceAsync(uri.ToString(), ct);
            var contentType = Header(one.Headers, "content-type");
            var textual = contentType is not null && (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(contentType, "json|xml", RegexOptions.IgnoreCase));
            return new JsonObject
            {
                ["url"] = uri.ToString(),
                ["status"] = one.Status,
                ["contentType"] = contentType,
                ["bytesRead"] = one.Report["page"]?["bytesSampled"]?.DeepClone(),
                ["preview"] = textual ? one.Body[..Math.Min(one.Body.Length, 1600)] : null
            };
        }
        catch
        {
            return null;
        }
    }

    private static JsonArray DetectTechnology(JsonObject headers, string html)
    {
        var hints = new JsonArray();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string name, string evidence, string confidence = "medium", string category = "software")
        {
            if (string.IsNullOrWhiteSpace(name) || !seen.Add(name)) return;
            hints.Add(new JsonObject { ["name"] = name, ["evidence"] = evidence, ["confidence"] = confidence, ["category"] = category });
        }
        var server = Header(headers, "server") ?? "";
        var powered = Header(headers, "x-powered-by") ?? "";
        var via = Header(headers, "via") ?? "";
        if (server.Length > 0) Add(server, "Server header", "high", "server");
        if (powered.Length > 0) Add(powered, "X-Powered-By header", "high", "runtime");
        if (Header(headers, "x-vercel-id") is not null || server.Contains("vercel", StringComparison.OrdinalIgnoreCase)) Add("Vercel", "Vercel response headers", "high", "platform");
        if (Header(headers, "x-nf-request-id") is not null || server.Contains("netlify", StringComparison.OrdinalIgnoreCase)) Add("Netlify", "Netlify response headers", "high", "platform");
        if (Header(headers, "cf-ray") is not null || server.Contains("cloudflare", StringComparison.OrdinalIgnoreCase)) Add("Cloudflare", "Cloudflare edge headers", "high", "edge");
        if (Header(headers, "x-amz-cf-pop") is not null || via.Contains("cloudfront", StringComparison.OrdinalIgnoreCase)) Add("Amazon CloudFront", "CloudFront response headers", "high", "edge");
        if (Header(headers, "x-served-by") is not null && Header(headers, "x-cache") is not null) Add("Fastly", "Cache and edge headers", "medium", "edge");
        if (Regex.IsMatch(html, "wp-content|wp-includes", RegexOptions.IgnoreCase)) Add("WordPress", "WordPress asset paths", "high", "cms");
        if (Regex.IsMatch(html, "_next/static|__next_data__", RegexOptions.IgnoreCase)) Add("Next.js", "Next.js page markers", "high", "framework");
        if (Regex.IsMatch(html, "/_nuxt/|__NUXT__", RegexOptions.IgnoreCase)) Add("Nuxt", "Nuxt page markers", "high", "framework");
        if (Regex.IsMatch(html, "cdn\\.shopify\\.com|shopify-section", RegexOptions.IgnoreCase)) Add("Shopify", "Shopify page markers", "high", "platform");
        if (Regex.IsMatch(html, "static\\.wixstatic\\.com|wix-code-sdk", RegexOptions.IgnoreCase)) Add("Wix", "Wix page markers", "high", "platform");
        if (Regex.IsMatch(html, "webflow\\.js|data-wf-page=", RegexOptions.IgnoreCase)) Add("Webflow", "Webflow page markers", "high", "platform");
        if (Regex.IsMatch(html, "cdn\\.squarespace\\.com|static1\\.squarespace\\.com", RegexOptions.IgnoreCase)) Add("Squarespace", "Squarespace asset hosts", "high", "platform");
        if (Regex.IsMatch(html, "drupalSettings|sites/default/files", RegexOptions.IgnoreCase)) Add("Drupal", "Drupal page markers", "medium", "cms");
        if (Regex.IsMatch(html, "joomla|/media/system/js/", RegexOptions.IgnoreCase)) Add("Joomla", "Joomla page markers", "medium", "cms");
        var generator = ExtractMeta(html, "generator");
        if (!string.IsNullOrWhiteSpace(generator)) Add(generator!, "Generator metadata", "high", "generator");
        if (Regex.IsMatch(html, "data-reactroot|__react|react-dom", RegexOptions.IgnoreCase)) Add("React", "React page markers", "medium", "framework");
        if (Regex.IsMatch(html, "__vue__|data-v-[0-9a-f]{6,}|vue\\.runtime", RegexOptions.IgnoreCase)) Add("Vue", "Vue page markers", "medium", "framework");
        return hints;
    }

    private static JsonObject DetectEdge(JsonObject headers, JsonObject ipIntel, JsonObject dns)
    {
        var provider = (string?)null;
        var evidence = new JsonArray();
        var server = Header(headers, "server") ?? "";
        var org = GetString(ipIntel["ownership"]?["organization"]) ?? "";
        var asn = GetString(ipIntel["ownership"]?["asn"]) ?? "";
        if (Header(headers, "cf-ray") is not null || Header(headers, "cf-cache-status") is not null || server.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) || asn.Contains("13335"))
        {
            provider = "Cloudflare";
            if (Header(headers, "cf-ray") is { } ray) evidence.Add($"cf-ray: {ray}");
            if (Header(headers, "cf-cache-status") is { } cache) evidence.Add($"cf-cache-status: {cache}");
            if (asn.Contains("13335")) evidence.Add($"ASN: {asn}");
        }
        else if (Header(headers, "x-vercel-id") is not null || org.Contains("vercel", StringComparison.OrdinalIgnoreCase)) provider = "Vercel";
        else if (Header(headers, "x-nf-request-id") is not null || org.Contains("netlify", StringComparison.OrdinalIgnoreCase)) provider = "Netlify";
        else if (Header(headers, "x-amz-cf-pop") is not null || (Header(headers, "via") ?? "").Contains("cloudfront", StringComparison.OrdinalIgnoreCase)) provider = "Amazon CloudFront";
        else if (Header(headers, "x-served-by") is not null && Header(headers, "x-cache") is not null) provider = "Fastly";
        else if (server.Contains("akamai", StringComparison.OrdinalIgnoreCase) || org.Contains("akamai", StringComparison.OrdinalIgnoreCase)) provider = "Akamai";
        else if (Header(headers, "fly-request-id") is not null || org.Contains("fly.io", StringComparison.OrdinalIgnoreCase)) provider = "Fly.io";
        if (dns["cname"] is JsonArray cnames && cnames.Count > 0) evidence.Add("CNAME: " + string.Join(", ", cnames.Select(GetString).Where(x => x is not null)));
        string? edgePoint = null;
        if (Header(headers, "cf-ray") is { } cfRay)
        {
            var match = Regex.Match(cfRay, "-([A-Z]{3})$", RegexOptions.IgnoreCase);
            if (match.Success) edgePoint = match.Groups[1].Value.ToUpperInvariant();
        }
        edgePoint ??= Header(headers, "x-amz-cf-pop");
        if (edgePoint is null && Header(headers, "x-vercel-id") is { } vercel) edgePoint = vercel.Split("::", 2)[0];
        return new JsonObject
        {
            ["provider"] = provider,
            ["detected"] = provider is not null,
            ["evidence"] = evidence,
            ["cloudflare"] = provider == "Cloudflare" ? "detected" : "not detected",
            ["edgePoint"] = edgePoint,
            ["requestPath"] = provider is null ? "Direct or unidentified edge" : $"{provider} edge",
            ["originDiscovery"] = "not attempted"
        };
    }

    private static JsonObject AnalyzeSecurity(JsonObject headers)
    {
        var hsts = Header(headers, "strict-transport-security") ?? "";
        var csp = Header(headers, "content-security-policy") ?? "";
        var checks = new (string Name, bool Pass, int Weight)[]
        {
            ("Strict-Transport-Security", hsts.Length > 0, 15),
            ("Content-Security-Policy", csp.Length > 0, 20),
            ("X-Content-Type-Options", (Header(headers, "x-content-type-options") ?? "").Contains("nosniff", StringComparison.OrdinalIgnoreCase), 10),
            ("X-Frame-Options or CSP frame-ancestors", Header(headers, "x-frame-options") is not null || csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase), 10),
            ("Referrer-Policy", Header(headers, "referrer-policy") is not null, 10),
            ("Permissions-Policy", Header(headers, "permissions-policy") is not null, 10),
            ("Cross-Origin-Opener-Policy", Header(headers, "cross-origin-opener-policy") is not null, 5),
            ("Cross-Origin-Resource-Policy", Header(headers, "cross-origin-resource-policy") is not null, 5),
            ("No wildcard CORS", Header(headers, "access-control-allow-origin") != "*", 5),
            ("CSP avoids unsafe-eval", !csp.Contains("'unsafe-eval'", StringComparison.OrdinalIgnoreCase), 5),
            ("CSP avoids unsafe-inline", !csp.Contains("'unsafe-inline'", StringComparison.OrdinalIgnoreCase), 5)
        };
        var score = checks.Where(x => x.Pass).Sum(x => x.Weight);
        var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
        var checkArray = new JsonArray();
        foreach (var check in checks) checkArray.Add(new JsonObject { ["name"] = check.Name, ["pass"] = check.Pass, ["weight"] = check.Weight });
        var cookieRows = new JsonArray();
        if (headers["set-cookie"] is JsonArray cookies)
        {
            foreach (var node in cookies)
            {
                var cookie = GetString(node) ?? "";
                var sameSite = Regex.Match(cookie, ";\\s*samesite=([^;]+)", RegexOptions.IgnoreCase);
                cookieRows.Add(new JsonObject
                {
                    ["name"] = cookie.Split('=', 2)[0].Trim(),
                    ["secure"] = Regex.IsMatch(cookie, ";\\s*secure", RegexOptions.IgnoreCase),
                    ["httpOnly"] = Regex.IsMatch(cookie, ";\\s*httponly", RegexOptions.IgnoreCase),
                    ["sameSite"] = sameSite.Success ? sameSite.Groups[1].Value.Trim() : null
                });
            }
        }
        return new JsonObject
        {
            ["score"] = score,
            ["grade"] = grade,
            ["note"] = "Weighted from common response headers and cookie flags.",
            ["checks"] = checkArray,
            ["details"] = new JsonObject
            {
                ["hsts"] = hsts,
                ["csp"] = csp,
                ["cspUnsafeInline"] = csp.Contains("'unsafe-inline'", StringComparison.OrdinalIgnoreCase),
                ["cspUnsafeEval"] = csp.Contains("'unsafe-eval'", StringComparison.OrdinalIgnoreCase),
                ["corsAllowOrigin"] = Header(headers, "access-control-allow-origin"),
                ["xFrameOptions"] = Header(headers, "x-frame-options"),
                ["xContentTypeOptions"] = Header(headers, "x-content-type-options"),
                ["referrerPolicy"] = Header(headers, "referrer-policy"),
                ["permissionsPolicy"] = Header(headers, "permissions-policy"),
                ["coop"] = Header(headers, "cross-origin-opener-policy"),
                ["coep"] = Header(headers, "cross-origin-embedder-policy"),
                ["corp"] = Header(headers, "cross-origin-resource-policy"),
                ["cookies"] = cookieRows
            }
        };
    }

    private static JsonObject BuildInfrastructure(JsonObject ipIntel, JsonObject? ipRdap, JsonObject dns, JsonObject? email, JsonObject? web, JsonObject edge, JsonArray technologies)
    {
        var org = GetString(ipIntel["ownership"]?["organization"]);
        var isp = GetString(ipIntel["ownership"]?["isp"]);
        var asn = GetString(ipIntel["ownership"]?["asn"]);
        var domain = GetString(ipIntel["ownership"]?["networkDomain"]);
        var headers = web?["headers"] as JsonObject ?? new JsonObject();
        var provider = DetectProviderName(org, isp, domain, GetString(ipRdap?["name"]), GetString(edge["provider"]));
        return new JsonObject
        {
            ["observedProvider"] = provider,
            ["networkOwner"] = org ?? GetString(ipRdap?["name"]),
            ["isp"] = isp,
            ["asn"] = asn,
            ["networkDomain"] = domain,
            ["dnsProvider"] = DetectDnsProvider(dns["ns"] as JsonArray),
            ["mailProvider"] = DetectMailProvider(email?["mx"] as JsonArray),
            ["serverSoftware"] = Header(headers, "server"),
            ["poweredBy"] = Header(headers, "x-powered-by"),
            ["via"] = Header(headers, "via"),
            ["edgeProvider"] = GetString(edge["provider"]),
            ["edgePoint"] = GetString(edge["edgePoint"]),
            ["reverseDns"] = GetString(ipIntel["reverseDns"]),
            ["resolvedAddressCount"] = (dns["a"] as JsonArray)?.Count + (dns["aaaa"] as JsonArray)?.Count,
            ["technologyCount"] = technologies.Count
        };
    }

    private static string? DetectProviderName(params string?[] values)
    {
        var haystack = string.Join(" | ", values.Where(x => !string.IsNullOrWhiteSpace(x))).ToLowerInvariant();
        var patterns = new (string[] Needles, string Name)[]
        {
            (["oracle cloud", "oracle corporation"], "Oracle Cloud"),
            (["microsoft", "azure"], "Microsoft Azure"),
            (["amazon", "aws", "amazon technologies"], "Amazon Web Services"),
            (["google cloud", "google llc", "googleusercontent"], "Google Cloud"),
            (["digitalocean"], "DigitalOcean"),
            (["hetzner"], "Hetzner"),
            (["ovh"], "OVHcloud"),
            (["vultr", "choopa"], "Vultr"),
            (["linode", "akamai connected cloud"], "Akamai Connected Cloud"),
            (["cloudflare"], "Cloudflare"),
            (["fastly"], "Fastly"),
            (["fly.io", "flyio"], "Fly.io"),
            (["vercel"], "Vercel"),
            (["netlify"], "Netlify"),
            (["leaseweb"], "Leaseweb"),
            (["contabo"], "Contabo"),
            (["ionos", "1&1 internet"], "IONOS"),
            (["alibaba", "aliyun"], "Alibaba Cloud"),
            (["tencent"], "Tencent Cloud"),
            (["rackspace"], "Rackspace"),
            (["hostinger"], "Hostinger")
        };
        foreach (var pattern in patterns)
            if (pattern.Needles.Any(haystack.Contains)) return pattern.Name;
        return values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
    }

    private static string? DetectDnsProvider(JsonArray? nameservers)
    {
        var joined = string.Join(' ', nameservers?.Select(GetString).Where(x => x is not null) ?? []).ToLowerInvariant();
        var map = new (string Needle, string Name)[]
        {
            ("cloudflare.com", "Cloudflare DNS"), ("awsdns-", "Amazon Route 53"), ("azure-dns", "Azure DNS"), ("googledomains.com", "Google Cloud DNS"), ("ns-cloud-", "Google Cloud DNS"), ("digitalocean.com", "DigitalOcean DNS"), ("hetzner.com", "Hetzner DNS"), ("ovh.net", "OVH DNS"), ("registrar-servers.com", "Namecheap DNS"), ("domaincontrol.com", "GoDaddy DNS"), ("ui-dns", "IONOS DNS"), ("nsone.net", "NS1"), ("cloudns", "ClouDNS")
        };
        return map.FirstOrDefault(x => joined.Contains(x.Needle)).Name;
    }

    private static string? DetectMailProvider(JsonArray? mx)
    {
        var joined = string.Join(' ', mx?.OfType<JsonObject>().Select(x => GetString(x["exchange"])).Where(x => x is not null) ?? []).ToLowerInvariant();
        var map = new (string[] Needles, string Name)[]
        {
            (["google.com", "googlemail.com"], "Google Workspace"), (["outlook.com", "protection.outlook.com"], "Microsoft 365"), (["protonmail", "proton.ch"], "Proton Mail"), (["zoho"], "Zoho Mail"), (["fastmail", "messagingengine.com"], "Fastmail"), (["icloud.com"], "iCloud Mail"), (["mimecast"], "Mimecast"), (["pphosted.com", "proofpoint"], "Proofpoint"), (["mxroute"], "MXroute")
        };
        foreach (var item in map) if (item.Needles.Any(joined.Contains)) return item.Name;
        return null;
    }

    private static JsonObject BuildRegistration(JsonObject? domainRdap, JsonObject? ipRdap)
    {
        JsonNode? domain = domainRdap?["data"]?.DeepClone();
        if (domain is JsonObject domainObj && domainObj["events"] is JsonObject events && GetString(events["registration"]) is { } created && DateTimeOffset.TryParse(created, out var stamp))
        {
            var days = Math.Max(0, (DateTimeOffset.UtcNow - stamp).Days);
            domainObj["domainAge"] = new JsonObject { ["days"] = days, ["years"] = Math.Round(days / 365.2425, 2) };
        }
        return new JsonObject { ["domain"] = domain, ["ip"] = ipRdap?.DeepClone() };
    }

    private static JsonObject BuildDnssecSummary(JsonObject dns)
    {
        return dns["dnssec"]?.DeepClone() as JsonObject ?? new JsonObject { ["authenticatedData"] = false };
    }

    private static JsonObject BuildSummary(TargetInfo target, string primaryIp, JsonObject dns, JsonObject? web, JsonObject? tls, JsonObject edge, JsonObject infrastructure, JsonObject serviceScan, JsonObject ipIntel, JsonObject registration, JsonObject? minecraft, JsonObject dnssec)
    {
        var geo = ipIntel["geolocation"]?["consensus"] as JsonObject;
        var city = GetString(geo?["city"]);
        var region = GetString(geo?["region"]);
        var country = GetString(geo?["country"]);
        var location = string.Join(", ", new[] { city, region, country }.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase));
        var domain = registration["domain"] as JsonObject;
        var domainAge = domain?["domainAge"] as JsonObject;
        var javaOnline = NodeBool(minecraft, "java", "online");
        var bedrockOnline = NodeBool(minecraft, "bedrock", "online");
        return new JsonObject
        {
            ["target"] = target.Host,
            ["online"] = web is not null,
            ["httpStatus"] = web?["status"]?.DeepClone(),
            ["primaryIp"] = primaryIp,
            ["ipv4Count"] = (dns["a"] as JsonArray)?.Count ?? 0,
            ["ipv6Count"] = (dns["aaaa"] as JsonArray)?.Count ?? 0,
            ["ipv6Supported"] = ((dns["aaaa"] as JsonArray)?.Count ?? 0) > 0,
            ["edgeProvider"] = GetString(edge["provider"]),
            ["edgePoint"] = GetString(edge["edgePoint"]),
            ["cloudflare"] = GetString(edge["cloudflare"]),
            ["networkProvider"] = GetString(infrastructure["observedProvider"]),
            ["networkOwner"] = GetString(infrastructure["networkOwner"]),
            ["asn"] = GetString(infrastructure["asn"]),
            ["dnsProvider"] = GetString(infrastructure["dnsProvider"]),
            ["mailProvider"] = GetString(infrastructure["mailProvider"]),
            ["server"] = GetString(infrastructure["serverSoftware"]),
            ["poweredBy"] = GetString(infrastructure["poweredBy"]),
            ["openPortCount"] = serviceScan["open"]?.DeepClone(),
            ["city"] = city,
            ["region"] = region,
            ["country"] = country,
            ["location"] = location,
            ["geoConfidence"] = GetString(geo?["confidence"]),
            ["httpVersion"] = GetString(web?["httpVersion"]),
            ["tlsVersion"] = GetString(tls?["protocol"]),
            ["alpn"] = GetString(tls?["alpn"]),
            ["dnssec"] = GetBool(dnssec["authenticatedData"]),
            ["registrar"] = GetString(domain?["registrar"]),
            ["domainAgeYears"] = GetDouble(domainAge?["years"]),
            ["minecraftJavaOnline"] = javaOnline,
            ["minecraftBedrockOnline"] = bedrockOnline
        };
    }

    private static string? Header(JsonObject headers, string name) => GetString(headers[name.ToLowerInvariant()]);

    private static string? GetString(JsonNode? node)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<string>(out var s)) return s;
            if (value.TryGetValue<long>(out var l)) return l.ToString(CultureInfo.InvariantCulture);
            if (value.TryGetValue<int>(out var i)) return i.ToString(CultureInfo.InvariantCulture);
            if (value.TryGetValue<double>(out var d)) return d.ToString(CultureInfo.InvariantCulture);
            if (value.TryGetValue<bool>(out var b)) return b ? "true" : "false";
        }
        return null;
    }

    private static long? GetLong(JsonNode? node)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<long>(out var l)) return l;
            if (value.TryGetValue<int>(out var i)) return i;
            if (value.TryGetValue<double>(out var d)) return (long)d;
            if (value.TryGetValue<string>(out var s) && long.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed)) return parsed;
        }
        return null;
    }

    private static double? GetDouble(JsonNode? node)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<double>(out var d)) return d;
            if (value.TryGetValue<float>(out var f)) return f;
            if (value.TryGetValue<long>(out var l)) return l;
            if (value.TryGetValue<string>(out var s) && double.TryParse(s, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed)) return parsed;
        }
        return null;
    }

    private static bool? GetBool(JsonNode? node)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<bool>(out var b)) return b;
            if (value.TryGetValue<string>(out var s) && bool.TryParse(s, out var parsed)) return parsed;
        }
        return null;
    }

    private static JsonNode? NodeAt(JsonNode? root, params string[] path)
    {
        var current = root;
        foreach (var key in path)
        {
            if (current is not JsonObject obj || !obj.TryGetPropertyValue(key, out current)) return null;
        }
        return current;
    }

    private static string? NodeString(JsonNode? root, params string[] path) => GetString(NodeAt(root, path));
    private static double? NodeDouble(JsonNode? root, params string[] path) => GetDouble(NodeAt(root, path));
    private static bool? NodeBool(JsonNode? root, params string[] path) => GetBool(NodeAt(root, path));

    private static string? FirstNonEmpty(params string?[] values) => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));

    private static string? ParseAsn(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var match = Regex.Match(value, "AS?(\\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : value;
    }

    private static string[] StringArray(JsonNode? node)
    {
        return node is JsonArray arr ? arr.Select(GetString).Where(x => x is not null).Select(x => x!).ToArray() : [];
    }
}
