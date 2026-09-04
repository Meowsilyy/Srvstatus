using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ServerStatusApp;

public sealed partial class NetworkEngine
{
    private const string UserAgent = "ServerStatusDesktop/1.0";
    private static readonly HttpClient Http = CreateHttpClient();

    private static readonly Dictionary<int, string> CommonPorts = new()
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

    private static readonly Dictionary<int, string> ExtendedPorts = new(CommonPorts)
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

    private sealed record TargetInfo(string Raw, string Host, int Port, string Scheme, string Path, bool ExplicitScheme, string Url, bool IsIp, int? RequestedPort);
    private sealed record HttpOne(JsonObject Report, string Body, string Url, JsonObject Headers, int Status, string? Location);
    private sealed record WebProbe(JsonObject? Report, string Body, string? FinalUrl, JsonObject Headers);

    public async Task<JsonObject> LookupAsync(string input, bool ipOnly, AppSettings settings, CancellationToken ct, IProgress<LookupUpdate>? progress = null)
    {
        var started = Stopwatch.StartNew();
        var target = ParseTarget(input, ipOnly);
        progress?.Report(new LookupUpdate("meta", null, "Resolving public addresses"));

        var resolveTask = ResolvePublicAsync(target.Host, ct);
        var dnsTask = GatherDnsAsync(target.Host, ct);
        var domainRdapTask = target.IsIp ? Task.FromResult<JsonObject?>(null) : FindDomainRdapAsync(target.Host, ct);
        var webTask = ProbeHttpAsync(target, ct);
        var tlsPort = target.ExplicitScheme && target.Port == 8443 ? 8443 : 443;
        var tlsTask = ProbeTlsAsync(target.Host, tlsPort, ct);

        var resolved = await resolveTask;
        var primaryIp = resolved.FirstOrDefault()?.ToString() ?? throw new InvalidOperationException("Target did not resolve to a public IP address.");

        var ipRdapTask = LookupIpRdapAsync(primaryIp, ct);
        var ipIntelTask = BuildIpIntelAsync(primaryIp, settings, ipRdapTask, ct);
        var routingTask = BuildRoutingAsync(primaryIp, settings.DeepRouting, ct);
        var serviceTask = ScanServicesAsync(primaryIp, settings.ScanMode, settings.ScanTimeoutMs, ct);
        var networkTask = BuildNetworkMeasurementsAsync(primaryIp, settings.DeepRouting, ct);
        var reputationTask = BuildReputationAsync(primaryIp, settings, ct);
        var minecraftTask = settings.MinecraftEnabled
            ? MinecraftLookupAsync(MinecraftAddress(target), ct)
            : Task.FromResult<JsonObject?>(new JsonObject
            {
                ["address"] = MinecraftAddress(target),
                ["skipped"] = true,
                ["cacheNote"] = "Disabled"
            });

        var dns = await dnsTask;
        progress?.Report(new LookupUpdate("dns", dns, "DNS complete"));

        var webProbe = await webTask;
        var web = webProbe.Report;
        progress?.Report(new LookupUpdate("web", web, web is null ? "HTTP probe returned no response" : "HTTP complete"));

        var tls = await tlsTask;
        progress?.Report(new LookupUpdate("tls", tls, tls?["available"]?.GetValue<bool>() == true ? "TLS complete" : "TLS probe finished"));

        var domainRdap = await domainRdapTask;
        var rootDomain = GetString(domainRdap?["rootDomain"]);
        var emailTask = string.IsNullOrWhiteSpace(rootDomain) ? Task.FromResult<JsonObject?>(null) : EmailDnsAsync(rootDomain!, ct);
        var resourcesTask = webProbe.FinalUrl is null ? Task.FromResult<JsonObject?>(null) : ProbeSiteResourcesAsync(webProbe.FinalUrl, ct);

        var ipRdap = await ipRdapTask;
        var ipIntel = await ipIntelTask;
        progress?.Report(new LookupUpdate("ipIntel", ipIntel, "IP intelligence complete"));

        var routing = await routingTask;
        progress?.Report(new LookupUpdate("routing", routing, "Routing intelligence complete"));

        var network = await networkTask;
        network["resolvedAddresses"] = AddressesToArray(resolved);
        network["primaryIp"] = primaryIp;
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
        var summary = BuildSummary(target, primaryIp, dns, web, tls, edge, infrastructure, serviceScan, ipIntel, registration, minecraft, dnssec);

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
            Timeout = TimeSpan.FromSeconds(12)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json,text/plain,*/*");
        return client;
    }

    private static TargetInfo ParseTarget(string input, bool ipOnly)
    {
        var raw = input.Trim();
        if (raw.Length == 0) throw new ArgumentException("Enter a hostname, IP address or URL.");
        if (raw.Length > 300) throw new ArgumentException("Target is too long.");

        if (ipOnly)
        {
            var clean = raw.Trim('[', ']');
            if (!IPAddress.TryParse(clean, out var parsedIp) || !IsPublicIp(parsedIp))
                throw new ArgumentException("IP mode requires a public IPv4 or IPv6 address.");
            var host = parsedIp.ToString();
            var bracketed = parsedIp.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]" : host;
            return new TargetInfo(raw, host, 443, "https", "/", false, $"https://{bracketed}/", true, null);
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
            var isIp = IPAddress.TryParse(uri.Host, out var parsedIp);
            if (isIp && !IsPublicIp(parsedIp!)) throw new ArgumentException("Private, local and reserved IP ranges are not allowed.");
            var normalized = uri.GetLeftPart(UriPartial.Path);
            if (!string.IsNullOrWhiteSpace(uri.Query)) normalized += uri.Query;
            return new TargetInfo(raw, uri.Host.TrimEnd('.').ToLowerInvariant(), port, uri.Scheme, string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery, true, normalized, isIp, port);
        }

        var authority = raw.Split('/', 2)[0].Trim();
        string host;
        int? requestedPort = null;
        if (authority.StartsWith('['))
        {
            var end = authority.IndexOf(']');
            if (end < 0) throw new ArgumentException("Invalid IPv6 target.");
            host = authority[1..end];
            if (end + 1 < authority.Length && authority[end + 1] == ':' && int.TryParse(authority[(end + 2)..], out var bracketPort)) requestedPort = bracketPort;
        }
        else if (authority.Count(c => c == ':') == 1)
        {
            var split = authority.LastIndexOf(':');
            if (split > 0 && int.TryParse(authority[(split + 1)..], out var parsedPort))
            {
                host = authority[..split];
                requestedPort = parsedPort;
            }
            else host = authority;
        }
        else host = authority;

        host = host.Trim().TrimEnd('.').ToLowerInvariant();
        ValidateHostname(host);
        var targetIsIp = IPAddress.TryParse(host, out var directIp);
        if (targetIsIp && !IsPublicIp(directIp!)) throw new ArgumentException("Private, local and reserved IP ranges are not allowed.");
        if (requestedPort is < 1 or > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
        var bracketedHost = targetIsIp && directIp!.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{host}]" : host;
        return new TargetInfo(raw, host, requestedPort ?? 443, "https", "/", false, $"https://{bracketedHost}/", targetIsIp, requestedPort);
    }

    private static void ValidateHostname(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Target host is empty.");
        var h = host.TrimEnd('.').ToLowerInvariant();
        if (h == "localhost" || h.EndsWith(".localhost") || h.EndsWith(".local") || h.EndsWith(".internal") || h.EndsWith(".home") || h.EndsWith(".lan") || h.EndsWith(".test") || h.EndsWith(".invalid") || h.EndsWith(".example") || h == "metadata.google.internal" || h == "metadata.google")
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
            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal || ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Loopback)) return false;
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
        var result = new JsonArray();
        foreach (var address in addresses)
        {
            result.Add(new JsonObject
            {
                ["address"] = address.ToString(),
                ["family"] = address.AddressFamily == AddressFamily.InterNetworkV6 ? 6 : 4
            });
        }
        return result;
    }

    private static async Task<JsonNode?> FetchJsonAsync(string url, CancellationToken ct, IReadOnlyDictionary<string, string>? headers = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd(UserAgent);
        request.Headers.Accept.ParseAdd("application/json");
        if (headers is not null)
        {
            foreach (var pair in headers) request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        }
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            return new JsonObject
            {
                ["error"] = $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}",
                ["status"] = (int)response.StatusCode,
                ["body"] = text.Length > 3000 ? text[..3000] : text
            };
        }
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

    private static string? GetString(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue<string>(out var text)) return text;
        if (value.TryGetValue<long>(out var longValue)) return longValue.ToString(CultureInfo.InvariantCulture);
        if (value.TryGetValue<int>(out var intValue)) return intValue.ToString(CultureInfo.InvariantCulture);
        if (value.TryGetValue<double>(out var doubleValue)) return doubleValue.ToString(CultureInfo.InvariantCulture);
        if (value.TryGetValue<bool>(out var boolValue)) return boolValue ? "true" : "false";
        return null;
    }

    private static long? GetLong(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue<long>(out var longValue)) return longValue;
        if (value.TryGetValue<int>(out var intValue)) return intValue;
        if (value.TryGetValue<double>(out var doubleValue)) return (long)doubleValue;
        if (value.TryGetValue<string>(out var text) && long.TryParse(text, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed)) return parsed;
        return null;
    }

    private static double? GetDouble(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue<double>(out var doubleValue)) return doubleValue;
        if (value.TryGetValue<float>(out var floatValue)) return floatValue;
        if (value.TryGetValue<long>(out var longValue)) return longValue;
        if (value.TryGetValue<int>(out var intValue)) return intValue;
        if (value.TryGetValue<string>(out var text) && double.TryParse(text, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed)) return parsed;
        return null;
    }

    private static bool? GetBool(JsonNode? node)
    {
        if (node is not JsonValue value) return null;
        if (value.TryGetValue<bool>(out var boolValue)) return boolValue;
        if (value.TryGetValue<string>(out var text) && bool.TryParse(text, out var parsed)) return parsed;
        return null;
    }

    private static JsonNode? NodeAt(JsonNode? root, params string[] path)
    {
        var current = root;
        foreach (var key in path)
        {
            if (current is not JsonObject obj || !obj.TryGetPropertyValue(key, out var next)) return null;
            current = next;
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
        var match = Regex.Match(value, "(?:AS)?(\\d+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : value;
    }

    private static string[] StringArray(JsonNode? node)
    {
        return node is JsonArray array
            ? array.Select(GetString).Where(x => x is not null).Select(x => x!).ToArray()
            : [];
    }
}
