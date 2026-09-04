using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ServerStatusApp;

public sealed partial class NetworkEngine
{
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
            result["dnssec"] = new JsonObject
            {
                ["authenticatedData"] = false,
                ["note"] = "Direct IP target"
            };
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
        result["soa"] = soaRaw.Count > 0 ? ParseSoa(GetString(soaRaw[0]) ?? "") : null;
        result["naptr"] = AnswerStrings(tasks["naptr"].Result, 35);
        result["dnssec"] = new JsonObject
        {
            ["status"] = GetLong(tasks["a"].Result["Status"]),
            ["authenticatedData"] = GetBool(tasks["a"].Result["AD"]),
            ["checkingDisabled"] = GetBool(tasks["a"].Result["CD"]),
            ["truncated"] = GetBool(tasks["a"].Result["TC"]),
            ["comment"] = GetString(tasks["a"].Result["Comment"])
        };

        var servicePrefixes = new[]
        {
            "_minecraft._tcp",
            "_minecraft._udp",
            "_sip._tcp",
            "_sip._udp",
            "_xmpp-server._tcp",
            "_xmpp-client._tcp"
        };
        var serviceTasks = servicePrefixes.ToDictionary(prefix => prefix, prefix => DnsQueryAsync($"{prefix}.{host}", 33, ct));
        await Task.WhenAll(serviceTasks.Values);
        var services = new JsonObject();
        foreach (var pair in serviceTasks)
        {
            var rows = ParseSrvArray(AnswerStrings(pair.Value.Result, 33));
            if (rows.Count > 0) services[pair.Key] = rows;
        }
        result["services"] = services;

        var firstIp = (result["a"] as JsonArray)?.FirstOrDefault() ?? (result["aaaa"] as JsonArray)?.FirstOrDefault();
        if (IPAddress.TryParse(GetString(firstIp), out var resolvedIp))
            result["ptr"] = await DnsAnswersArrayAsync(ReversePointer(resolvedIp), 12, ct);

        return result;
    }

    private static async Task<JsonObject> DnsQueryAsync(string name, int type, CancellationToken ct)
    {
        var node = await SafeJsonAsync($"https://dns.google/resolve?name={Uri.EscapeDataString(name)}&type={type}&do=1", ct);
        return node as JsonObject ?? new JsonObject { ["error"] = "No DNS response" };
    }

    private static JsonArray AnswerStrings(JsonObject response, int type)
    {
        var result = new JsonArray();
        if (response["Answer"] is not JsonArray answers) return result;
        foreach (var answer in answers.OfType<JsonObject>())
        {
            if (GetLong(answer["type"]) == type && GetString(answer["data"]) is { } data)
                result.Add(data);
        }
        return result;
    }

    private static async Task<JsonArray> DnsAnswersArrayAsync(string name, int type, CancellationToken ct)
    {
        return AnswerStrings(await DnsQueryAsync(name, type, ct), type);
    }

    private static JsonArray StripDotArray(JsonArray input)
    {
        var result = new JsonArray();
        foreach (var node in input)
        {
            if (GetString(node) is { } value) result.Add(value.TrimEnd('.'));
        }
        return result;
    }

    private static JsonArray ParseTxtArray(JsonArray input)
    {
        var result = new JsonArray();
        foreach (var node in input)
        {
            var value = GetString(node) ?? "";
            var matches = Regex.Matches(value, "\"((?:\\\\.|[^\"\\\\])*)\"");
            if (matches.Count == 0)
            {
                result.Add(value);
                continue;
            }
            var builder = new StringBuilder();
            foreach (Match match in matches)
                builder.Append(match.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\"));
            result.Add(builder.ToString());
        }
        return result;
    }

    private static JsonArray ParseMxArray(JsonArray input)
    {
        var rows = new List<JsonObject>();
        foreach (var node in input)
        {
            var parts = (GetString(node) ?? "").Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 2 && int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out var priority))
            {
                rows.Add(new JsonObject
                {
                    ["priority"] = priority,
                    ["exchange"] = parts[1].TrimEnd('.')
                });
            }
        }
        var result = new JsonArray();
        foreach (var row in rows.OrderBy(row => row["priority"]?.GetValue<int>() ?? 0)) result.Add(row);
        return result;
    }

    private static JsonArray ParseSrvArray(JsonArray input)
    {
        var result = new JsonArray();
        foreach (var node in input)
        {
            var parts = (GetString(node) ?? "").Split(' ', 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 4) continue;
            if (!int.TryParse(parts[0], out var priority)) continue;
            if (!int.TryParse(parts[1], out var weight)) continue;
            if (!int.TryParse(parts[2], out var port)) continue;
            result.Add(new JsonObject
            {
                ["priority"] = priority,
                ["weight"] = weight,
                ["port"] = port,
                ["name"] = parts[3].TrimEnd('.')
            });
        }
        return result;
    }

    private static JsonArray ParseCaaArray(JsonArray input)
    {
        var result = new JsonArray();
        foreach (var node in input)
        {
            var value = GetString(node) ?? "";
            var match = Regex.Match(value, "^(\\d+)\\s+(\\S+)\\s+\"?(.*?)\"?$");
            if (!match.Success)
            {
                result.Add(new JsonObject { ["raw"] = value });
                continue;
            }
            result.Add(new JsonObject
            {
                ["critical"] = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture),
                ["tag"] = match.Groups[2].Value,
                ["value"] = match.Groups[3].Value.Trim('"')
            });
        }
        return result;
    }

    private static JsonObject ParseSoa(string value)
    {
        var parts = value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 7) return new JsonObject { ["raw"] = value };
        return new JsonObject
        {
            ["nsname"] = parts[0].TrimEnd('.'),
            ["hostmaster"] = parts[1].TrimEnd('.'),
            ["serial"] = NumberOrString(parts[2]),
            ["refresh"] = NumberOrString(parts[3]),
            ["retry"] = NumberOrString(parts[4]),
            ["expire"] = NumberOrString(parts[5]),
            ["minttl"] = NumberOrString(parts[6])
        };
    }

    private static JsonNode NumberOrString(string value)
    {
        return long.TryParse(value, out var number) ? JsonValue.Create(number)! : JsonValue.Create(value)!;
    }

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
            if (raw is not JsonObject rawObject || !string.IsNullOrWhiteSpace(GetString(rawObject["error"]))) continue;
            var parsed = ParseDomainRdap(rawObject);
            var registeredName = GetString(parsed["ldhName"]);
            if (string.IsNullOrWhiteSpace(registeredName)) continue;
            return new JsonObject
            {
                ["rootDomain"] = registeredName.ToLowerInvariant(),
                ["data"] = parsed
            };
        }
        return new JsonObject
        {
            ["rootDomain"] = labels.Length >= 2 ? string.Join('.', labels[^2..]) : host,
            ["data"] = null
        };
    }

    private static JsonObject ParseDomainRdap(JsonObject raw)
    {
        string? registrar = null;
        if (raw["entities"] is JsonArray entities)
        {
            foreach (var entity in entities.OfType<JsonObject>())
            {
                if (!StringArray(entity["roles"]).Any(role => role.Equals("registrar", StringComparison.OrdinalIgnoreCase))) continue;
                registrar = EntityName(entity);
                break;
            }
        }

        var nameservers = new JsonArray();
        if (raw["nameservers"] is JsonArray ns)
        {
            foreach (var item in ns.OfType<JsonObject>())
            {
                var name = GetString(item["ldhName"]) ?? GetString(item["unicodeName"]);
                if (!string.IsNullOrWhiteSpace(name)) nameservers.Add(name);
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
        if (raw is not JsonObject rawObject || !string.IsNullOrWhiteSpace(GetString(rawObject["error"]))) return raw as JsonObject;

        var entities = new JsonArray();
        if (rawObject["entities"] is JsonArray rawEntities)
        {
            foreach (var entity in rawEntities.OfType<JsonObject>())
            {
                entities.Add(new JsonObject
                {
                    ["name"] = EntityName(entity),
                    ["handle"] = GetString(entity["handle"]),
                    ["roles"] = entity["roles"]?.DeepClone(),
                    ["vcard"] = entity["vcardArray"]?.DeepClone()
                });
            }
        }

        return new JsonObject
        {
            ["handle"] = GetString(rawObject["handle"]),
            ["name"] = GetString(rawObject["name"]),
            ["type"] = GetString(rawObject["type"]),
            ["startAddress"] = GetString(rawObject["startAddress"]),
            ["endAddress"] = GetString(rawObject["endAddress"]),
            ["ipVersion"] = GetString(rawObject["ipVersion"]),
            ["country"] = GetString(rawObject["country"]),
            ["parentHandle"] = GetString(rawObject["parentHandle"]),
            ["status"] = rawObject["status"]?.DeepClone(),
            ["events"] = RdapEvents(rawObject),
            ["entities"] = entities,
            ["remarks"] = rawObject["remarks"]?.DeepClone(),
            ["notices"] = rawObject["notices"]?.DeepClone(),
            ["links"] = rawObject["links"]?.DeepClone(),
            ["raw"] = rawObject.DeepClone()
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
        var result = new JsonObject();
        if (raw["events"] is not JsonArray events) return result;
        foreach (var item in events.OfType<JsonObject>())
        {
            var action = GetString(item["eventAction"]);
            var date = GetString(item["eventDate"]);
            if (!string.IsNullOrWhiteSpace(action) && !string.IsNullOrWhiteSpace(date)) result[action] = date;
        }
        return result;
    }

    private static async Task<JsonObject?> EmailDnsAsync(string domain, CancellationToken ct)
    {
        var mxTask = DnsQueryAsync(domain, 15, ct);
        var txtTask = DnsQueryAsync(domain, 16, ct);
        var dmarcTask = DnsQueryAsync($"_dmarc.{domain}", 16, ct);
        var mtaTask = DnsQueryAsync($"_mta-sts.{domain}", 16, ct);
        var bimiTask = DnsQueryAsync($"default._bimi.{domain}", 16, ct);
        await Task.WhenAll(mxTask, txtTask, dmarcTask, mtaTask, bimiTask);

        var txt = ParseTxtArray(AnswerStrings(txtTask.Result, 16));
        var spf = new JsonArray();
        foreach (var item in txt)
        {
            var value = GetString(item);
            if (value?.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase) == true) spf.Add(value);
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
            ["cacheNote"] = "mcsrvstat.us can cache status data upstream for several minutes."
        };
    }

    private static string MinecraftAddress(TargetInfo target)
    {
        if (target.RequestedPort is null) return target.Host;
        if (IPAddress.TryParse(target.Host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
            return $"[{target.Host}]:{target.RequestedPort}";
        return $"{target.Host}:{target.RequestedPort}";
    }

    private static JsonObject BuildRegistration(JsonObject? domainRdap, JsonObject? ipRdap)
    {
        var domain = domainRdap?["data"]?.DeepClone();
        if (domain is JsonObject domainObject && domainObject["events"] is JsonObject events)
        {
            var registrationDate = GetString(events["registration"]);
            if (DateTimeOffset.TryParse(registrationDate, out var created))
            {
                var days = Math.Max(0, (DateTimeOffset.UtcNow - created).Days);
                domainObject["domainAge"] = new JsonObject
                {
                    ["days"] = days,
                    ["years"] = Math.Round(days / 365.2425, 2)
                };
            }
        }
        return new JsonObject
        {
            ["domain"] = domain,
            ["ip"] = ipRdap?.DeepClone()
        };
    }

    private static JsonObject BuildDnssecSummary(JsonObject dns)
    {
        return dns["dnssec"]?.DeepClone() as JsonObject ?? new JsonObject { ["authenticatedData"] = false };
    }
}
