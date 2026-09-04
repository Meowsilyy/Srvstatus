using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ServerStatusApp;

public sealed class AppSettings
{
    public string Theme { get; set; } = "dark";
    public bool Compact { get; set; }
    public string ScanMode { get; set; } = "common";
    public int ScanTimeoutMs { get; set; } = 500;
    public bool ShowClosedServices { get; set; }
    public bool MinecraftEnabled { get; set; } = true;
    public bool LocationCrossCheck { get; set; } = true;
    public bool DeepRouting { get; set; } = true;
    public bool RestoreLastTarget { get; set; }
    public bool RememberRecent { get; set; } = true;
    public string LastTarget { get; set; } = "";
    public List<string> RecentTargets { get; set; } = [];
    public string IpApiIsKey { get; set; } = "";
    public string AbuseIpDbKey { get; set; } = "";
    public string ShodanKey { get; set; } = "";
    public string VirusTotalKey { get; set; } = "";
}

public sealed record LookupUpdate(string Section, JsonNode? Data, string Message);

public static class SettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string DirectoryPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ServerStatus");
    public static string FilePath => Path.Combine(DirectoryPath, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new AppSettings();
            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<AppSettings>(json, Options) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(AppSettings settings)
    {
        Directory.CreateDirectory(DirectoryPath);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(settings, Options));
    }

    public static void RememberTarget(AppSettings settings, string target)
    {
        settings.LastTarget = target;
        if (settings.RememberRecent)
        {
            settings.RecentTargets.RemoveAll(x => string.Equals(x, target, StringComparison.OrdinalIgnoreCase));
            settings.RecentTargets.Insert(0, target);
            if (settings.RecentTargets.Count > 6)
                settings.RecentTargets.RemoveRange(6, settings.RecentTargets.Count - 6);
        }
        Save(settings);
    }
}
