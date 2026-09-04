using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace ServerStatusApp;

public partial class MainWindow : Window
{
    private static readonly string[] Sections =
    [
        "Overview", "Infrastructure", "IP Intel", "Services", "HTTP", "Edge", "Network", "Routing", "DNS", "TLS", "Security", "Reputation", "Registration", "Email DNS", "Technology", "Minecraft", "Site files", "Raw JSON"
    ];

    private static readonly Dictionary<string, string> SectionKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Overview"] = "summary",
        ["Infrastructure"] = "infrastructure",
        ["IP Intel"] = "ipIntel",
        ["Services"] = "serviceScan",
        ["HTTP"] = "web",
        ["Edge"] = "edge",
        ["Network"] = "network",
        ["Routing"] = "routing",
        ["DNS"] = "dns",
        ["TLS"] = "tls",
        ["Security"] = "security",
        ["Reputation"] = "reputation",
        ["Registration"] = "registration",
        ["Email DNS"] = "email",
        ["Technology"] = "technologies",
        ["Minecraft"] = "minecraft",
        ["Site files"] = "resources"
    };

    private static readonly Dictionary<string, string> Subtitles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Overview"] = "Fast summary of the target and the strongest signals returned by the lookup.",
        ["Infrastructure"] = "Observed provider, hosting stack, reverse DNS, edge and service ownership.",
        ["IP Intel"] = "Public IP ownership, geolocation cross-checks, ASN data, classification and raw provider responses.",
        ["Services"] = "Direct TCP checks against the selected public address.",
        ["HTTP"] = "Response metadata, redirect chain, timings, headers and page fingerprint information.",
        ["Edge"] = "CDN and edge-network fingerprints. Protected origins are not bypassed.",
        ["Network"] = "Resolved addresses, latency, packet loss, reverse DNS and route-path measurements.",
        ["Routing"] = "BGP, prefix, RIR, RPKI, PeeringDB and RIPEstat information.",
        ["DNS"] = "A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, NAPTR, PTR and selected SRV records.",
        ["TLS"] = "Certificate, chain validation, protocol, cipher, ALPN and fingerprint details.",
        ["Security"] = "HTTP security headers, cookie flags and a weighted configuration grade.",
        ["Reputation"] = "Public blocklist and optional AbuseIPDB, VirusTotal and Shodan intelligence.",
        ["Registration"] = "Domain and IP RDAP registration records and events.",
        ["Email DNS"] = "MX, SPF, DMARC, MTA-STS and BIMI records.",
        ["Technology"] = "Software, framework, CMS, hosting and edge fingerprints from observable responses.",
        ["Minecraft"] = "Java and Bedrock status from the same upstream source used by the website.",
        ["Site files"] = "robots.txt, sitemap.xml, security.txt and favicon probes from the same host.",
        ["Raw JSON"] = "Complete machine-readable result, including provider responses that are not promoted into the UI."
    };

    private readonly NetworkEngine _engine = new();
    private AppSettings _settings;
    private JsonObject? _report;
    private CancellationTokenSource? _cts;
    private DispatcherTimer? _timer;
    private Stopwatch? _watch;
    private bool _syncing;

    public MainWindow()
    {
        InitializeComponent();
        _settings = SettingsStore.Load();
        NavList.ItemsSource = Sections;
        NavList.SelectedIndex = 0;
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        SyncSettingsToUi();
        RefreshRecent();
        ApplyLayoutSettings();
        TargetInput.Focus();
        if (_settings.RestoreLastTarget && !string.IsNullOrWhiteSpace(_settings.LastTarget))
        {
            TargetInput.Text = _settings.LastTarget;
            await BeginLookupAsync();
        }
    }

    private void SyncSettingsToUi()
    {
        _syncing = true;
        SelectComboByTag(ThemeCombo, _settings.Theme);
        SelectComboByTag(ScanModeCombo, _settings.ScanMode);
        SelectComboByTag(ScanTimeoutCombo, _settings.ScanTimeoutMs.ToString());
        CompactCheck.IsChecked = _settings.Compact;
        ShowClosedCheck.IsChecked = _settings.ShowClosedServices;
        MinecraftCheck.IsChecked = _settings.MinecraftEnabled;
        LocationCrossCheckCheck.IsChecked = _settings.LocationCrossCheck;
        DeepRoutingCheck.IsChecked = _settings.DeepRouting;
        RestoreLastCheck.IsChecked = _settings.RestoreLastTarget;
        RecentCheck.IsChecked = _settings.RememberRecent;
        IpApiIsKeyBox.Password = _settings.IpApiIsKey;
        AbuseKeyBox.Password = _settings.AbuseIpDbKey;
        ShodanKeyBox.Password = _settings.ShodanKey;
        VirusTotalKeyBox.Password = _settings.VirusTotalKey;
        _syncing = false;
        App.ApplyTheme(_settings.Theme);
    }

    private static void SelectComboByTag(ComboBox combo, string value)
    {
        foreach (var item in combo.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), value, StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedItem = item;
                return;
            }
        }
        combo.SelectedIndex = 0;
    }

    private static string ComboTag(ComboBox combo, string fallback)
    {
        return (combo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? fallback;
    }

    private void Settings_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        _settings.Theme = ComboTag(ThemeCombo, "dark");
        _settings.ScanMode = ComboTag(ScanModeCombo, "common");
        _settings.ScanTimeoutMs = int.TryParse(ComboTag(ScanTimeoutCombo, "500"), out var timeout) ? timeout : 500;
        _settings.Compact = CompactCheck.IsChecked == true;
        _settings.ShowClosedServices = ShowClosedCheck.IsChecked == true;
        _settings.MinecraftEnabled = MinecraftCheck.IsChecked == true;
        _settings.LocationCrossCheck = LocationCrossCheckCheck.IsChecked == true;
        _settings.DeepRouting = DeepRoutingCheck.IsChecked == true;
        _settings.RestoreLastTarget = RestoreLastCheck.IsChecked == true;
        _settings.RememberRecent = RecentCheck.IsChecked == true;
        SettingsStore.Save(_settings);
        App.ApplyTheme(_settings.Theme);
        ApplyLayoutSettings();
        RefreshRecent();
        if (NavList.SelectedItem?.ToString() == "Services") RenderSelectedSection();
    }

    private void ApiKey_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncing) return;
        _settings.IpApiIsKey = IpApiIsKeyBox.Password.Trim();
        _settings.AbuseIpDbKey = AbuseKeyBox.Password.Trim();
        _settings.ShodanKey = ShodanKeyBox.Password.Trim();
        _settings.VirusTotalKey = VirusTotalKeyBox.Password.Trim();
        SettingsStore.Save(_settings);
    }

    private void ApplyLayoutSettings()
    {
        ContentHost.Margin = _settings.Compact ? new Thickness(18, 14, 18, 24) : new Thickness(22, 20, 22, 36);
    }

    private void RefreshRecent()
    {
        RecentItems.ItemsSource = _settings.RememberRecent ? _settings.RecentTargets.ToArray() : Array.Empty<string>();
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        SettingsPanel.Visibility = SettingsPanel.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
    }

    private void CloseSettings_Click(object sender, RoutedEventArgs e)
    {
        SettingsPanel.Visibility = Visibility.Collapsed;
    }

    private void ClearRecent_Click(object sender, RoutedEventArgs e)
    {
        _settings.RecentTargets.Clear();
        SettingsStore.Save(_settings);
        RefreshRecent();
    }

    private void ResetSettings_Click(object sender, RoutedEventArgs e)
    {
        _settings = new AppSettings();
        SettingsStore.Save(_settings);
        SyncSettingsToUi();
        RefreshRecent();
        ApplyLayoutSettings();
    }

    private void Mode_Checked(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        TargetHint.Text = IpModeButton.IsChecked == true ? "Public IPv4 or IPv6 address" : "Domain, URL, IP or Minecraft address";
    }

    private async void LookupButton_Click(object sender, RoutedEventArgs e)
    {
        await BeginLookupAsync();
    }

    private async void TargetInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            await BeginLookupAsync();
        }
    }

    private async void RecentTarget_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.Tag is not string target) return;
        TargetInput.Text = target;
        await BeginLookupAsync();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }

    private async Task BeginLookupAsync()
    {
        var target = TargetInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(target))
        {
            ShowMessage("Enter a target.", "A domain, URL, public IP or Minecraft address is required.");
            return;
        }

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _report = new JsonObject();
        StartRunUi(target);

        var progress = new Progress<LookupUpdate>(update =>
        {
            if (update.Data is not null)
                _report![update.Section] = update.Data.DeepClone();
            ProgressText.Text = update.Message;
            var selected = NavList.SelectedItem?.ToString();
            if (selected is not null && SectionKeys.TryGetValue(selected, out var key) && string.Equals(key, update.Section, StringComparison.OrdinalIgnoreCase))
                RenderSelectedSection();
        });

        try
        {
            var result = await _engine.LookupAsync(target, IpModeButton.IsChecked == true, _settings, token, progress);
            _report = result;
            SettingsStore.RememberTarget(_settings, target);
            RefreshRecent();
            RunStateText.Text = "Complete";
            ProgressText.Text = "Complete";
            NavList.SelectedIndex = 0;
            RenderSelectedSection();
        }
        catch (OperationCanceledException)
        {
            RunStateText.Text = "Cancelled";
            ProgressText.Text = "Cancelled";
        }
        catch (Exception ex)
        {
            RunStateText.Text = "Failed";
            ShowMessage("Lookup failed", ex.Message);
        }
        finally
        {
            StopRunUi();
        }
    }

    private void StartRunUi(string target)
    {
        LookupButton.IsEnabled = false;
        CancelButton.Visibility = Visibility.Visible;
        ProgressStrip.Visibility = Visibility.Visible;
        ProgressText.Text = $"Resolving {target}";
        RunStateText.Text = "Running";
        _watch = Stopwatch.StartNew();
        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _timer.Tick += (_, _) => RunTimeText.Text = $"{_watch.Elapsed.TotalSeconds:0.0}s";
        _timer.Start();
    }

    private void StopRunUi()
    {
        _timer?.Stop();
        _watch?.Stop();
        if (_watch is not null) RunTimeText.Text = $"{_watch.Elapsed.TotalSeconds:0.0}s";
        LookupButton.IsEnabled = true;
        CancelButton.Visibility = Visibility.Collapsed;
        ProgressStrip.Visibility = Visibility.Collapsed;
    }

    private void NavList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RenderSelectedSection();
    }

    private void RenderSelectedSection()
    {
        if (!IsLoaded) return;
        var section = NavList.SelectedItem?.ToString() ?? "Overview";
        SectionTitle.Text = section;
        SectionSubtitle.Text = Subtitles.GetValueOrDefault(section, "");
        SectionBody.Children.Clear();

        if (_report is null || _report.Count == 0)
        {
            AddNotice("No lookup data yet.");
            return;
        }

        if (section == "Raw JSON")
        {
            RenderRaw();
            return;
        }

        if (!SectionKeys.TryGetValue(section, out var key) || !_report.TryGetPropertyValue(key, out var node) || node is null)
        {
            AddNotice("This section has not returned data yet.");
            return;
        }

        if (section == "Overview" && node is JsonObject summary)
        {
            RenderOverview(summary);
            return;
        }

        if (section == "Services" && node is JsonObject services)
        {
            RenderServices(services);
            return;
        }

        RenderNode(node, section, 0);
    }

    private void RenderOverview(JsonObject summary)
    {
        var order = new[]
        {
            "target", "httpStatus", "primaryIp", "networkProvider", "networkOwner", "asn", "location", "edgeProvider", "server", "openPortCount", "tlsVersion", "httpVersion", "dnsProvider", "mailProvider", "registrar", "domainAgeYears", "ipv6Supported", "minecraftJavaOnline", "minecraftBedrockOnline"
        };

        var wrap = new WrapPanel { Orientation = Orientation.Horizontal };
        foreach (var key in order)
        {
            if (!summary.TryGetPropertyValue(key, out var value)) continue;
            var card = new Border
            {
                Width = 210,
                MinHeight = 84,
                Margin = new Thickness(0, 0, 10, 10),
                Padding = new Thickness(12),
                CornerRadius = new CornerRadius(7),
                Background = Brush("PanelBrush"),
                BorderBrush = Brush("BorderBrushApp"),
                BorderThickness = new Thickness(1)
            };
            var stack = new StackPanel();
            stack.Children.Add(new TextBlock
            {
                Text = FriendlyName(key),
                Foreground = Brush("MutedBrush"),
                FontSize = 11,
                Margin = new Thickness(0, 0, 0, 7)
            });
            stack.Children.Add(new TextBlock
            {
                Text = FormatNode(value),
                Foreground = Brush("TextBrush"),
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                TextWrapping = TextWrapping.Wrap
            });
            card.Child = stack;
            wrap.Children.Add(card);
        }
        SectionBody.Children.Add(wrap);

        var extras = new JsonObject();
        foreach (var pair in summary)
        {
            if (!order.Contains(pair.Key)) extras[pair.Key] = pair.Value?.DeepClone();
        }
        if (extras.Count > 0) RenderNode(extras, "Additional summary", 0);
    }

    private void RenderServices(JsonObject services)
    {
        var header = new JsonObject();
        foreach (var pair in services)
        {
            if (pair.Key != "results") header[pair.Key] = pair.Value?.DeepClone();
        }
        RenderNode(header, "Scan", 0);

        if (services["results"] is not JsonArray results || results.Count == 0)
        {
            AddNotice("No service scan results returned.");
            return;
        }

        var filtered = new JsonArray();
        foreach (var item in results)
        {
            if (item is not JsonObject row) continue;
            var open = row["open"]?.GetValue<bool>() == true;
            if (open || _settings.ShowClosedServices) filtered.Add(row.DeepClone());
        }
        RenderNode(filtered, _settings.ShowClosedServices ? "Checked ports" : "Open services", 0);
    }

    private void RenderRaw()
    {
        var toolbar = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 0, 0, 8) };
        var copy = new Button { Content = "Copy JSON", Padding = new Thickness(12, 6, 12, 6) };
        copy.Click += (_, _) => Clipboard.SetText(_report!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        toolbar.Children.Add(copy);
        SectionBody.Children.Add(toolbar);
        var box = new TextBox
        {
            Text = _report!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }),
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.NoWrap,
            FontFamily = new FontFamily("Cascadia Mono, Consolas"),
            FontSize = 12,
            MinHeight = 520,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        SectionBody.Children.Add(box);
    }

    private void RenderNode(JsonNode node, string title, int depth)
    {
        if (depth > 5)
        {
            AddValueBlock(title, node.ToJsonString());
            return;
        }

        if (node is JsonObject obj)
        {
            var simple = new List<KeyValuePair<string, JsonNode?>>();
            var complex = new List<KeyValuePair<string, JsonNode?>>();
            foreach (var pair in obj)
            {
                if (IsSimple(pair.Value)) simple.Add(pair);
                else complex.Add(pair);
            }
            if (simple.Count > 0) AddKeyValueBlock(title, simple);
            foreach (var pair in complex)
            {
                if (pair.Value is not null) RenderNode(pair.Value, FriendlyName(pair.Key), depth + 1);
            }
            if (simple.Count == 0 && complex.Count == 0) AddNotice($"{title}: no data returned.");
            return;
        }

        if (node is JsonArray array)
        {
            AddArrayBlock(title, array, depth);
            return;
        }

        AddValueBlock(title, FormatNode(node));
    }

    private void AddKeyValueBlock(string title, IEnumerable<KeyValuePair<string, JsonNode?>> pairs)
    {
        var border = NewSectionBorder();
        var stack = new StackPanel();
        stack.Children.Add(BlockTitle(title));
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(190) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var row = 0;
        foreach (var pair in pairs)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var label = new TextBlock
            {
                Text = FriendlyName(pair.Key),
                Foreground = Brush("MutedBrush"),
                FontSize = 12,
                Margin = new Thickness(0, 5, 12, 5),
                TextWrapping = TextWrapping.Wrap
            };
            var value = new TextBlock
            {
                Text = FormatNode(pair.Value),
                Foreground = Brush("TextBrush"),
                FontFamily = LooksTechnical(pair.Key, pair.Value) ? new FontFamily("Cascadia Mono, Consolas") : FontFamily,
                FontSize = 12,
                Margin = new Thickness(0, 5, 0, 5),
                TextWrapping = TextWrapping.Wrap
            };
            Grid.SetRow(label, row);
            Grid.SetColumn(label, 0);
            Grid.SetRow(value, row);
            Grid.SetColumn(value, 1);
            grid.Children.Add(label);
            grid.Children.Add(value);
            row++;
        }
        stack.Children.Add(grid);
        border.Child = stack;
        SectionBody.Children.Add(border);
    }

    private void AddArrayBlock(string title, JsonArray array, int depth)
    {
        var border = NewSectionBorder();
        var stack = new StackPanel();
        stack.Children.Add(BlockTitle($"{title} · {array.Count}"));
        if (array.Count == 0)
        {
            stack.Children.Add(new TextBlock { Text = "No data returned.", Foreground = Brush("MutedBrush") });
            border.Child = stack;
            SectionBody.Children.Add(border);
            return;
        }

        var limit = Math.Min(array.Count, 100);
        for (var i = 0; i < limit; i++)
        {
            var item = array[i];
            if (item is JsonObject obj)
            {
                var itemBorder = new Border
                {
                    Background = Brush("PanelRaisedBrush"),
                    BorderBrush = Brush("BorderBrushApp"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(5),
                    Padding = new Thickness(10),
                    Margin = new Thickness(0, 0, 0, 7)
                };
                var itemStack = new StackPanel();
                var simple = obj.Where(x => IsSimple(x.Value)).ToList();
                if (simple.Count > 0)
                {
                    var grid = new Grid();
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
                    grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    var r = 0;
                    foreach (var pair in simple)
                    {
                        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                        var label = new TextBlock { Text = FriendlyName(pair.Key), Foreground = Brush("MutedBrush"), FontSize = 11, Margin = new Thickness(0, 3, 10, 3) };
                        var value = new TextBlock { Text = FormatNode(pair.Value), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 3), FontFamily = LooksTechnical(pair.Key, pair.Value) ? new FontFamily("Cascadia Mono, Consolas") : FontFamily };
                        Grid.SetRow(label, r); Grid.SetColumn(label, 0);
                        Grid.SetRow(value, r); Grid.SetColumn(value, 1);
                        grid.Children.Add(label); grid.Children.Add(value);
                        r++;
                    }
                    itemStack.Children.Add(grid);
                }
                foreach (var pair in obj.Where(x => !IsSimple(x.Value)))
                {
                    itemStack.Children.Add(new TextBlock { Text = $"{FriendlyName(pair.Key)}: {FormatNode(pair.Value)}", FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 5, 0, 0) });
                }
                itemBorder.Child = itemStack;
                stack.Children.Add(itemBorder);
            }
            else
            {
                stack.Children.Add(new TextBlock { Text = FormatNode(item), FontFamily = new FontFamily("Cascadia Mono, Consolas"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 3) });
            }
        }

        if (array.Count > limit)
            stack.Children.Add(new TextBlock { Text = $"UI preview limited to {limit} rows. Raw JSON contains all {array.Count}.", Foreground = Brush("MutedBrush"), FontSize = 11, Margin = new Thickness(0, 6, 0, 0) });
        border.Child = stack;
        SectionBody.Children.Add(border);
    }

    private void AddValueBlock(string title, string value)
    {
        var border = NewSectionBorder();
        border.Child = new StackPanel
        {
            Children =
            {
                BlockTitle(title),
                new TextBlock { Text = value, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Cascadia Mono, Consolas"), FontSize = 12 }
            }
        };
        SectionBody.Children.Add(border);
    }

    private void AddNotice(string text)
    {
        var border = NewSectionBorder();
        border.Child = new TextBlock { Text = text, Foreground = Brush("MutedBrush"), FontSize = 12, TextWrapping = TextWrapping.Wrap };
        SectionBody.Children.Add(border);
    }

    private void ShowMessage(string title, string text)
    {
        SectionTitle.Text = title;
        SectionSubtitle.Text = text;
        SectionBody.Children.Clear();
        AddNotice(text);
    }

    private Border NewSectionBorder()
    {
        return new Border
        {
            Style = (Style)FindResource("SectionBorderStyle")
        };
    }

    private TextBlock BlockTitle(string title)
    {
        return new TextBlock
        {
            Text = title,
            FontSize = 13,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 10)
        };
    }

    private Brush Brush(string key) => (Brush)FindResource(key);

    private static bool IsSimple(JsonNode? node)
    {
        if (node is null || node is JsonValue) return true;
        if (node is JsonArray array) return array.Count <= 16 && array.All(x => x is null || x is JsonValue);
        return false;
    }

    private static string FormatNode(JsonNode? node)
    {
        if (node is null) return "—";
        if (node is JsonValue value)
        {
            if (value.TryGetValue<string>(out var s)) return string.IsNullOrWhiteSpace(s) ? "—" : s;
            if (value.TryGetValue<bool>(out var b)) return b ? "YES" : "NO";
            if (value.TryGetValue<long>(out var l)) return l.ToString("N0");
            if (value.TryGetValue<double>(out var d)) return d.ToString("0.###");
            return value.ToJsonString().Trim('"');
        }
        if (node is JsonArray array && array.All(x => x is null || x is JsonValue))
            return string.Join(", ", array.Select(FormatNode));
        var raw = node.ToJsonString();
        return raw.Length > 1200 ? raw[..1200] + "…" : raw;
    }

    private static bool LooksTechnical(string key, JsonNode? value)
    {
        var k = key.ToLowerInvariant();
        return k.Contains("ip") || k.Contains("address") || k.Contains("host") || k.Contains("asn") || k.Contains("prefix") || k.Contains("hash") || k.Contains("fingerprint") || k.Contains("url") || k.Contains("dns") || k.Contains("port") || k.Contains("cidr") || k.Contains("handle") || (value is JsonValue v && v.TryGetValue<string>(out var s) && (s.Contains(':') || s.Contains('.') || s.Contains('/')));
    }

    private static string FriendlyName(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return key;
        var chars = new List<char> { char.ToUpperInvariant(key[0]) };
        for (var i = 1; i < key.Length; i++)
        {
            if (char.IsUpper(key[i]) && !char.IsUpper(key[i - 1])) chars.Add(' ');
            else if (key[i] is '_' or '-') chars.Add(' ');
            else chars.Add(key[i]);
        }
        return new string(chars.ToArray());
    }
}
