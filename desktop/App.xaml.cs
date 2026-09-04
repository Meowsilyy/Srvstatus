using System.Windows;
using System.Windows.Media;

namespace ServerStatusApp;

public partial class App : Application
{
    public static void ApplyTheme(string theme)
    {
        var resolved = theme;
        if (string.Equals(theme, "system", StringComparison.OrdinalIgnoreCase))
        {
            var color = SystemParameters.WindowGlassColor;
            var brightness = (color.R * 299 + color.G * 587 + color.B * 114) / 255000.0;
            resolved = brightness > 0.45 ? "light" : "dark";
        }

        if (string.Equals(resolved, "light", StringComparison.OrdinalIgnoreCase))
        {
            SetBrush("WindowBrush", "#F3F4F5");
            SetBrush("PanelBrush", "#FFFFFF");
            SetBrush("PanelRaisedBrush", "#F7F8F9");
            SetBrush("BorderBrushApp", "#D8DDE3");
            SetBrush("TextBrush", "#15191E");
            SetBrush("MutedBrush", "#65707C");
            SetBrush("AccentBrush", "#55718D");
            SetBrush("AccentSoftBrush", "#E8EEF3");
            SetBrush("GoodBrush", "#3F785A");
            SetBrush("WarnBrush", "#8C641F");
            SetBrush("BadBrush", "#9D4545");
        }
        else
        {
            SetBrush("WindowBrush", "#0A0B0D");
            SetBrush("PanelBrush", "#0F1114");
            SetBrush("PanelRaisedBrush", "#14171B");
            SetBrush("BorderBrushApp", "#242830");
            SetBrush("TextBrush", "#F0F2F5");
            SetBrush("MutedBrush", "#8C949E");
            SetBrush("AccentBrush", "#8FA7C2");
            SetBrush("AccentSoftBrush", "#1A222B");
            SetBrush("GoodBrush", "#9CC8AF");
            SetBrush("WarnBrush", "#D4B483");
            SetBrush("BadBrush", "#D38F8F");
        }
    }

    private static void SetBrush(string key, string hex)
    {
        Current.Resources[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }
}
