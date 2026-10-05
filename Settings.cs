using System.IO;
using System.Text.Json;

namespace tlk_hex;

public class Settings
{
    // Gorunum
    public bool Dark { get; set; }
    public double WinW { get; set; } = 1380;
    public double WinH { get; set; } = 860;
    public double WinX { get; set; } = double.NaN;
    public double WinY { get; set; } = double.NaN;
    public bool WinMax { get; set; }
    public string ThemeName { get; set; } = "purple";       // light / dark / purple
    public bool BackgroundOn { get; set; } = true;
    public string? BackgroundPath { get; set; }              // bos = gomulu varsayilan gorsel
    public double BackgroundDim { get; set; } = 0.15;        // gorsel ustu karartma (okunabilirlik)
    public string FontFamily { get; set; } = "Consolas";
    public double FontSize { get; set; } = 13;
    public bool GraphByDefault { get; set; } = true;
    public bool ShowQuickStart { get; set; } = true;
    public bool AskLoadOptions { get; set; } = false;
    public string SymbolMode { get; set; } = "ask";      // ask / always / never (Microsoft sembol sunucusu)   // acarken "yeni dosya yukle" penceresini goster

    // Disassembly
    public bool ShowPrefix { get; set; } = true;
    public int OpcodeBytes { get; set; } = 0;
    public int MaxXrefs { get; set; } = 8;
    public int MinStrLen { get; set; } = 5;
    public bool AutoSaveDb { get; set; } = false;

    // AI ayarlari
    public string AiProvider { get; set; } = "Anthropic";  // Anthropic | OpenAI
    public string? AiApiKey { get; set; }
    public string AiModel { get; set; } = "";
    public string AiBaseUrl { get; set; } = "";  // OpenAI uyumlu ozel uc nokta (opsiyonel)

    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tlk-hex");
    private static readonly string FilePath = Path.Combine(Dir, "settings.json");

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath)) ?? new Settings();
        }
        catch { }
        return new Settings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this,
                new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }
}
