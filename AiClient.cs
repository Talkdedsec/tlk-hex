using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace tlk_hex;

public static class AiClient
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(90) };

    // Analiz sonucundan kompakt baglam uretir (token tasarrufu)
    public static string BuildContext(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Dosya: {System.IO.Path.GetFileName(r.FilePath)}");
        sb.AppendLine($"Tip: {r.FileType}, Mimari: {r.Architecture}, .NET: {r.IsDotNet}, Imzali: {r.IsSigned}");
        sb.AppendLine($"Boyut: {FormatSize(r.FileSize)}, Derleme: {r.Timestamp}");
        sb.AppendLine($"Sayilar: {r.Imports.Count} import, {r.Exports.Count} export, "
                      + $"{r.Functions.Count} fonksiyon, {r.Strings.Count} string");

        sb.AppendLine("\nBULGULAR:");
        foreach (var f in r.Findings)
            sb.AppendLine($"- [{f.Severity}/{f.Category}] {f.Title}: {f.Detail}");

        sb.AppendLine("\nONEMLI IMPORTLAR (ilk 60):");
        foreach (var i in r.Imports.Take(60))
            sb.AppendLine($"- {i.Dll}!{i.Function}");

        sb.AppendLine("\nDIKKAT CEKEN STRINGLER (ilk 40, uzun olanlar):");
        foreach (var s in r.Strings.Where(s => s.Length >= 6).OrderByDescending(s => s.Length).Take(40))
            sb.AppendLine($"- {s.Value}");

        return sb.ToString();
    }

    public static async Task<string> AskAsync(Settings cfg, string context, string question)
    {
        string key = cfg.AiApiKey ?? "";
        if (string.IsNullOrWhiteSpace(key))
            return "AI anahtari tanimli degil. Ayarlar > AI bolumunden anahtarini gir.";

        string system = "Sen bir tersine muhendislik ve zararli yazilim analizi uzmanisin. "
            + "Sana bir PE dosyasinin statik analiz ozeti verilecek. Turkce, kisa ve net yanitla. "
            + "Kesin kanit yoksa 'kesin degil' de. Abartma, sadece veriye dayan.";
        string userMsg = $"Statik analiz ozeti:\n\n{context}\n\nSoru: {question}";

        try
        {
            return cfg.AiProvider == "OpenAI"
                ? await OpenAiAsync(cfg, system, userMsg)
                : await AnthropicAsync(cfg, system, userMsg);
        }
        catch (Exception ex)
        {
            return $"AI hatasi: {ex.Message}";
        }
    }

    private static async Task<string> AnthropicAsync(Settings cfg, string system, string user)
    {
        var body = new
        {
            model = string.IsNullOrWhiteSpace(cfg.AiModel) ? "claude-sonnet-5-5" : cfg.AiModel,
            max_tokens = 1024,
            system,
            messages = new[] { new { role = "user", content = user } },
        };
        var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages");
        req.Headers.Add("x-api-key", cfg.AiApiKey);
        req.Headers.Add("anthropic-version", "2023-06-01");
        req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

        var resp = await Http.SendAsync(req);
        string txt = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) return $"API {(int)resp.StatusCode}: {Trim(txt)}";

        using var doc = JsonDocument.Parse(txt);
        return doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString() ?? "(bos yanit)";
    }

    private static async Task<string> OpenAiAsync(Settings cfg, string system, string user)
    {
        string baseUrl = string.IsNullOrWhiteSpace(cfg.AiBaseUrl)
            ? "https://api.openai.com/v1" : cfg.AiBaseUrl.TrimEnd('/');
        var body = new
        {
            model = string.IsNullOrWhiteSpace(cfg.AiModel) ? "gpt-4o-mini" : cfg.AiModel,
            messages = new[]
            {
                new { role = "system", content = system },
                new { role = "user", content = user },
            },
        };
        var req = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/chat/completions");
        req.Headers.Add("Authorization", $"Bearer {cfg.AiApiKey}");
        req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");

        var resp = await Http.SendAsync(req);
        string txt = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode) return $"API {(int)resp.StatusCode}: {Trim(txt)}";

        using var doc = JsonDocument.Parse(txt);
        return doc.RootElement.GetProperty("choices")[0].GetProperty("message")
                   .GetProperty("content").GetString() ?? "(bos yanit)";
    }

    private static string FormatSize(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB" };
        double size = bytes;
        int u = 0;
        while (size >= 1024 && u < units.Length - 1) { size /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{size:0.##} {units[u]}";
    }

    private static string Trim(string s) => s.Length <= 300 ? s : s[..300] + "...";
}
