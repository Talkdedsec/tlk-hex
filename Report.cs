using System.IO;
using System.Text;

namespace tlk_hex;

// Kendi kendine yeten (tek dosya) HTML analiz raporu uretir.
public static class Report
{
    public static void Save(string path, AnalysisResult r)
        => File.WriteAllText(path, Html(r), Encoding.UTF8);

    public static string Html(AnalysisResult r)
    {
        var sb = new StringBuilder();
        string name = Path.GetFileName(r.FilePath);
        string imphash = r.Findings.FirstOrDefault(f => f.Title == "imphash")?.Detail.Split(' ').FirstOrDefault() ?? "—";
        string bits = r.Architecture == "x64" ? "64-bit" : r.Architecture == "x86" ? "32-bit" : r.Architecture;

        sb.Append($@"<!doctype html><html lang=""tr""><head><meta charset=""utf-8"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1"">
<title>{E(name)} — analiz raporu</title>
<style>
:root{{--bg:#09080d;--bg2:#0e0c14;--line:#1c1826;--ink:#e7e5ef;--dim:#8e8aa0;--acc:#9d7cf0;--hi:#e0463a;--md:#d08a10;--lo:#3a7bd5;--mono:'Cascadia Mono','Consolas',ui-monospace,monospace}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 'Segoe UI',system-ui,sans-serif;padding:0 0 60px}}
.wrap{{max-width:1040px;margin:0 auto;padding:0 20px}}
header{{border-bottom:1px solid var(--line);padding:28px 0;margin-bottom:28px;background:var(--bg2)}}
h1{{margin:0 0 4px;font-size:24px}}
h1 .acc{{color:var(--acc)}}
h2{{font-size:16px;margin:30px 0 12px;border-left:3px solid var(--acc);padding-left:10px}}
.sub{{color:var(--dim);font-size:13px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin:14px 0}}
.kv{{background:var(--bg2);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.kv .k{{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
.kv .v{{font-family:var(--mono);font-size:14px;margin-top:3px;word-break:break-all}}
table{{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}}
th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}}
td.mono,.mono{{font-family:var(--mono)}}
.badge{{display:inline-block;padding:1px 8px;border-radius:6px;font-size:12px;font-weight:600}}
.sev-Yuksek{{color:var(--hi);border:1px solid var(--hi)}}
.sev-Orta{{color:var(--md);border:1px solid var(--md)}}
.sev-Bilgi{{color:var(--lo);border:1px solid var(--lo)}}
.pill{{display:inline-block;background:var(--bg2);border:1px solid var(--line);border-radius:20px;padding:2px 10px;margin:2px 4px 2px 0;font-size:12px;font-family:var(--mono)}}
footer{{color:var(--dim);font-size:12px;border-top:1px solid var(--line);margin-top:36px;padding-top:16px}}
a{{color:var(--acc)}}
</style></head><body>
<header><div class=""wrap"">
<h1>tlk<span class=""acc"">-</span>hex · analiz raporu</h1>
<div class=""sub"">{E(name)} — {bits} {E(r.FileType)}{(r.IsDotNet ? " · .NET" : "")}{(r.IsSigned ? " · imzalı" : " · imzasız")}</div>
</div></header>
<div class=""wrap"">");

        // Ozet kartlari
        sb.Append("<div class=\"grid\">");
        Kv(sb, "Dosya", name);
        Kv(sb, "Boyut", FormatSize(r.FileSize));
        Kv(sb, "Mimari", $"{bits} ({E(r.Architecture)})");
        Kv(sb, "Giriş noktası", r.EntryPoint);
        Kv(sb, "Image base", r.ImageBase);
        Kv(sb, "Derleme zamanı", r.Timestamp);
        Kv(sb, "imphash", imphash);
        Kv(sb, "İmza", r.IsSigned ? "var" : "yok");
        sb.Append("</div>");
        sb.Append($"<p class=\"sub\">{r.Imports.Count:N0} import · {r.Exports.Count:N0} export · {r.Functions.Count:N0} fonksiyon · {r.Strings.Count:N0} string · analiz {r.AnalysisSeconds:0.00} sn</p>");

        // Bulgular
        sb.Append("<h2>Bulgular</h2>");
        if (r.Findings.Count == 0) sb.Append("<p class=\"sub\">Bulgu yok.</p>");
        else
        {
            sb.Append("<table><tr><th>Önem</th><th>Kategori</th><th>Bulgu</th><th>Ayrıntı</th></tr>");
            foreach (var f in r.Findings)
                sb.Append($"<tr><td><span class=\"badge sev-{E(f.Severity)}\">{E(f.Severity)}</span></td>"
                    + $"<td>{E(f.Category)}</td><td>{E(f.Title)}</td><td>{E(f.Detail)}</td></tr>");
            sb.Append("</table>");
        }

        // Bolumler
        if (r.Sections.Count > 0)
        {
            sb.Append("<h2>Bölümler</h2><table><tr><th>Ad</th><th>Sanal adres</th><th>Sanal boyut</th><th>Ham boyut</th><th>Entropi</th><th>Bayrak</th></tr>");
            foreach (var s in r.Sections)
                sb.Append($"<tr><td class=\"mono\">{E(s.Name)}</td><td class=\"mono\">{E(s.VirtualAddress)}</td>"
                    + $"<td class=\"mono\">{E(s.VirtualSize)}</td><td class=\"mono\">{E(s.RawSize)}</td>"
                    + $"<td class=\"mono\">{E(s.Entropy)}</td><td class=\"mono\">{E(s.Flags)}</td></tr>");
            sb.Append("</table>");
        }

        // Importlar (DLL'e gore grupli)
        if (r.Imports.Count > 0)
        {
            sb.Append("<h2>Importlar (DLL başına)</h2>");
            var byDll = r.Imports.GroupBy(i => i.Dll).OrderByDescending(g => g.Count());
            sb.Append("<table><tr><th>DLL</th><th>Sayı</th><th>Fonksiyonlar (ilk 30)</th></tr>");
            foreach (var g in byDll)
            {
                var fns = string.Join(", ", g.Select(i => i.Function).Take(30));
                if (g.Count() > 30) fns += $", … (+{g.Count() - 30})";
                sb.Append($"<tr><td class=\"mono\">{E(g.Key)}</td><td>{g.Count()}</td><td class=\"mono\" style=\"color:var(--dim)\">{E(fns)}</td></tr>");
            }
            sb.Append("</table>");
        }

        // Dikkat ceken stringler
        var urls = r.Strings.Where(s => s.Value.Contains("http://") || s.Value.Contains("https://")).Select(s => s.Value).Distinct().Take(40).ToList();
        if (urls.Count > 0)
        {
            sb.Append("<h2>URL / bağlantı göstergeleri</h2><p>");
            foreach (var u in urls) sb.Append($"<span class=\"pill\">{E(u)}</span>");
            sb.Append("</p>");
        }
        var longest = r.Strings.Where(s => s.Length >= 6).OrderByDescending(s => s.Length).Take(40).ToList();
        if (longest.Count > 0)
        {
            sb.Append("<h2>En uzun stringler</h2><table><tr><th>Uzunluk</th><th>Kodlama</th><th>Değer</th></tr>");
            foreach (var s in longest)
                sb.Append($"<tr><td class=\"mono\">{s.Length}</td><td class=\"mono\">{E(s.Encoding)}</td><td class=\"mono\">{E(Clip(s.Value, 180))}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append($@"<footer>
tlk-hex ile üretildi · <a href=""https://github.com/Talkdedsec/tlk-hex"">github.com/Talkdedsec/tlk-hex</a><br>
Yalnızca yetkili analiz, eğitim ve araştırma içindir. Rapor {DateTime.Now:yyyy-MM-dd HH:mm} tarihinde oluşturuldu.
</footer></div></body></html>");
        return sb.ToString();
    }

    private static void Kv(StringBuilder sb, string k, string v)
        => sb.Append($"<div class=\"kv\"><div class=\"k\">{E(k)}</div><div class=\"v\">{E(string.IsNullOrEmpty(v) ? "—" : v)}</div></div>");

    private static string Clip(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private static string E(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(c switch
            {
                '&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;", '\'' => "&#39;",
                _ => c < 0x20 && c != '\t' ? "." : c.ToString(),
            });
        return sb.ToString();
    }

    private static string FormatSize(long bytes)
    {
        string[] u = { "B", "KB", "MB", "GB" };
        double size = bytes; int i = 0;
        while (size >= 1024 && i < u.Length - 1) { size /= 1024; i++; }
        return i == 0 ? $"{bytes} B" : $"{size:0.##} {u[i]}";
    }
}
