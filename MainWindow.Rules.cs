using System.IO;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Kural tabanli tarama (YARA benzeri)
public partial class MainWindow
{
    private List<RuleMatch>? _ruleMatches;
    private string _ruleSource = "gömülü kurallar";

    private void ScanRuleFile()
    {
        if (_s == null) return;
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Kural dosyası seç",
            Filter = "YARA kuralları (*.yar;*.yara;*.txt)|*.yar;*.yara;*.txt|Tüm dosyalar (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) ScanRules(dlg.FileName);
    }

    private async void ScanRules(string? ruleFile)
    {
        if (_s == null || _busy) return;

        List<YaraRule> rules;
        try
        {
            rules = RuleScan.Builtins();
            if (ruleFile != null)
            {
                var extra = RuleScan.Parse(File.ReadAllText(ruleFile));
                if (extra.Count == 0)
                {
                    Dialogs.Info(this, "Kural taraması", "Dosyada ayrıştırılabilir kural bulunamadı.");
                    return;
                }
                rules.AddRange(extra);
                _ruleSource = $"gömülü + {Path.GetFileName(ruleFile)} ({extra.Count} kural)";
            }
            else _ruleSource = $"gömülü kurallar ({rules.Count})";
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", "Kurallar okunamadı:\n" + ex.Message); return; }

        _busy = true;
        UpdateEnabled();
        SetAu(true, "Kural taraması...");
        Mouse.OverrideCursor = Cursors.AppStarting;

        List<RuleMatch>? matches = null;
        try
        {
            var data = _s.Db.FileBytes;
            var strs = _s.Db.Strings.Select(s => s.Value).ToList();
            matches = await Task.Run(() => RuleScan.Scan(data, strs, rules));
        }
        catch (Exception ex) { _out.Log("Kural taraması HATA: " + ex.Message); }
        finally
        {
            Mouse.OverrideCursor = null;
            _busy = false;
            SetAu(false);
            UpdateEnabled();
        }
        if (matches == null) return;

        _ruleMatches = matches;
        _out.Log($"Kural taraması ({_ruleSource}): {matches.Count} kural eşleşti.");
        MergeRuleFindings(matches);
        ShowRuleMatches();
    }

    // Eslesmeleri Bulgular'a da ekle (rapora yansisin); eski kural bulgularini temizle
    private void MergeRuleFindings(List<RuleMatch> matches)
    {
        _result ??= _s!.ToResult();
        _result.Findings.RemoveAll(f => f.Title.StartsWith("Kural: ", StringComparison.Ordinal));
        foreach (var m in matches)
        {
            string detail = $"Eşleşen: {string.Join(", ", m.HitIds.Select(h => "$" + h))}";
            if (m.FirstOffset >= 0) detail += $" · ilk ofset 0x{m.FirstOffset:X}";
            _result.Findings.Add(new FindingEntry
            {
                Severity = m.Rule.Severity,
                Category = m.Rule.Category,
                Title = "Kural: " + m.Rule.Name,
                Detail = detail,
                Rank = 50,
            });
        }
        _result.Findings = _result.Findings
            .OrderBy(f => f.Severity switch { "Yuksek" => 0, "Orta" => 1, "Bilgi" => 2, _ => 3 })
            .ThenBy(f => f.Rank).ToList();
        RefreshLists();   // acik Bulgular paneli varsa guncelle
    }

    private void ShowRuleMatches()
    {
        if (_ruleMatches == null) return;
        OpenList("rules", "Kural eşleşmeleri", new[]
        {
            ("Önem", 70.0), ("Kategori", 100.0), ("Kural", 220.0), ("Eşleşen", 160.0), ("İlk ofset", -1.0),
        }, () =>
        {
            if (_ruleMatches!.Count == 0)
                return new List<Row> { new() { Ea = 0, C = new[] { "", "", "(eşleşme yok)", "", "" } } };
            return _ruleMatches!
                .OrderBy(m => m.Rule.Severity switch { "Yuksek" => 0, "Orta" => 1, "Bilgi" => 2, _ => 3 })
                .Select(m => new Row
                {
                    Ea = 0,
                    Fg = Theme.B(m.Rule.Severity switch
                    {
                        "Yuksek" => Color.FromRgb(0xE0, 0x3A, 0x3A),
                        "Orta" => Color.FromRgb(0xD0, 0x8A, 0x10),
                        _ => Color.FromRgb(0x3A, 0x7B, 0xD5),
                    }),
                    C = new[]
                    {
                        m.Rule.Severity, m.Rule.Category, m.Rule.Name,
                        string.Join(", ", m.HitIds.Select(h => "$" + h)),
                        m.FirstOffset >= 0 ? "0x" + m.FirstOffset.ToString("X") : "—",
                    },
                }).ToList();
        }, true,
        r => Dialogs.Info(this, "Kural: " + r.C[2], $"[{r.C[0]} / {r.C[1]}]\nEşleşen: {r.C[3]}\nİlk ofset: {r.C[4]}"),
        r => r == null ? null : new System.Windows.Controls.ContextMenu
        {
            Items = { FunctionsPane.Mi("Satırı kopyala", () => Copy(string.Join("  ", r.C))) },
        });
    }
}
