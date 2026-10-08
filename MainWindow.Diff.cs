using System.IO;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Iki dosya karsilastirma (BinDiff benzeri)
public partial class MainWindow
{
    private List<DiffPair>? _diffPairs;
    private string _diffRightName = "";

    private async void CompareWith()
    {
        if (_s == null || _busy) return;
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = Loc.T("Karşılaştırılacak ikinci dosyayı seç"),
            Filter = Loc.T("Çalıştırılabilir / kütüphane|*.exe;*.dll;*.sys;*.ocx;*.so;*.o;*.elf;*.bin|Tüm dosyalar (*.*)|*.*"),
        };
        if (dlg.ShowDialog(this) != true) return;
        string path = dlg.FileName;
        if (!File.Exists(path)) return;
        if (string.Equals(path, _s.Db.FilePath, StringComparison.OrdinalIgnoreCase))
        {
            Dialogs.Info(this, "Karşılaştırma", "Aynı dosyayı kendisiyle karşılaştıramazsın.");
            return;
        }

        _busy = true;
        UpdateEnabled();
        SetAu(true, "BinDiff:  ikinci dosya analiz ediliyor");
        Mouse.OverrideCursor = Cursors.AppStarting;
        _out.Log("");
        _out.Log(Loc.F("BinDiff: {0} analiz ediliyor...", Path.GetFileName(path)));

        List<DiffPair>? pairs = null;
        DiffStats? stats = null;
        try
        {
            var leftDb = _s.Db;
            var leftDis = _s.Dis;
            pairs = await Task.Run(() =>
            {
                var other = Session.Open(path, new LoadOptions(), null, _cfg.MinStrLen,
                    m => Dispatcher.BeginInvoke(() => _out.Log("  " + m)),
                    p => Dispatcher.BeginInvoke(() => SetAu(true, "BinDiff:  " + p)));
                var leftSigs = BinDiff.BuildSigs(leftDb, leftDis);
                var rightSigs = BinDiff.BuildSigs(other.Db, other.Dis);
                return BinDiff.Compare(leftSigs, rightSigs);
            });
            stats = BinDiff.Summarize(pairs);
        }
        catch (Exception ex)
        {
            _out.Log(Loc.T("BinDiff HATA: ") + ex.Message);
            Dialogs.Info(this, "Karşılaştırma hatası", "İkinci dosya analiz edilemedi:\n\n" + ex.Message);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            _busy = false;
            SetAu(false);
            UpdateEnabled();
        }
        if (pairs == null || stats == null) return;

        _diffPairs = pairs;
        _diffRightName = Path.GetFileName(path);
        _out.Log(Loc.F("BinDiff tamamlandı: {0} aynı, {1} değişmiş, {2} yalnız solda, {3} yalnız sağda.",
                 stats.Identical, stats.Changed, stats.OnlyLeft, stats.OnlyRight));
        ShowDiff();
    }

    private void ShowDiff()
    {
        if (_diffPairs == null) return;
        OpenList("bindiff", Loc.F("BinDiff — {0}", _diffRightName), new[]
        {
            ("Durum", 100.0), ("Benzerlik", 80.0), ("Sol (bu dosya)", 300.0), (Loc.F("Sağ ({0})", _diffRightName), -1.0),
        }, () =>
        {
            int Order(DiffKind k) => k switch
            {
                DiffKind.Changed => 0, DiffKind.OnlyLeft => 1, DiffKind.OnlyRight => 2, _ => 3,
            };
            return _diffPairs!
                .OrderBy(p => Order(p.Kind))
                .ThenByDescending(p => p.Kind == DiffKind.Changed ? p.Similarity : 0)
                .ThenBy(p => p.Left?.Ea ?? p.Right?.Ea ?? 0)
                .Select(p => new Row
                {
                    Ea = p.Left?.Ea ?? 0,
                    Tag = p,
                    Fg = Theme.B(p.Kind switch
                    {
                        DiffKind.Identical => Color.FromRgb(0x7A, 0x78, 0x90),
                        DiffKind.Changed => Color.FromRgb(0xD0, 0x8A, 0x10),
                        DiffKind.OnlyLeft => Color.FromRgb(0xE0, 0x3A, 0x3A),
                        _ => Color.FromRgb(0x3A, 0x7B, 0xD5),
                    }),
                    C = new[]
                    {
                        Loc.T(p.Kind switch
                        {
                            DiffKind.Identical => "aynı",
                            DiffKind.Changed => "değişti",
                            DiffKind.OnlyLeft => "yalnız solda",
                            _ => "yalnız sağda",
                        }),
                        p.Kind is DiffKind.OnlyLeft or DiffKind.OnlyRight ? "" : $"{p.Similarity * 100:0}%",
                        Side(p.Left),
                        Side(p.Right),
                    },
                }).ToList();
        }, true,
        r =>   // cift tiklama: soldaki fonksiyona atla
        {
            if (r.Tag is DiffPair { Left: { } l }) Jump(l.Ea);
        },
        r =>
        {
            if (r?.Tag is not DiffPair p) return null;
            var m = new System.Windows.Controls.ContextMenu();
            if (p.Left != null) m.Items.Add(FunctionsPane.Mi("Soldaki fonksiyona atla", () => Jump(p.Left.Ea)));
            m.Items.Add(FunctionsPane.Mi("Satırı kopyala", () => Copy(string.Join("  ", r.C))));
            return m;
        });
    }

    private static string Side(FuncSig? s)
        => s == null ? "—" : Loc.F("{0}  ({1} komut)", s.Name, s.InsnCount);
}
