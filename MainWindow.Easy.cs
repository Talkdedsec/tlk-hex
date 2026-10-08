using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Kullanim kolayligi: hos geldin ekrani, onizleme, Git kutusu, ipuclari
public partial class MainWindow
{
    private readonly Border _welcome = new();
    private readonly StackPanel _recentPanel = new();
    private readonly GoBox _go = new();
    private readonly Popup _preview = new() { AllowsTransparency = true, Placement = PlacementMode.Relative, StaysOpen = true };

    // ================= Hos geldin ekrani =================

    private void BuildWelcome()
    {
        var sp = new StackPanel { Margin = new Thickness(70, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left, MaxWidth = 640 };

        // göz logosu + isim
        var brand = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 2) };
        try
        {
            var eye = new System.Windows.Controls.Image
            {
                Source = new BitmapImage(new Uri("pack://application:,,,/resources/eye.png")),
                Height = 62,
                Stretch = Stretch.Uniform,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(-4, 0, 16, 0),
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = (Color)ColorConverter.ConvertFromString("#9D7CF0"),
                    BlurRadius = 26, ShadowDepth = 0, Opacity = 0.75,
                },
            };
            RenderOptions.SetBitmapScalingMode(eye, BitmapScalingMode.HighQuality);
            brand.Children.Add(eye);
        }
        catch { }
        var title = new TextBlock { Text = "tlk-hex", FontSize = 44, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        title.SetResourceReference(TextBlock.ForegroundProperty, "AccentBrush");
        brand.Children.Add(title);
        sp.Children.Add(brand);
        var sub = new TextBlock
        {
            Text = Loc.T("İnteraktif disassembler — EXE, DLL, SYS, ELF ve ham binary dosyalarını incele."),
            FontSize = 15,
            Margin = new Thickness(0, 2, 0, 22),
            TextWrapping = TextWrapping.Wrap,
        };
        sub.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        sp.Children.Add(sub);

        var row = new StackPanel { Orientation = Orientation.Horizontal };
        row.Children.Add(BigButton("", "Dosya aç", "Ctrl+O", true, () => OpenDialog()));
        row.Children.Add(BigButton("", "Hızlı rehber", "F1", false, ShowGuide));
        sp.Children.Add(row);

        var drop = new TextBlock
        {
            Text = Loc.T("İpucu: dosyayı bu pencereye sürükleyip bırakman da yeterli."),
            Margin = new Thickness(2, 14, 0, 26),
            FontSize = 13,
        };
        drop.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        sp.Children.Add(drop);
        sp.Children.Add(_recentPanel);

        _welcome.Child = sp;
        // soldan sağa koyulaşan perde: metin okunur kalsın, sağdaki görsel görünsün
        var scrim = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(1, 0) };
        scrim.GradientStops.Add(new GradientStop(Color.FromArgb(0xF2, 0x09, 0x08, 0x0D), 0));
        scrim.GradientStops.Add(new GradientStop(Color.FromArgb(0xD0, 0x09, 0x08, 0x0D), 0.40));
        scrim.GradientStops.Add(new GradientStop(Color.FromArgb(0x00, 0x09, 0x08, 0x0D), 0.74));
        scrim.Freeze();
        _welcome.Background = scrim;
        _idaPane.Children.Add(_welcome);
        UpdateWelcome();
    }

    private Button BigButton(string glyph, string text, string key, bool accent, Action act)
    {
        var b = new Button { Margin = new Thickness(0, 0, 12, 0), Padding = new Thickness(18, 10, 18, 10), Cursor = Cursors.Hand };
        if (accent)
        {
            b.SetResourceReference(Control.BackgroundProperty, "AccentBrush");
            b.SetResourceReference(Control.BorderBrushProperty, "AccentBrush");
        }
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(new TextBlock
        {
            Text = glyph,
            FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
            FontSize = 18,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 10, 0),
            Foreground = accent ? Brushes.White : null,
        });
        var t = new TextBlock { Text = Loc.T(text), FontSize = 15, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        if (accent) t.Foreground = Brushes.White;
        sp.Children.Add(t);
        var k = new TextBlock { Text = "  " + key, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Opacity = 0.75 };
        if (accent) k.Foreground = Brushes.White;
        sp.Children.Add(k);
        b.Content = sp;
        b.Click += (_, _) => act();
        return b;
    }

    private void UpdateWelcome()
    {
        bool show = _s == null && !_busy;
        _welcome.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        if (!show) return;
        _recentPanel.Children.Clear();
        var recent = RecentFiles.Load();
        if (recent.Count == 0) return;
        var h = new TextBlock { Text = Loc.T("SON AÇILANLAR"), FontSize = 11.5, FontWeight = FontWeights.SemiBold, Margin = new Thickness(2, 0, 0, 8) };
        h.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        _recentPanel.Children.Add(h);
        foreach (var p in recent.Take(7))
        {
            var path = p;
            var card = new Border { Padding = new Thickness(12, 7, 12, 7), Margin = new Thickness(0, 0, 0, 5), CornerRadius = new CornerRadius(4), Cursor = Cursors.Hand, BorderThickness = new Thickness(1) };
            card.SetResourceReference(Border.BackgroundProperty, "SurfaceBrush");
            card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
            var cs = new StackPanel();
            var n = new TextBlock { Text = Path.GetFileName(path), FontWeight = FontWeights.SemiBold, FontSize = 13.5 };
            n.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
            var d = new TextBlock { Text = path, FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis };
            d.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
            cs.Children.Add(n);
            cs.Children.Add(d);
            card.Child = cs;
            card.MouseEnter += (_, _) => card.SetResourceReference(Border.BorderBrushProperty, "AccentBrush");
            card.MouseLeave += (_, _) => card.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
            card.MouseLeftButtonUp += (_, _) => OpenFile(path, false);
            _recentPanel.Children.Add(card);
        }
    }

    // ================= Git / Ara kutusu =================

    private void SetupGoBox()
    {
        _go.Picked += it => Jump(it.Ea);
        _go.Submitted += (q, hl) =>
        {
            if (_s == null) return;
            var ea = _s.Db.Resolve(q);
            bool looksAddr = q.Any(char.IsDigit) && q.All(c => Uri.IsHexDigit(c) || c is 'x' or 'X' or 'h' or 'H' or '+' or '_');
            if (ea is ulong e && _s.Db.IsMapped(e) && (looksAddr || _s.Db.NameIndex().ContainsKey(q))) { Jump(e); return; }
            if (hl != null) { Jump(hl.Ea); return; }
            if (ea is ulong e2 && _s.Db.IsMapped(e2)) { Jump(e2); return; }
            // eslesme yok: arama panelinde her yerde ara
            ShowSearch(q);
        };
    }

    private void BuildGoItems()
    {
        if (_s == null) { _go.SetItems(new()); return; }
        var db = _s.Db;
        var items = new List<GoBox.Item>();
        var seen = new HashSet<ulong>();
        foreach (var f in db.Funcs.Values.OrderBy(f => f.Start))
            if (f.Chunks.Count > 0 && seen.Add(f.Start))
                items.Add(new GoBox.Item(db.FuncName(f), f.Start, f.IsThunk ? "thunk" : "fonk", db.AddrStr(f.Start)));
        foreach (var r in NameRows())
        {
            string k = r.C[0] switch { "I" => "import", "A" => "metin", "C" => "kod", "F" => "fonk", "L" => "thunk", _ => "veri" };
            if (seen.Add(r.Ea)) items.Add(new GoBox.Item(r.C[1], r.Ea, k, db.AddrStr(r.Ea)));
        }
        foreach (var s in db.Segs) items.Add(new GoBox.Item(s.Name, s.Start, "segment", db.AddrStr(s.Start)));
        _go.SetItems(items);
    }

    // ================= Onizleme (fareyle bekleyince) =================

    private void OnWordHover(FrameworkElement view, string word, Point pt)
    {
        if (_s == null || !IsActive) return;
        if (WordEa(word) is not ulong ea) return;
        var lines = PreviewLines(ea, word);
        if (lines.Count == 0) return;
        var sp = new StackPanel();
        foreach (var l in lines)
        {
            var tb = new TextBlock { FontFamily = new FontFamily(_cfg.FontFamily + ", Consolas"), FontSize = Math.Max(10, _cfg.FontSize - 1) };
            foreach (var t in l.Toks) tb.Inlines.Add(new Run(t.Text) { Foreground = UI.Theme.Tok(t.Kind) });
            sp.Children.Add(tb);
        }
        var border = new Border
        {
            Child = sp,
            Padding = new Thickness(8, 6, 8, 6),
            BorderThickness = new Thickness(1),
            MaxWidth = 760,
        };
        border.Background = UI.Theme.B(UI.Theme.P.Bg);
        border.BorderBrush = UI.Theme.B(UI.Theme.P.Accent);
        _preview.Child = border;
        _preview.PlacementTarget = view;
        _preview.HorizontalOffset = pt.X + 14;
        _preview.VerticalOffset = pt.Y + 18;
        _preview.IsOpen = true;
    }

    private void HidePreview() => _preview.IsOpen = false;

    private List<Line> PreviewLines(ulong ea, string word)
    {
        var db = _s!.Db;
        var res = new List<Line>();
        Line Head(string text)
        {
            var l = new Line();
            l.Toks.Add(new Tok(text, Tk.AutoCmt));
            return l;
        }
        if (db.ImportAt.TryGetValue(ea, out var imp))
        {
            res.Add(Head($"; Import: {imp.Dll}!{imp.Name}"));
            res.Add(Head(Loc.F("; {0} yerde kullanılıyor", db.XrefsTo(ea).Count)));
            return res;
        }
        var s = db.StringAt(db.HeadOf(ea));
        if (s != null)
        {
            res.Add(Head($"; string ({s.Length} karakter)"));
            var l = new Line();
            l.Toks.Add(new Tok("\"" + Db.Escape(s, 300) + "\"", Tk.Str));
            res.Add(l);
            return res;
        }
        var f = db.FuncAt(ea);
        ulong cur = db.HeadOf(ea);
        if (f != null && ea == f.Start) res.Add(Head($"; {db.FuncName(f)}  —  {f.Instrs.Count} komut, {db.XrefsTo(ea).Count} referans"));
        int n = 0;
        while (n < 16 && db.IsMapped(cur))
        {
            foreach (var l in _s.List.ItemLinesForGraph(cur))
            {
                if (l.Type is LT.VarDecl) continue;
                res.Add(l);
                if (++n >= 16) break;
            }
            if (!db.IsCode(cur)) break;
            if (_s.Dis.TryDecode(cur, out var ins) && ins.FlowControl is Iced.Intel.FlowControl.Return
                    or Iced.Intel.FlowControl.UnconditionalBranch or Iced.Intel.FlowControl.IndirectBranch) break;
            cur = db.NextHead(cur);
            if (!db.IsCode(cur)) break;
        }
        return res;
    }

    // ================= Ipuclari =================

    private void ShowHint()
    {
        if (_s == null) return;
        var w = Word();
        ulong ea = Here();
        string h;
        if (w != null && WordEa(w) is ulong t && t != _s.Db.HeadOf(ea))
            h = Loc.F("'{0}':  çift tık / Enter = git   •   X = nereden kullanılıyor   •   N = yeniden adlandır   •   Esc = geri", w);
        else if (_s.Db.FuncAt(ea) != null)
            h = "Space = graph/metin   •   F5 = pseudocode   •   ; = yorum   •   N = isim ver   •   X = referanslar   •   G = adrese git";
        else if (_s.Db.IsCode(_s.Db.HeadOf(ea)))
            h = "P = fonksiyon oluştur   •   U = tanımsız yap   •   ; = yorum   •   N = isim ver";
        else
            h = "C = koda çevir   •   D = veri tipi   •   A = string   •   U = tanımsız   •   O = işaretçi";
        SetStatus(h);
    }

    // ================= Rehber =================

    internal const string Guide =
        "NASIL KULLANILIR\n\n" +
        "1) Dosya aç: Ctrl+O, araç çubuğundaki 'Aç' ya da dosyayı pencereye sürükle.\n" +
        "   Analiz otomatik yapılır; birkaç saniye sürebilir (alt çubukta 'AU' göstergesi).\n\n" +
        "2) Gezin:\n" +
        "   • Soldaki 'Functions' listesinde bir fonksiyona tıkla, ortada kodu açılır.\n" +
        "   • Üstteki 'Git / ara' kutusuna isim, adres veya metin yaz (Ctrl+F) — öneriler çıkar.\n" +
        "   • Ayrıntılı arama: 'Ara' düğmesi / Ctrl+Shift+F — isim, metin, kod, yorum, bayt ve sabit değer;\n" +
        "     yazdıkça sonuçlar listelenir, tıklayınca oraya gider.\n" +
        "   • Koddaki bir isme çift tıkla (ya da Enter) o adrese gider; Esc ile geri dönersin.\n" +
        "   • Farenin geri/ileri tuşları da çalışır.\n" +
        "   • Bir ismin üzerinde fareyi bekletirsen içeriğini önizleme olarak gösterir.\n" +
        "   • Üstteki renkli şerit tüm dosyanın haritasıdır; tıklayınca oraya gider.\n\n" +
        "3) Görünümler:\n" +
        "   • Space: kod ile akış grafiği (graph) arasında geçiş.\n" +
        "   • F5: seçili fonksiyonun C benzeri pseudocode'u.\n" +
        "   • Hex View sekmesi: ham baytlar (F2 ile düzenleme).\n" +
        "   • Strings (Shift+F12), Imports, Exports, Bulgular (güvenlik analizi) sekmeleri.\n\n" +
        "4) Not al ve düzenle:\n" +
        "   • N: yeniden adlandır   • ; : yorum ekle   • X: bu nereden kullanılıyor?\n" +
        "   • Ctrl+W: çalışmanı kaydet (isimler/yorumlar dosyayı tekrar açınca geri gelir).\n\n" +
        "5) Semboller: Windows dosyalarında 'Dosya > Sembolleri indir' ile gerçek fonksiyon adları gelir\n" +
        "   (ilk açılışta da sorulur). Kendi PDB dosyan varsa 'PDB dosyası yükle'.\n\n" +
        "6) AI: Seçenekler'den API anahtarı girersen Output > AI ile soru sorabilir,\n" +
        "   Pseudocode sekmesinde 'AI ile decompile' kullanabilirsin.\n\n" +
        "Alt çubuk, imlecin olduğu yere göre kullanılabilecek tuşları her zaman gösterir.\n\n" +
        "──────────────────────────────────────────\n\n";

    private void ShowGuide() => Dialogs.Info(this, "Hızlı rehber", Loc.T(Guide) + Loc.T(Dialogs.Shortcuts));
}
