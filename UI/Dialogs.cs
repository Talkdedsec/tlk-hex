using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

public static class Dialogs
{
    public static Action<Window>? ShotHook;   // test modu

    public static Window Make(Window? owner, string title, double width)
    {
        var w = new Window
        {
            Title = Loc.T(title),
            Width = width,
            SizeToContent = SizeToContent.Height,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = owner != null ? WindowStartupLocation.CenterOwner : WindowStartupLocation.CenterScreen,
            ShowInTaskbar = false,
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 12.5,
        };
        if (owner != null && owner.IsLoaded) w.Owner = owner;
        w.SetResourceReference(Control.BackgroundProperty, "BgBrush");
        w.SetResourceReference(Control.ForegroundProperty, "TextBrush");
        MainWindow.DarkTitle(w, Theme.P.Dark);
        ShotHook?.Invoke(w);
        return w;
    }

    public static Button Btn(string text, bool def = false, bool cancel = false) => new()
    {
        Content = Loc.T(text),
        MinWidth = 80,
        Height = 26,
        Margin = new Thickness(6, 0, 0, 0),
        IsDefault = def,
        IsCancel = cancel,
        Padding = new Thickness(10, 0, 10, 0),
    };

    public static StackPanel Buttons(params Button[] b)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        foreach (var x in b) sp.Children.Add(x);
        return sp;
    }

    public static TextBlock Label(string t, double top = 0) => new() { Text = Loc.T(t), Margin = new Thickness(0, top, 0, 4) };

    // ================= Metin girisi (G, N, ; ...) =================

    public static string? Input(Window? owner, string title, string prompt, string initial, bool multiline = false,
        IList<string>? history = null)
    {
        var w = Make(owner, title, multiline ? 520 : 420);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(Label(prompt));
        Control box;
        Func<string> get;
        if (history != null && !multiline)
        {
            var cb = new ComboBox { IsEditable = true, Text = initial, FontFamily = new FontFamily("Consolas"), FontSize = 13 };
            foreach (var h in history) cb.Items.Add(h);
            cb.Text = initial;
            box = cb;
            get = () => cb.Text;
            w.Loaded += (_, _) =>
            {
                cb.Focus();
                if (cb.Template.FindName("PART_EditableTextBox", cb) is TextBox t) t.SelectAll();
            };
        }
        else
        {
            var tb = new TextBox
            {
                Text = initial,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 13,
                AcceptsReturn = multiline,
                TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap,
                Height = multiline ? 120 : double.NaN,
                VerticalScrollBarVisibility = multiline ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden,
                Padding = new Thickness(3, 2, 3, 2),
            };
            box = tb;
            get = () => tb.Text;
            w.Loaded += (_, _) => { tb.Focus(); tb.SelectAll(); };
        }
        sp.Children.Add(box);
        var ok = Btn("Tamam", !multiline);
        var cancel = Btn("İptal", false, true);
        string? result = null;
        ok.Click += (_, _) => { result = get(); w.DialogResult = true; };
        if (multiline)
        {
            w.PreviewKeyDown += (_, e) =>
            {
                if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control) { result = get(); w.DialogResult = true; e.Handled = true; }
            };
            sp.Children.Add(new TextBlock { Text = Loc.T("Ctrl+Enter = Tamam"), Opacity = 0.6, FontSize = 11, Margin = new Thickness(0, 4, 0, 0) });
        }
        sp.Children.Add(Buttons(ok, cancel));
        w.Content = sp;
        return w.ShowDialog() == true ? result : null;
    }

    public static bool Confirm(Window? owner, string title, string text)
    {
        var w = Make(owner, title, 440);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock { Text = Loc.T(text), TextWrapping = TextWrapping.Wrap });
        var yes = Btn("Evet", true);
        var no = Btn("Hayır", false, true);
        bool r = false;
        yes.Click += (_, _) => { r = true; w.DialogResult = true; };
        sp.Children.Add(Buttons(yes, no));
        w.Content = sp;
        w.ShowDialog();
        return r;
    }

    public static void Info(Window? owner, string title, string text)
    {
        var w = Make(owner, title, text.Length > 1500 ? 720 : 460);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBox
        {
            Text = Loc.T(text), IsReadOnly = true, BorderThickness = new Thickness(0), Background = Brushes.Transparent,
            TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas"), MaxHeight = 620,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        });
        var ok = Btn("Tamam", true, true);
        ok.Click += (_, _) => w.DialogResult = true;
        sp.Children.Add(Buttons(ok));
        w.Content = sp;
        w.ShowDialog();
    }

    // true = kaydet, false = kaydetme, null = vazgec
    public static bool? AskSave(Window? owner, string file)
    {
        var w = Make(owner, "Veritabanını kaydet", 460);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock
        {
            Text = Loc.F("'{0}' için yapılan değişiklikler (isimler, yorumlar, tanımlar, yamalar) kaydedilsin mi?", file),
            TextWrapping = TextWrapping.Wrap,
        });
        bool? r = null;
        var save = Btn("Kaydet", true);
        var dont = Btn("Kaydetme");
        var cancel = Btn("İptal", false, true);
        save.Click += (_, _) => { r = true; w.DialogResult = true; };
        dont.Click += (_, _) => { r = false; w.DialogResult = true; };
        sp.Children.Add(Buttons(save, dont, cancel));
        w.Content = sp;
        w.ShowDialog();
        return r;
    }

    // ================= Chooser =================

    public static Row? Choose(Window? owner, string title, (string, double)[] cols, List<Row> rows, ulong? selectEa = null,
        double width = 760, double height = 460)
    {
        var w = Make(owner, title, width);
        w.SizeToContent = SizeToContent.Manual;
        w.Height = height;
        w.ResizeMode = ResizeMode.CanResize;
        var dp = new DockPanel { Margin = new Thickness(8) };
        var list = new ListPane(cols);
        list.SetRows(rows);
        Row? result = null;
        var ok = Btn("Tamam", false);
        var cancel = Btn("İptal", false, true);
        var search = Btn("Ara");
        ok.Click += (_, _) => { result = list.Selected; if (result != null) w.DialogResult = true; };
        search.Click += (_, _) => list.FocusFilter();
        list.Activated += r => { result = r; w.DialogResult = true; };
        var btns = Buttons(ok, cancel, search);
        btns.Margin = new Thickness(0, 8, 0, 0);
        DockPanel.SetDock(btns, Dock.Bottom);
        dp.Children.Add(btns);
        dp.Children.Add(list);
        w.Content = dp;
        w.Loaded += (_, _) =>
        {
            if (selectEa is ulong ea) list.SelectEa(ea);
            if (list.Grid.SelectedIndex < 0 && rows.Count > 0) list.Grid.SelectedIndex = 0;
            list.Grid.Focus();
            if (list.Grid.SelectedItem != null) list.Grid.ScrollIntoView(list.Grid.SelectedItem);
        };
        w.PreviewKeyDown += (_, e) =>
        {
            // yazmaya baslayinca filtreye gec
            if (Keyboard.FocusedElement is DataGridCell or DataGrid or DataGridRow && e.Key >= Key.A && e.Key <= Key.Z
                && Keyboard.Modifiers == ModifierKeys.None)
                list.FocusFilter();
        };
        return w.ShowDialog() == true ? result : null;
    }

    // ================= Load a new file =================

    public static LoadOptions? Load(Window? owner, string path, byte[] bytes, bool hasIdb, out bool useIdb)
    {
        useIdb = false;
        var w = Make(owner, "Yeni dosya yükle", 700);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(Label(Loc.F("Yükle: {0}", Path.GetFileName(path))));
        string det = Loaders.Detect(bytes);
        var loaders = new ListBox { Height = 86, FontFamily = new FontFamily("Consolas"), FontSize = 12.5 };
        var ids = new List<string>();
        if (det != "bin")
        {
            loaders.Items.Add($"{Loaders.Describe(bytes, det)} [{det}]");
            ids.Add(det);
        }
        loaders.Items.Add("Binary file [bin]");
        ids.Add("bin");
        loaders.SelectedIndex = 0;
        sp.Children.Add(loaders);

        var grid = new Grid { Margin = new Thickness(0, 10, 0, 0) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var left = new StackPanel();
        left.Children.Add(Label("İşlemci tipi"));
        var proc = new ComboBox { IsEnabled = false };
        proc.Items.Add("MetaPC (disassemble all opcodes) [metapc]");
        proc.SelectedIndex = 0;
        left.Children.Add(proc);
        left.Children.Add(Label("Yükleme adresi (binary)", 8));
        var baseBox = new TextBox { Text = "0", FontFamily = new FontFamily("Consolas") };
        left.Children.Add(baseBox);
        left.Children.Add(Label("Bit genişliği (binary)", 8));
        var bits = new ComboBox();
        bits.Items.Add("64-bit");
        bits.Items.Add("32-bit");
        bits.Items.Add("16-bit");
        bits.SelectedIndex = 0;
        left.Children.Add(bits);

        var right = new StackPanel { Margin = new Thickness(16, 0, 0, 0) };
        right.Children.Add(Label("Seçenekler"));
        var cbAnalysis = new CheckBox { Content = Loc.T("Otomatik analiz (Analysis enabled)"), IsChecked = true, Margin = new Thickness(0, 2, 0, 2) };
        var cbIdata = new CheckBox { Content = Loc.T("Imports segmenti oluştur (.idata)"), IsChecked = true, Margin = new Thickness(0, 2, 0, 2) };
        var cbRsrc = new CheckBox { Content = Loc.T("Kaynakları yükle (.rsrc)"), IsChecked = false, Margin = new Thickness(0, 2, 0, 2) };
        right.Children.Add(cbAnalysis);
        right.Children.Add(cbIdata);
        right.Children.Add(cbRsrc);
        CheckBox? cbIdb = null;
        if (hasIdb)
        {
            cbIdb = new CheckBox
            {
                Content = Loc.T("Kayıtlı veritabanını kullan (isim/yorum/islemler)"),
                IsChecked = true,
                Margin = new Thickness(0, 10, 0, 2),
                FontWeight = FontWeights.SemiBold,
            };
            right.Children.Add(cbIdb);
        }
        Grid.SetColumn(right, 1);
        grid.Children.Add(left);
        grid.Children.Add(right);
        sp.Children.Add(grid);

        void Upd()
        {
            bool bin = ids[Math.Max(0, loaders.SelectedIndex)] == "bin";
            baseBox.IsEnabled = bits.IsEnabled = bin;
            cbIdata.IsEnabled = cbRsrc.IsEnabled = !bin;
        }
        loaders.SelectionChanged += (_, _) => Upd();
        Upd();

        LoadOptions? res = null;
        var ok = Btn("Tamam", true);
        var cancel = Btn("İptal", false, true);
        bool idbChoice = false;
        ok.Click += (_, _) =>
        {
            var o = new LoadOptions
            {
                Loader = ids[Math.Max(0, loaders.SelectedIndex)],
                Analyze = cbAnalysis.IsChecked == true,
                SplitIdata = cbIdata.IsChecked == true,
                LoadResources = cbRsrc.IsChecked == true,
                BinBitness = bits.SelectedIndex switch { 1 => 32, 2 => 16, _ => 64 },
                BinBase = Db.ParseNum(baseBox.Text) ?? 0,
            };
            idbChoice = cbIdb?.IsChecked == true;
            res = o;
            w.DialogResult = true;
        };
        sp.Children.Add(Buttons(ok, cancel));
        w.Content = sp;
        w.ShowDialog();
        useIdb = idbChoice;
        return res;
    }

    // ================= Arama =================

    public sealed record TextSearch(string Text, bool MatchCase, bool Regex, bool Up, bool All);

    public static TextSearch? SearchText(Window? owner, string initial, bool binary)
    {
        var w = Make(owner, binary ? "İkili arama (bayt dizisi)" : "Metin ara", 460);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(Label(binary ? "Bayt dizisi (örnek: 48 8B ?? 24 veya \"metin\"):" : "Metin:"));
        var tb = new TextBox { Text = initial, FontFamily = new FontFamily("Consolas"), FontSize = 13, Padding = new Thickness(3, 2, 3, 2) };
        sp.Children.Add(tb);
        var mc = new CheckBox { Content = Loc.T("Büyük/küçük harf duyarlı"), Margin = new Thickness(0, 8, 0, 0), Visibility = binary ? Visibility.Collapsed : Visibility.Visible };
        var rx = new CheckBox { Content = Loc.T("Düzenli ifade (regex)"), Margin = new Thickness(0, 4, 0, 0), Visibility = binary ? Visibility.Collapsed : Visibility.Visible };
        var up = new CheckBox { Content = Loc.T("Yukarı doğru ara"), Margin = new Thickness(0, 4, 0, 0) };
        var all = new CheckBox { Content = Loc.T("Tüm eşleşmeleri bul"), Margin = new Thickness(0, 4, 0, 0) };
        sp.Children.Add(mc);
        sp.Children.Add(rx);
        sp.Children.Add(up);
        sp.Children.Add(all);
        TextSearch? r = null;
        var ok = Btn("Tamam", true);
        var cancel = Btn("İptal", false, true);
        ok.Click += (_, _) =>
        {
            r = new TextSearch(tb.Text, mc.IsChecked == true, rx.IsChecked == true, up.IsChecked == true, all.IsChecked == true);
            w.DialogResult = true;
        };
        sp.Children.Add(Buttons(ok, cancel));
        w.Content = sp;
        w.Loaded += (_, _) => { tb.Focus(); tb.SelectAll(); };
        return w.ShowDialog() == true ? r : null;
    }

    // ================= Quick start =================

    public static string? QuickStart(Window? owner, List<string> recent)
    {
        var w = Make(owner, "Hızlı başlangıç", 560);
        var sp = new StackPanel { Margin = new Thickness(16) };
        var head = new TextBlock { Text = "tlk-hex", FontSize = 22, FontWeight = FontWeights.SemiBold };
        sp.Children.Add(head);
        sp.Children.Add(new TextBlock { Text = "Interaktif disassembler", Opacity = 0.7, Margin = new Thickness(0, 0, 0, 14) });
        string? r = null;
        var row = new UniformGrid3();
        Button Big(string glyph, string title, string sub, string res)
        {
            var b = new Button { Height = 74, Margin = new Thickness(0, 0, 8, 0), HorizontalContentAlignment = HorizontalAlignment.Left, Padding = new Thickness(10, 4, 10, 4) };
            var bsp = new StackPanel { Orientation = Orientation.Horizontal };
            bsp.Children.Add(new TextBlock
            {
                Text = glyph, FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"), FontSize = 26,
                VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0),
            });
            var tsp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            tsp.Children.Add(new TextBlock { Text = title, FontWeight = FontWeights.SemiBold, FontSize = 14 });
            tsp.Children.Add(new TextBlock { Text = sub, Opacity = 0.7, FontSize = 11.5, TextWrapping = TextWrapping.Wrap, MaxWidth = 110 });
            bsp.Children.Add(tsp);
            b.Content = bsp;
            b.Click += (_, _) => { r = res; w.DialogResult = true; };
            return b;
        }
        row.Add(Big("", "Yeni", "Yeni dosya disassemble et", "new"));
        row.Add(Big("", "Başla", "Boş çalışma alanı", "go"));
        row.Add(Big("", "Önceki", "Son dosyayı aç", recent.Count > 0 ? "prev:" + recent[0] : "new"));
        sp.Children.Add(row.Panel);
        if (recent.Count > 0)
        {
            sp.Children.Add(Label("Son açılanlar", 14));
            var lb = new ListBox { Height = 150, FontFamily = new FontFamily("Consolas") };
            foreach (var p in recent) lb.Items.Add(p);
            lb.MouseDoubleClick += (_, _) =>
            {
                if (lb.SelectedItem is string p) { r = "prev:" + p; w.DialogResult = true; }
            };
            sp.Children.Add(lb);
        }
        var cancel = Btn("Kapat", false, true);
        sp.Children.Add(Buttons(cancel));
        w.Content = sp;
        return w.ShowDialog() == true ? r : null;
    }

    private sealed class UniformGrid3
    {
        public readonly System.Windows.Controls.Primitives.UniformGrid Panel = new() { Columns = 3 };
        public void Add(UIElement e) => Panel.Children.Add(e);
    }

    // ================= Hakkinda / kisayollar =================

    public const string Shortcuts =
        "GEZİNME\n" +
        "  G            Adrese/isme atla\n" +
        "  Enter        İşaretçi altındaki isme git\n" +
        "  Esc          Geri\n" +
        "  Ctrl+Enter   İleri\n" +
        "  Ctrl+P       Fonksiyona atla\n" +
        "  Ctrl+E       Giriş noktasına atla\n" +
        "  Ctrl+L       İsme atla (Names)\n" +
        "  Ctrl+S       Segmente atla\n" +
        "  Alt+M / Ctrl+M  Konumu işaretle / işarete atla\n" +
        "  Space        Metin <-> Graph görünümü\n" +
        "  F5 / Tab     Pseudocode\n" +
        "\nDUZENLEME\n" +
        "  N            Yeniden adlandır\n" +
        "  ;  /  :      Yorum / tekrarlanan yorum\n" +
        "  C  D  U  A   Kod / Veri / Tanımsız / String\n" +
        "  P            Fonksiyon oluştur\n" +
        "  O            Offset (işaretçi) yap/kaldır\n" +
        "  H            Onaltılık / ondalık\n" +
        "  X            Xref'ler (bu isme referanslar)\n" +
        "  Ctrl+X       Xref'ler (bu komuttan çıkanlar)\n" +
        "\nARAMA\n" +
        "  Alt+T / Ctrl+T   Metin ara / sonraki\n" +
        "  Alt+B / Ctrl+B   Bayt dizisi ara / sonraki\n" +
        "  Alt+I            Sabit değer (immediate) ara\n" +
        "\nPENCERELER\n" +
        "  Shift+F3  Functions    Shift+F4  Names\n" +
        "  Shift+F7  Segments     Shift+F12 Strings\n" +
        "  Ctrl+W    Veritabanını kaydet\n" +
        "  Hex View: F2 düzenleme modu";
}
