using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using tlk_hex.UI;

namespace tlk_hex;

// Secenekler > Genel (IDA "Options" penceresi karsiligi)
public sealed class SettingsWindow : Window
{
    public Settings Result { get; }

    public SettingsWindow(Settings cur)
    {
        Title = Loc.T("Seçenekler");
        Width = 520;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 12.5;
        SetResourceReference(BackgroundProperty, "BgBrush");
        SetResourceReference(ForegroundProperty, "TextBrush");
        MainWindow.DarkTitle(this, UI.Theme.P.Dark);

        Result = new Settings
        {
            Dark = cur.Dark, ThemeName = cur.ThemeName, BackgroundOn = cur.BackgroundOn, BackgroundPath = cur.BackgroundPath,
            BackgroundDim = cur.BackgroundDim, FontFamily = cur.FontFamily, FontSize = cur.FontSize, GraphByDefault = cur.GraphByDefault,
            ShowQuickStart = cur.ShowQuickStart, AskLoadOptions = cur.AskLoadOptions, SymbolMode = cur.SymbolMode, ShowPrefix = cur.ShowPrefix, OpcodeBytes = cur.OpcodeBytes,
            MaxXrefs = cur.MaxXrefs, MinStrLen = cur.MinStrLen, AutoSaveDb = cur.AutoSaveDb,
            AiApiKey = cur.AiApiKey, AiModel = cur.AiModel, AiBaseUrl = cur.AiBaseUrl, Lang = cur.Lang,
        };

        var root = new StackPanel { Margin = new Thickness(14) };

        // ---- gorunum ----
        root.Children.Add(Header("Görünüm"));

        var lang = new ComboBox();
        lang.Items.Add("Türkçe");
        lang.Items.Add("English");
        lang.SelectedIndex = cur.Lang == "en" ? 1 : 0;
        root.Children.Add(Row("Arayüz dili (yeniden başlatınca)", lang));

        var theme = new ComboBox();
        theme.Items.Add(Loc.T("IDA (açık)"));
        theme.Items.Add(Loc.T("IDA (koyu)"));
        theme.Items.Add(Loc.T("Mor gece"));
        theme.SelectedIndex = cur.ThemeName switch { "light" => 0, "dark" => 1, _ => 2 };
        root.Children.Add(Row("Renk teması", theme));

        var bgOn = new CheckBox { Content = Loc.T("Kod görünümlerinde arka plan görseli"), IsChecked = cur.BackgroundOn, Margin = new Thickness(0, 4, 0, 4) };
        root.Children.Add(bgOn);
        var bgPath = new TextBox { Text = cur.BackgroundPath ?? "", IsReadOnly = true };
        root.Children.Add(Row("Görsel (boş = varsayılan)", bgPath));
        var bgBtns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 2, 0, 2) };
        var browse = new Button { Content = Loc.T("Gözat..."), Padding = new Thickness(10, 2, 10, 2) };
        var def = new Button { Content = Loc.T("Varsayılan"), Padding = new Thickness(10, 2, 10, 2), Margin = new Thickness(6, 0, 0, 0) };
        browse.Click += (_, _) =>
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Filter = Loc.T("Gorseller|*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff|Tüm dosyalar (*.*)|*.*") };
            if (dlg.ShowDialog(this) == true) { bgPath.Text = dlg.FileName; bgOn.IsChecked = true; }
        };
        def.Click += (_, _) => bgPath.Text = "";
        bgBtns.Children.Add(browse);
        bgBtns.Children.Add(def);
        root.Children.Add(bgBtns);
        var dim = new Slider { Minimum = 0, Maximum = 0.9, Value = cur.BackgroundDim, VerticalAlignment = VerticalAlignment.Center };
        root.Children.Add(Row("Görsel karartma", dim));
        var font = new ComboBox { IsEditable = true, Text = cur.FontFamily };
        foreach (var f in new[] { "Consolas", "Cascadia Mono", "Courier New", "Lucida Console", "Fixedsys" }) font.Items.Add(f);
        font.Text = cur.FontFamily;
        root.Children.Add(Row("Yazı tipi", font));
        var fsize = new TextBox { Text = cur.FontSize.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        root.Children.Add(Row("Yazı boyutu", fsize));
        var graph = new CheckBox { Content = Loc.T("Fonksiyonları varsayılan olarak graph görünümünde aç"), IsChecked = cur.GraphByDefault };
        var quick = new CheckBox { Content = Loc.T("Dosya açarken yukleme seçeneklerini sor (ileri düzey)"), IsChecked = cur.AskLoadOptions, Margin = new Thickness(0, 4, 0, 0) };
        root.Children.Add(graph);
        root.Children.Add(quick);

        // ---- disassembly ----
        root.Children.Add(Header("Disassembly"));
        var prefix = new CheckBox { Content = Loc.T("Satır önekleri (.text:00401000)"), IsChecked = cur.ShowPrefix };
        root.Children.Add(prefix);
        var opb = new TextBox { Text = cur.OpcodeBytes.ToString() };
        root.Children.Add(Row("Opcode bayt sayısı (0 = gizli)", opb));
        var xr = new TextBox { Text = cur.MaxXrefs.ToString() };
        root.Children.Add(Row("Gosterilecek xref sayısı", xr));
        var ms = new TextBox { Text = cur.MinStrLen.ToString() };
        root.Children.Add(Row("Strings: en kısa uzunluk", ms));
        var sym = new ComboBox();
        sym.Items.Add(Loc.T("Sor"));
        sym.Items.Add(Loc.T("Her zaman indir"));
        sym.Items.Add(Loc.T("Asla indirme"));
        sym.SelectedIndex = cur.SymbolMode switch { "always" => 1, "never" => 2, _ => 0 };
        root.Children.Add(Row("PDB sembolleri (sunucudan)", sym));
        var autosave = new CheckBox { Content = Loc.T("Kapatırken veritabanını sormadan kaydet"), IsChecked = cur.AutoSaveDb, Margin = new Thickness(0, 4, 0, 0) };
        root.Children.Add(autosave);

        // ---- AI (saglayici-bagimsiz, OpenAI-uyumlu) ----
        root.Children.Add(Header("AI desteği"));
        var baseUrl = new TextBox { Text = cur.AiBaseUrl };
        root.Children.Add(Row("Uç nokta (OpenAI uyumlu API)", baseUrl));
        var key = new PasswordBox { Password = cur.AiApiKey ?? "" };
        root.Children.Add(Row("API anahtarı", key));
        var model = new TextBox { Text = cur.AiModel };
        root.Children.Add(Row("Model", model));

        var ok = Dialogs.Btn("Tamam", true);
        var cancel = Dialogs.Btn("İptal", false, true);
        ok.Click += (_, _) =>
        {
            Result.ThemeName = theme.SelectedIndex switch { 0 => "light", 1 => "dark", _ => "purple" };
            Result.Dark = Result.ThemeName != "light";
            Result.BackgroundOn = bgOn.IsChecked == true;
            Result.BackgroundPath = string.IsNullOrWhiteSpace(bgPath.Text) ? null : bgPath.Text;
            Result.BackgroundDim = dim.Value;
            Result.FontFamily = string.IsNullOrWhiteSpace(font.Text) ? "Consolas" : font.Text.Trim();
            if (double.TryParse(fsize.Text, System.Globalization.NumberStyles.Any,
                    System.Globalization.CultureInfo.InvariantCulture, out var fs))
                Result.FontSize = Math.Clamp(fs, 8, 32);
            Result.GraphByDefault = graph.IsChecked == true;
            Result.AskLoadOptions = quick.IsChecked == true;
            Result.ShowPrefix = prefix.IsChecked == true;
            if (int.TryParse(opb.Text, out var ob)) Result.OpcodeBytes = Math.Clamp(ob, 0, 16);
            if (int.TryParse(xr.Text, out var x)) Result.MaxXrefs = Math.Clamp(x, 1, 100);
            if (int.TryParse(ms.Text, out var m)) Result.MinStrLen = Math.Clamp(m, 2, 64);
            Result.AutoSaveDb = autosave.IsChecked == true;
            Result.SymbolMode = sym.SelectedIndex switch { 1 => "always", 2 => "never", _ => "ask" };
            Result.AiApiKey = string.IsNullOrWhiteSpace(key.Password) ? null : key.Password;
            Result.AiModel = model.Text.Trim();
            Result.AiBaseUrl = baseUrl.Text.Trim();
            Result.Lang = lang.SelectedIndex == 1 ? "en" : "tr";
            DialogResult = true;
        };
        root.Children.Add(Dialogs.Buttons(ok, cancel));
        Content = root;
    }

    private static TextBlock Header(string t) => new()
    {
        Text = Loc.T(t),
        FontWeight = FontWeights.SemiBold,
        FontSize = 13,
        Margin = new Thickness(0, 12, 0, 6),
    };

    private static Grid Row(string label, FrameworkElement c)
    {
        var g = new Grid { Margin = new Thickness(0, 2, 0, 2) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var tb = new TextBlock { Text = Loc.T(label), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(c, 1);
        if (c is Control) c.MinHeight = 24;
        if (c is TextBox t) t.VerticalContentAlignment = VerticalAlignment.Center;
        if (c is PasswordBox pb) pb.VerticalContentAlignment = VerticalAlignment.Center;
        g.Children.Add(tb);
        g.Children.Add(c);
        return g;
    }
}
