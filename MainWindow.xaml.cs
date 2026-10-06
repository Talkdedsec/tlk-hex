using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using AvalonDock;
using AvalonDock.Layout;
using Microsoft.Win32;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

public partial class MainWindow : Window
{
    private Settings _cfg;
    private Session? _s;
    private AnalysisResult? _result;
    private bool _busy;

    // gorunumler
    private readonly DisasmView _dv = new();
    private readonly GraphView _gv = new();
    private readonly GraphOverview _ov = new();
    private readonly HexView _hv = new();
    private readonly PseudoView _pv = new();
    private readonly FunctionsPane _fp = new();
    private readonly CallTreePane _ct = new();
    private readonly OutputPane _out = new();
    private readonly Grid _idaPane = new();
    private readonly TextBlock _idaStatus = new();
    private readonly DockPanel _pseudoPane = new();
    private readonly TextBlock _pseudoTitle = new();

    // dock
    private DockingManager _dock = null!;
    private LayoutAnchorable _funcAnch = null!, _overAnch = null!, _treeAnch = null!, _outAnch = null!;
    private readonly Dictionary<string, LayoutDocument> _docs = new();
    private readonly Dictionary<string, (ListPane Pane, Func<List<Row>> Rows)> _lists = new();
    private readonly List<FrameworkElement> _needFile = new();

    public MainWindow()
    {
        InitializeComponent();
        _cfg = Settings.Load();
        Theme.Apply(_cfg.ThemeName);
        Theme.SetBackground(_cfg.BackgroundOn, _cfg.BackgroundPath, _cfg.BackgroundDim);

        BuildViews();
        BuildDock();
        BuildMenu();
        BuildToolbar();
        ApplyViewSettings();

        SetupGoBox();
        SetupSearchPane();
        Nav.Navigate += ea => Jump(ea);
        Theme.Changed += () => _fp.Reload();
        Closing += OnClosing;
        UpdateTitle();
        UpdateEnabled();
        UpdateDisk(null);

        _out.Log("tlk-hex - interaktif disassembler");
        _out.Log("Dosya > Aç (Ctrl+O) ile ya da sürükle-bırak ile PE / ELF / ham binary yükleyin. F1: kısayollar.");

        Width = Math.Max(MinWidth, _cfg.WinW);
        Height = Math.Max(MinHeight, _cfg.WinH);
        if (!double.IsNaN(_cfg.WinX) && !double.IsNaN(_cfg.WinY)
            && _cfg.WinX > SystemParameters.VirtualScreenLeft - 50 && _cfg.WinX < SystemParameters.VirtualScreenLeft + SystemParameters.VirtualScreenWidth - 100
            && _cfg.WinY > SystemParameters.VirtualScreenTop - 50 && _cfg.WinY < SystemParameters.VirtualScreenTop + SystemParameters.VirtualScreenHeight - 100)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = _cfg.WinX;
            SetValue(TopProperty, _cfg.WinY);
        }
        if (_cfg.WinMax) WindowState = WindowState.Maximized;
        if (Application.Current is App sa && sa.ShotDir != null)
        {
            WindowState = WindowState.Normal;
            ShowActivated = false;
            WindowStartupLocation = WindowStartupLocation.Manual;
            Left = -6000;
            SetValue(TopProperty, 0.0);
            Width = 1500;
            Height = 900;
        }
        Loaded += (_, _) =>
        {
            if (Application.Current is App app && !string.IsNullOrEmpty(app.StartupFile))
            {
                if (app.ShotDir != null) _ = RunShots(app.ShotDir, app.StartupFile);
                else OpenFile(app.StartupFile, !app.Autonomous);
            }
            UpdateWelcome();
        };
    }

    // ================= Kurulum =================

    private void BuildViews()
    {
        _dv.CursorMoved += () => { if (!_graphMode) OnViewCursor(_dv.CurrentEa); };
        _dv.LineActivated += FollowUnderCursor;
        _dv.MenuRequested += p => ShowViewMenu(_dv, p);
        _gv.CursorMoved += () => { if (_graphMode) OnViewCursor(_gv.CursorEa); };
        _gv.LineActivated += FollowUnderCursor;
        _gv.MenuRequested += p => ShowViewMenu(_gv, p);
        _gv.ViewChanged += UpdateIdaStatus;
        _gv.Visibility = Visibility.Collapsed;
        KeyboardNavigation.SetTabNavigation(_dv, KeyboardNavigationMode.None);
        KeyboardNavigation.SetTabNavigation(_gv, KeyboardNavigationMode.None);
        KeyboardNavigation.SetTabNavigation(_pv, KeyboardNavigationMode.None);

        _idaPane.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        _idaPane.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _idaPane.Children.Add(_dv);
        _idaPane.Children.Add(_gv);
        var sb = new Border { BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(6, 1, 6, 1) };
        sb.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        sb.SetResourceReference(Border.BackgroundProperty, "BgBrush");
        _idaStatus.FontFamily = new FontFamily("Consolas");
        _idaStatus.FontSize = 12;
        _idaStatus.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        sb.Child = _idaStatus;
        Grid.SetRow(sb, 1);
        _idaPane.Children.Add(sb);

        _ov.Graph = _gv;

        _hv.CursorMoved += OnHexCursor;
        _hv.BytePatched += OnBytePatched;
        _hv.EditModeChanged += () => SetStatus(_hv.EditMode
            ? "Hex View: DÜZENLEME modu (F2/Esc ile çık). Değişiklikler yama olarak kaydedilir."
            : "Hex View: düzenleme bitti.");
        _hv.MenuRequested += p => ShowHexMenu(p);

        _pv.CursorMoved += () =>
        {
            if (_s == null || _pv.CurrentEa == 0) return;
            Nav.Current = _pv.CurrentEa;
        };
        _pv.LineActivated += FollowUnderCursor;
        _pv.MenuRequested += p => ShowPseudoMenu(p);
        var bar = new DockPanel { Margin = new Thickness(4, 2, 4, 2) };
        _pseudoTitle.VerticalAlignment = VerticalAlignment.Center;
        _pseudoTitle.FontWeight = FontWeights.SemiBold;
        var aiBtn = new Button { Content = "AI ile decompile", Padding = new Thickness(10, 2, 10, 2), Margin = new Thickness(4, 0, 0, 0) };
        aiBtn.Click += (_, _) => AiDecompile();
        var reBtn = new Button { Content = "Yenile", Padding = new Thickness(10, 2, 10, 2) };
        reBtn.Click += (_, _) => ShowPseudo(_pseudoFunc?.Start);
        DockPanel.SetDock(aiBtn, Dock.Right);
        DockPanel.SetDock(reBtn, Dock.Right);
        bar.Children.Add(aiBtn);
        bar.Children.Add(reBtn);
        bar.Children.Add(_pseudoTitle);
        DockPanel.SetDock(bar, Dock.Top);
        _pseudoPane.Children.Add(bar);
        _pseudoPane.Children.Add(_pv);

        _dv.WordHover += (w, p) => OnWordHover(_dv, w, p);
        _gv.WordHover += (w, p) => OnWordHover(_gv, w, p);
        _pv.WordHover += (w, p) => OnWordHover(_pv, w, p);
        _dv.HoverEnd += HidePreview;
        _gv.HoverEnd += HidePreview;
        _pv.HoverEnd += HidePreview;
        BuildWelcome();

        _fp.Previewed += ea => Jump(ea, false, false);
        _fp.Activated += ea => Jump(ea);
        _fp.FoldersChanged += UpdateTitle;
        _ct.Activated += ea => Jump(ea);
        _out.Command += OnCommand;
    }

    private void BuildDock()
    {
        _dock = new DockingManager();
        ApplyDockTheme();
        var root = new LayoutRoot();
        var vert = new LayoutPanel { Orientation = Orientation.Vertical };
        var horiz = new LayoutPanel { Orientation = Orientation.Horizontal };
        var left = new LayoutAnchorablePaneGroup { Orientation = Orientation.Vertical, DockWidth = new GridLength(400) };
        var fpane = new LayoutAnchorablePane { DockHeight = new GridLength(2, GridUnitType.Star) };
        _funcAnch = new LayoutAnchorable { Title = "Functions", ContentId = "functions", Content = _fp, CanClose = false };
        fpane.Children.Add(_funcAnch);
        var lpane = new LayoutAnchorablePane { DockHeight = new GridLength(1, GridUnitType.Star) };
        _overAnch = new LayoutAnchorable { Title = "Graph overview", ContentId = "overview", Content = _ov, CanClose = false };
        _treeAnch = new LayoutAnchorable { Title = "Fonksiyon ağaçı", ContentId = "calltree", Content = _ct, CanClose = false };
        lpane.Children.Add(_overAnch);
        lpane.Children.Add(_treeAnch);
        left.Children.Add(fpane);
        left.Children.Add(lpane);
        var docPane = new LayoutDocumentPane();
        horiz.Children.Add(left);
        horiz.Children.Add(docPane);
        var opane = new LayoutAnchorablePane { DockHeight = new GridLength(230) };
        _outAnch = new LayoutAnchorable { Title = "Output", ContentId = "output", Content = _out, CanClose = false };
        opane.Children.Add(_outAnch);
        _searchAnch = new LayoutAnchorable { Title = "Arama", ContentId = "search", Content = _sp, CanClose = false };
        opane.Children.Add(_searchAnch);
        opane.SelectedContentIndex = 0;
        vert.Children.Add(horiz);
        vert.Children.Add(opane);
        root.RootPanel = vert;
        _dock.Layout = root;
        DockHost.Content = _dock;

        ShowDoc("idaview", "IDA View-A", _idaPane, false);
        ShowDoc("hexview", "Hex View-1", _hv, true, false);
        _docs["idaview"].IsActive = true;
    }

    private void ApplyDockTheme()
    {
        _dock.Theme = _cfg.ThemeName == "light" ? new AvalonDock.Themes.Vs2013LightTheme() : new AvalonDock.Themes.Vs2013DarkTheme();
        // dock renklerini temaya bagla (sekmeler, basliklar, kenarliklar)
        var p = UI.Theme.P;
        var R = _dock.Resources;
        R.Clear();
        void S(object key, System.Windows.Media.Color c) => R[key] = UI.Theme.B(c);
        R[AvalonDock.Themes.VS2013.Themes.ResourceKeys.ControlAccentColorKey] = p.Accent;
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ControlAccentBrushKey, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.Background, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.PanelBorderBrush, p.Border);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.TabBackground, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabSelectedActiveBackground, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabSelectedActiveText, System.Windows.Media.Colors.White);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabSelectedInactiveBackground, p.UiSel);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabSelectedInactiveText, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabUnselectedBackground, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.DocumentWellTabUnselectedText, p.TextDim);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionActiveBackground, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionActiveText, System.Windows.Media.Colors.White);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionActiveGrip, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionInactiveBackground, p.Surface);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionInactiveText, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowCaptionInactiveGrip, p.Surface);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabSelectedActiveBackground, p.Panel);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabSelectedActiveText, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabSelectedInactiveBackground, p.Panel);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabSelectedInactiveText, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabUnselectedBackground, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.ToolWindowTabUnselectedText, p.TextDim);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.FloatingDocumentWindowBackground, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.FloatingDocumentWindowBorder, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.FloatingToolWindowBackground, p.Window);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.FloatingToolWindowBorder, p.Accent);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.AutoHideTabDefaultBackground, p.Surface);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.AutoHideTabDefaultText, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.AutoHideTabDefaultBorder, p.Border);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.NavigatorWindowBackground, p.Surface);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.NavigatorWindowForeground, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.NavigatorWindowSelectedBackground, p.UiSel);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.NavigatorWindowSelectedText, p.Text);
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.PreviewBoxBackgroundBrushKey, System.Windows.Media.Color.FromArgb(0x50, p.Accent.R, p.Accent.G, p.Accent.B));
        S(AvalonDock.Themes.VS2013.Themes.ResourceKeys.PreviewBoxBorderBrushKey, p.Accent);
        DarkTitle(this, p.Dark);
    }

    // Windows 10/11 koyu baslik cubugu
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int v, int size);

    public static void DarkTitle(Window w, bool dark)
    {
        void Do()
        {
            var h = new System.Windows.Interop.WindowInteropHelper(w).Handle;
            if (h == IntPtr.Zero) return;
            int v = dark ? 1 : 0;
            try { DwmSetWindowAttribute(h, 20, ref v, sizeof(int)); } catch { }
        }
        if (new System.Windows.Interop.WindowInteropHelper(w).Handle != IntPtr.Zero) Do();
        else w.SourceInitialized += (_, _) => Do();
    }

    private LayoutDocument ShowDoc(string id, string title, object content, bool canClose = true, bool activate = true)
    {
        if (_docs.TryGetValue(id, out var d) && d.Parent != null)
        {
            d.Title = title;
            if (activate) d.IsActive = true;
            return d;
        }
        if (content is FrameworkElement fe && fe.Parent is ContentPresenter or ContentControl)
        {
            // eski kapatilmis belgeden ayir
            foreach (var old in _dock.Layout.Descendents().OfType<LayoutDocument>().Where(x => x.Content == content).ToList())
                old.Content = null;
        }
        d = new LayoutDocument { Title = title, ContentId = id, Content = content, CanClose = canClose, CanFloat = true };
        var doc = d;
        d.Closed += (_, _) =>
        {
            doc.Content = null;
            if (_docs.TryGetValue(id, out var cur) && cur == doc) _docs.Remove(id);
            if (id == "pseudo") _pseudoFunc = null;
        };
        DocPane().Children.Add(d);
        _docs[id] = d;
        if (activate) d.IsActive = true;
        return d;
    }

    private LayoutDocumentPane DocPane()
    {
        var p = _dock.Layout.Descendents().OfType<LayoutDocumentPane>().FirstOrDefault();
        if (p != null) return p;
        p = new LayoutDocumentPane();
        if (_dock.Layout.RootPanel is LayoutPanel rp)
        {
            var h = rp.Children.OfType<LayoutPanel>().FirstOrDefault() ?? rp;
            h.Children.Add(p);
        }
        return p;
    }

    private static void ShowAnch(LayoutAnchorable a)
    {
        if (a.IsHidden) a.Show();
        a.IsActive = true;
    }

    private void ApplyViewSettings()
    {
        _dv.SetFont(_cfg.FontFamily, _cfg.FontSize);
        _hv.SetFont(_cfg.FontFamily, _cfg.FontSize);
        _pv.SetFont(_cfg.FontFamily, _cfg.FontSize);
        _gv.SetFont(_cfg.FontFamily, _cfg.FontSize);
        if (_s != null)
        {
            ConfigureListing(_s.List);
            ulong ea = Here();
            _s.List.Build();
            _dv.Refresh();
            _gv.MarkDirty();
            Jump(ea, false, false);
        }
    }

    private void ConfigureListing(Listing l)
    {
        l.ShowPrefix = _cfg.ShowPrefix;
        l.OpBytes = _cfg.OpcodeBytes;
        l.MaxXrefs = _cfg.MaxXrefs;
    }

    // ================= Menu =================

    private MenuItem TopMenu(string header)
    {
        var m = new MenuItem { Header = header };
        MainMenu.Items.Add(m);
        return m;
    }

    private MenuItem Add(ItemsControl parent, string header, string gesture, Action act, bool needFile = true)
    {
        var mi = new MenuItem { Header = header, InputGestureText = gesture };
        mi.Click += (_, _) => act();
        parent.Items.Add(mi);
        if (needFile) _needFile.Add(mi);
        return mi;
    }

    private static void Sep(ItemsControl p) => p.Items.Add(new Separator());

    private MenuItem _recentMenu = null!;

    private void BuildMenu()
    {
        var file = TopMenu("_Dosya");
        Add(file, "Aç...", "Ctrl+O", () => OpenDialog(), false);
        Add(file, "Gelişmiş seçeneklerle aç...", "", () => OpenDialog(true), false);
        _recentMenu = new MenuItem { Header = "Son açılanlar" };
        _recentMenu.SubmenuOpened += (_, _) => FillRecent();
        _recentMenu.Items.Add(new MenuItem { Header = "(boş)" });
        file.Items.Add(_recentMenu);
        Sep(file);
        Add(file, "Veritabanını kaydet", "Ctrl+W", SaveDb);
        Sep(file);
        Add(file, "Sembolleri indir (Microsoft sembol sunucusu)", "", () => _ = DownloadSymbols());
        Add(file, "PDB dosyası yükle...", "", LoadPdbFile);
        Add(file, "Veritabanını sıfırla ve yeniden analiz et...", "", ResetDb);
        Sep(file);
        Add(file, "Başka dosyayla karşılaştır... (BinDiff)", "", CompareWith);
        Add(file, "Kütüphane imzası uygula (.sig)...", "", ApplySignatures);
        Sep(file);
        var produce = new MenuItem { Header = "Dosya üret" };
        file.Items.Add(produce);
        _needFile.Add(produce);
        Add(produce, "ASM dosyası oluştur...", "Alt+F10", () => ExportListing(false));
        Add(produce, "LST dosyası oluştur...", "", () => ExportListing(true));
        Add(produce, "DIF dosyası oluştur...", "", ExportDif);
        Add(produce, "Fonksiyonu C (pseudocode) olarak kaydet...", "", ExportPseudo);
        Add(produce, "Kütüphane imzası (.sig) üret...", "", GenerateSignatures);
        Add(produce, "Analiz raporu (HTML) oluştur...", "", ExportReport);
        Sep(file);
        Add(file, "Yamaları dosyaya uygula...", "", ApplyPatches);
        Sep(file);
        Add(file, "Kapat", "", () => CloseSession(true));
        Add(file, "Çıkış", "Alt+X", Close, false);

        var edit = TopMenu("_Düzen");
        Add(edit, "Kopyala", "Ctrl+C", CopySelection);
        Sep(edit);
        Add(edit, "Kod", "C", () => DoOp("C"));
        Add(edit, "Veri", "D", () => DoOp("D"));
        Add(edit, "String (ASCII / UTF-16)", "A", () => DoOp("A"));
        Add(edit, "Tanımsız yap", "U", () => DoOp("U"));
        Add(edit, "Offset yap / kaldır", "O", () => DoOp("O"));
        Add(edit, "Onaltılık / ondalık", "H", ToggleRadix);
        Sep(edit);
        Add(edit, "Yeniden adlandır...", "N", Rename);
        Add(edit, "Yorum...", ";", () => Comment(false));
        Add(edit, "Tekrarlanan yorum...", ":", () => Comment(true));
        Sep(edit);
        var fn = new MenuItem { Header = "Fonksiyonlar" };
        edit.Items.Add(fn);
        _needFile.Add(fn);
        Add(fn, "Fonksiyon oluştur", "P", () => DoOp("P"));
        Add(fn, "Fonksiyonu sil", "", () => DoOp("DF"));
        var patch = new MenuItem { Header = "Programı yamala" };
        edit.Items.Add(patch);
        _needFile.Add(patch);
        Add(patch, "Bayt değiştir...", "", PatchBytesDialog);
        Add(patch, "Hex View'da düzenle", "F2", () => { ShowDoc("hexview", "Hex View-1", _hv); _hv.Focus(); });
        Add(patch, "Yamalı baytları listele", "", ListPatches);

        var jump = TopMenu("_Atla");
        Add(jump, "Adrese atla...", "G", JumpDialog);
        Add(jump, "Fonksiyona atla...", "Ctrl+P", ChooseFunction);
        Add(jump, "Giriş noktasına atla...", "Ctrl+E", ChooseEntry);
        Add(jump, "İsme atla...", "Ctrl+L", ChooseName);
        Add(jump, "Segmente atla...", "Ctrl+S", ChooseSegment);
        Sep(jump);
        Add(jump, "Geri", "Esc", Back);
        Add(jump, "İleri", "Ctrl+Enter", Forward);
        Sep(jump);
        Add(jump, "Sonraki fonksiyon", "Ctrl+Down", () => NextFunc(true));
        Add(jump, "Önceki fonksiyon", "Ctrl+Up", () => NextFunc(false));
        Sep(jump);
        Add(jump, "Xref'ler (referans verenler)...", "X", XrefsTo);
        Add(jump, "Xref'ler (bu komuttan)...", "Ctrl+X", XrefsFrom);
        Sep(jump);
        Add(jump, "Konumu işaretle...", "Alt+M", MarkPosition);
        Add(jump, "İşaretli konuma atla...", "Ctrl+M", JumpMark);

        var search = TopMenu("_Ara");
        Add(search, "Arama paneli...", "Ctrl+Shift+F", () => ShowSearch());
        Sep(search);
        Add(search, "Metin...", "Alt+T", () => SearchText(false));
        Add(search, "Sonraki metin", "Ctrl+T", () => SearchText(true));
        Add(search, "Bayt dizisi...", "Alt+B", () => SearchBinary(false));
        Add(search, "Sonraki bayt dizisi", "Ctrl+B", () => SearchBinary(true));
        Add(search, "Sabit değer (immediate)...", "Alt+I", SearchImmediate);
        Sep(search);
        Add(search, "Sonraki kod", "Alt+C", () => NextKind("code"));
        Add(search, "Sonraki veri", "Ctrl+D", () => NextKind("data"));
        Add(search, "Sonraki keşfedilmemiş", "Ctrl+U", () => NextKind("unk"));
        Sep(search);
        Add(search, "Arama yönü: aşağı/yukarı", "", () => { _searchUp = !_searchUp; DirText.Text = _searchUp ? "Up" : "Down"; }, false);

        var view = TopMenu("_Görünüm");
        var sub = new MenuItem { Header = "Alt görünümleri aç" };
        view.Items.Add(sub);
        Add(sub, "Disassembly (IDA View-A)", "", () => { ShowDoc("idaview", "IDA View-A", _idaPane, false); FocusIda(); }, false);
        Add(sub, "Hex dump (Hex View-1)", "", () => ShowDoc("hexview", "Hex View-1", _hv), false);
        Add(sub, "Pseudocode", "F5", () => ShowPseudo(null));
        Sep(sub);
        Add(sub, "Functions", "Shift+F3", () => { ShowAnch(_funcAnch); _fp.List.Grid.Focus(); }, false);
        Add(sub, "Names", "Shift+F4", ShowNames);
        Add(sub, "Strings", "Shift+F12", ShowStrings);
        Add(sub, "Segments", "Shift+F7", ShowSegments);
        Add(sub, "Imports", "", ShowImports);
        Add(sub, "Exports", "", ShowExports);
        Add(sub, "Bulgular (güvenlik analizi)", "", ShowFindings);
        Sep(sub);
        Add(sub, "Fonksiyon ağaçı", "", () => ShowAnch(_treeAnch), false);
        Add(sub, "Graph overview", "", () => ShowAnch(_overAnch), false);
        Add(sub, "Output", "", () => ShowAnch(_outAnch), false);
        Sep(view);
        Add(view, "Graph / metin görünümü", "Space", () => SetGraph(!_graphMode));
        Add(view, "Graph'i pencereye sığdır", "W", () => _gv.FitAll());
        Add(view, "Graph %100", "1", () => _gv.ZoomTo(1));
        Sep(view);
        Add(view, "Hesap makinesi...", "?", Calculator, false);
        var pref = Add(view, "Satır önekleri", "", () => { _cfg.ShowPrefix = !_cfg.ShowPrefix; _cfg.Save(); ApplyViewSettings(); }, false);
        pref.IsCheckable = true;
        view.SubmenuOpened += (_, _) => pref.IsChecked = _cfg.ShowPrefix;

        var dbg = TopMenu("Hata a_yıklayıcı");
        foreach (var (h, g) in new[] { ("Hata ayıklayıcı seç...", ""), ("İşlemi başlat", "F9"), ("İşlemi sonlandır", "Ctrl+F2"),
                     ("Kesme noktası ekle/kaldır", "F2"), ("Adım adım (into)", "F7"), ("Adım adım (over)", "F8") })
        {
            var mi = new MenuItem { Header = h, InputGestureText = g, IsEnabled = false };
            dbg.Items.Add(mi);
        }
        Sep(dbg);
        dbg.Items.Add(new MenuItem { Header = "(Bu sürümde hata ayıklayıcı yok - statik analiz)", IsEnabled = false });

        var opt = TopMenu("_Seçenekler");
        Add(opt, "Genel...", "", OpenSettings, false);
        Sep(opt);
        Add(opt, "Açık tema (IDA)", "", () => SetTheme("light"), false);
        Add(opt, "Koyu tema", "", () => SetTheme("dark"), false);
        Add(opt, "Mor gece teması", "", () => SetTheme("purple"), false);
        Sep(opt);
        var bgItem = Add(opt, "Arka plan görseli", "", () =>
        {
            _cfg.BackgroundOn = !_cfg.BackgroundOn;
            _cfg.Save();
            Theme.SetBackground(_cfg.BackgroundOn, _cfg.BackgroundPath, _cfg.BackgroundDim);
        }, false);
        bgItem.IsCheckable = true;
        opt.SubmenuOpened += (_, _) => bgItem.IsChecked = _cfg.BackgroundOn;
        Add(opt, "Arka plan görseli seç...", "", PickBackground, false);
        Add(opt, "Varsayılan arka plana dön", "", () =>
        {
            _cfg.BackgroundPath = null;
            _cfg.BackgroundOn = true;
            _cfg.Save();
            Theme.SetBackground(true, null, _cfg.BackgroundDim);
        }, false);
        Sep(opt);
        Add(opt, "Yazı tipini büyüt", "Ctrl+Plus", () => { _cfg.FontSize = Math.Min(30, _cfg.FontSize + 1); _cfg.Save(); ApplyViewSettings(); }, false);
        Add(opt, "Yazı tipini küçült", "Ctrl+Minus", () => { _cfg.FontSize = Math.Max(8, _cfg.FontSize - 1); _cfg.Save(); ApplyViewSettings(); }, false);

        var win = TopMenu("_Pencereler");
        Add(win, "Varsayılan düzeni yükle", "", ResetLayout, false);
        Sep(win);
        Add(win, "IDA View-A", "", () => { ShowDoc("idaview", "IDA View-A", _idaPane, false); FocusIda(); }, false);
        Add(win, "Functions", "", () => ShowAnch(_funcAnch), false);
        Add(win, "Output", "", () => { ShowAnch(_outAnch); _out.FocusInput(); }, false);
        Add(win, "Arama", "Ctrl+Shift+F", () => ShowSearch(), false);

        var help = TopMenu("_Yardım");
        Add(help, "Hızlı rehber", "F1", ShowGuide, false);
        Add(help, "Klavye kısayolları", "", () => Dialogs.Info(this, "Klavye kısayolları", Dialogs.Shortcuts), false);
        Add(help, "IDC komutları", "", () => _out.Log(IdcHelp), false);
        Sep(help);
        Add(help, "Hakkında", "", () => Dialogs.Info(this, "tlk-hex hakkında",
            "tlk-hex - interaktif disassembler\n\nx86 / x64 PE, ELF ve ham binary için statik analiz:\n" +
            "otomatik analiz, xref'ler, graph görünümü, hex view, yamalama,\nbasit pseudocode ve AI desteği.\n\n" +
            "Disassembly motoru: Iced\nPencere yerleşimi: AvalonDock\n\n" +
            "Yazar: Talkdedsec\nhttps://github.com/Talkdedsec/tlk-hex\n" +
            "Lisans: MIT + Commons Clause (satış yasak, atıf zorunlu)\n© 2026 Talkdedsec"), false);
    }

    private void FillRecent()
    {
        _recentMenu.Items.Clear();
        var r = RecentFiles.Load();
        if (r.Count == 0) _recentMenu.Items.Add(new MenuItem { Header = "(boş)", IsEnabled = false });
        int i = 1;
        foreach (var p in r)
        {
            var path = p;
            var mi = new MenuItem { Header = $"_{i++} {path}" };
            mi.Click += (_, _) => OpenFile(path, _cfg.AskLoadOptions);
            _recentMenu.Items.Add(mi);
        }
    }

    // ================= Arac cubugu =================

    private void BuildToolbar()
    {
        void B(string glyph, string tip, Action act, string? label = null, bool needFile = true, Color? color = null)
        {
            var tb = new TextBlock
            {
                Text = glyph,
                FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
                FontSize = 15,
                VerticalAlignment = VerticalAlignment.Center,
            };
            if (color is Color c) tb.Foreground = new SolidColorBrush(c);
            else tb.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
            object content = tb;
            var b = new Button { ToolTip = tip, Style = (Style)FindResource("Tb") };
            if (label != null)
            {
                var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 0, 6, 0) };
                sp.Children.Add(tb);
                var lt = new TextBlock { Text = label, Margin = new Thickness(5, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, FontSize = 12 };
                lt.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
                sp.Children.Add(lt);
                content = sp;
                b.Width = double.NaN;
            }
            b.Content = content;
            b.Click += (_, _) => act();
            ToolBarPanel.Children.Add(b);
            if (needFile) _needFile.Add(b);
        }
        void S()
        {
            var r = new Border { Width = 1, Height = 18, Margin = new Thickness(5, 0, 5, 0) };
            r.SetResourceReference(Border.BackgroundProperty, "BorderBrush");
            ToolBarPanel.Children.Add(r);
        }
        B("\uE838", "Dosya aç (Ctrl+O)", () => OpenDialog(), "Aç", false, Color.FromRgb(0xE0, 0xA8, 0x2E));
        B("\uE74E", "Çalışmayı kaydet (Ctrl+W)", SaveDb, "Kaydet", true, Color.FromRgb(0x3A, 0x7B, 0xD5));
        S();
        B("\uE72B", "Geri (Esc / fare geri tuşu)", Back);
        B("\uE72A", "İleri (Ctrl+Enter / fare ileri tuşu)", Forward);
        ToolBarPanel.Children.Add(_go);
        _needFile.Add(_go);
        S();
        B("\uE721", "Arama paneli: isim, metin, kod, bayt, sabit (Ctrl+Shift+F)", () => ShowSearch(), "Ara");
        B("\uE8FD", "Fonksiyon listesinden seç (Ctrl+P)", ChooseFunction, "Fonksiyonlar");
        B("\uE71B", "Bu nereden kullanılıyor? (X)", XrefsTo, "Referanslar");
        S();
        B("\uE8A9", "Graph / metin görünümü (Space)", () => SetGraph(!_graphMode), "Graph", true, Color.FromRgb(0x2E, 0x9E, 0x5B));
        B("\uE943", "C benzeri pseudocode (F5)", () => ShowPseudo(null), "Pseudocode", true, Color.FromRgb(0x8E, 0x5C, 0xD9));
        B("\uE8A5", "Ham baytlar (Hex View)", () => ShowDoc("hexview", "Hex View-1", _hv), "Hex");
        B("\uE8D2", "Dosyadaki metinler (Shift+F12)", ShowStrings, "Strings");
        B("\uE7BA", "Güvenlik bulguları", ShowFindings, "Bulgular", true, Color.FromRgb(0xE0, 0x8A, 0x1E));
        S();
        B("\uE945", "AI'ya soru sor (Output > AI)", () => { ShowAnch(_outAnch); _out.Mode = "AI"; _out.FocusInput(); }, "AI", true, Color.FromRgb(0x8E, 0x5C, 0xD9));
        B("\uE897", "Hızlı rehber (F1)", ShowGuide, null, false);
        B("\uE793", "Tema değiştir (açık / koyu / mor)", () => SetTheme(_cfg.ThemeName switch { "light" => "dark", "dark" => "purple", _ => "light" }), null, false);
        B("\uE713", "Seçenekler", OpenSettings, null, false);
    }

    private void UpdateEnabled()
    {
        bool has = _s != null && !_busy;
        foreach (var e in _needFile) e.IsEnabled = has;
    }

    // ================= Tema / ayarlar =================

    private void PickBackground()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Arka plan görseli seç",
            Filter = "Gorseller|*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff|Tüm dosyalar (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        _cfg.BackgroundPath = dlg.FileName;
        _cfg.BackgroundOn = true;
        _cfg.Save();
        Theme.SetBackground(true, dlg.FileName, _cfg.BackgroundDim);
        if (Theme.BgImage == null) _out.Log("Görsel yüklenemedi: " + dlg.FileName);
    }

    private void SetTheme(string name)
    {
        _cfg.ThemeName = name;
        _cfg.Dark = name != "light";
        _cfg.Save();
        Theme.Apply(name);
        ApplyDockTheme();
        _dv.Refresh();
        _hv.Refresh();
        _pv.Refresh();
        _gv.InvalidateVisual();
        Nav.InvalidateVisual();
    }

    private void OpenSettings()
    {
        var w = new SettingsWindow(_cfg) { Owner = this };
        if (w.ShowDialog() != true) return;
        bool themeChanged = w.Result.ThemeName != _cfg.ThemeName;
        int oldMin = _cfg.MinStrLen;
        _cfg = w.Result;
        _cfg.Save();
        if (themeChanged) SetTheme(_cfg.ThemeName);
        Theme.SetBackground(_cfg.BackgroundOn, _cfg.BackgroundPath, _cfg.BackgroundDim);
        ApplyViewSettings();
        if (_s != null && oldMin != _cfg.MinStrLen)
        {
            _s.Au.MinStrLen = _cfg.MinStrLen;
            _s.Au.BuildStrings();
            RefreshLists();
        }
    }

    private void ResetLayout()
    {
        ShowAnch(_funcAnch);
        ShowAnch(_overAnch);
        ShowAnch(_treeAnch);
        ShowAnch(_searchAnch);
        ShowAnch(_outAnch);
        ShowDoc("idaview", "IDA View-A", _idaPane, false);
        ShowDoc("hexview", "Hex View-1", _hv, true, false);
        _docs["idaview"].IsActive = true;
    }

    // ================= Durum =================

    private void SetAu(bool busy, string? text = null)
    {
        AuDot.Fill = new SolidColorBrush(busy ? Color.FromRgb(0xE8, 0xB0, 0x20) : Color.FromRgb(0x3C, 0xB0, 0x43));
        AuText.Text = text ?? (busy ? "AU:  busy" : "AU:  idle");
    }

    private void SetStatus(string s) => StatusMsg.Text = s;

    private void UpdateDisk(string? path)
    {
        try
        {
            var root = Path.GetPathRoot(path ?? Environment.CurrentDirectory);
            if (root != null)
            {
                var di = new DriveInfo(root);
                DiskText.Text = $"Disk: {di.AvailableFreeSpace / (1L << 30)}GB";
            }
        }
        catch { DiskText.Text = "Disk: -"; }
    }

    private void UpdateTitle()
    {
        if (_s == null) { Title = "tlk-hex"; return; }
        Title = $"tlk-hex - {Path.GetFileName(_s.Db.FilePath)} {_s.Db.FilePath}{(_s.Db.Dirty ? " *" : "")}";
    }

    // ================= Dosya =================

    private void OpenDialog(bool advanced = false)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Disassemble edilecek dosyayı seç",
            Filter = "Çalıştırılabilir dosyalar|*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr;*.drv;*.efi;*.node;*.so;*.elf;*.o;*.bin|Tüm dosyalar (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) OpenFile(dlg.FileName, advanced || _cfg.AskLoadOptions);
    }

    private void QuickStart()
    {
        if (_s != null) return;
        var r = Dialogs.QuickStart(this, RecentFiles.Load());
        if (r == null || r == "go") return;
        if (r == "new") OpenDialog();
        else if (r.StartsWith("prev:")) OpenFile(r[5..], true);
    }

    private async void OpenFile(string path, bool ask)
    {
        if (_busy || !File.Exists(path)) return;
        if (_s != null && !CloseSession(true)) return;

        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch (Exception ex) { Dialogs.Info(this, "Hata", "Dosya okunamadı:\n" + ex.Message); return; }

        bool hasIdb = IdbStore.Exists(path);
        LoadOptions? opt;
        bool useIdb = hasIdb;
        if (ask)
        {
            opt = Dialogs.Load(this, path, bytes, hasIdb, out useIdb);
            if (opt == null) return;
        }
        else opt = new LoadOptions();
        var idb = useIdb ? IdbStore.Load(path) : null;
        if (idb != null && idb.Loader == "bin" && opt.Loader != "bin")
        {
            opt.Loader = "bin";
            opt.BinBitness = idb.BinBitness;
            opt.BinBase = idb.BinBase;
        }

        _busy = true;
        UpdateEnabled();
        UpdateWelcome();
        SetAu(true, "AU:  yükleniyor");
        Mouse.OverrideCursor = Cursors.AppStarting;
        _out.Log("");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Session? s = null;
        try
        {
            var o = opt;
            int minStr = _cfg.MinStrLen;
            s = await Task.Run(() => Session.Open(path, o, idb, minStr,
                m => Dispatcher.BeginInvoke(() => _out.Log(m)),
                p => Dispatcher.BeginInvoke(() => SetAu(true, p)),
                ConfigureListing));
        }
        catch (Exception ex)
        {
            _out.Log("HATA: " + ex.Message);
            Dialogs.Info(this, "Yükleme hatası", "Dosya analiz edilemedi:\n\n" + ex.Message);
        }
        finally
        {
            Mouse.OverrideCursor = null;
            _busy = false;
            SetAu(false);
        }
        if (s == null) { UpdateEnabled(); UpdateWelcome(); return; }

        _s = s;
        _result = null;
        RecentFiles.Add(path);
        UpdateDisk(path);
        BindSession();
        _out.Log($"Otomatik analiz tamamlandı ({sw.Elapsed.TotalSeconds:0.00} sn).");
        if (s.Db.IsDotNet)
            _out.Log("Not: Bu bir .NET assembly; IL kodu yerine yalnızca yerel giriş kodu disassemble edildi.");

        ulong start = s.DefaultEa();
        _graphMode = false;
        _dv.Visibility = Visibility.Visible;
        _gv.Visibility = Visibility.Collapsed;
        _back.Clear();
        _fwd.Clear();
        if (_cfg.GraphByDefault && s.Db.FuncAt(start) != null) SetGraph(true, start);
        Jump(start, false);
        ShowImports(false);
        ShowExports(false);
        _docs["idaview"].IsActive = true;
        FocusIda();
        UpdateTitle();
        UpdateEnabled();
        if (s.Db.SymbolSource != null) SetStatus("Semboller yüklendi: " + Path.GetFileName(s.Db.SymbolSource));
        AfterOpenSymbols();
    }

    private void BindSession()
    {
        _dv.Session = _s;
        _hv.Session = _s;
        _gv.MarkDirty();
        Nav.SetSession(_s);
        _fp.SetSession(_s);
        _ct.SetSession(_s);
        RefreshLists();
        BuildGoItems();
        UpdateWelcome();
    }

    private bool CloseSession(bool ask)
    {
        if (_s == null) return true;
        if (_s.Db.Dirty)
        {
            bool? save = _cfg.AutoSaveDb ? true : ask ? Dialogs.AskSave(this, Path.GetFileName(_s.Db.FilePath)) : false;
            if (save == null) return false;
            if (save == true) SaveDb();
        }
        foreach (var id in _docs.Keys.Where(k => k is not ("idaview" or "hexview")).ToList())
            _docs[id].Close();
        _lists.Clear();
        _s = null;
        _result = null;
        _pseudoFunc = null;
        BindSession();
        _graphMode = false;
        _gv.Visibility = Visibility.Collapsed;
        _dv.Visibility = Visibility.Visible;
        _idaStatus.Text = "";
        UpdateTitle();
        UpdateEnabled();
        return true;
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (_busy) { e.Cancel = true; return; }
        if (!CloseSession(true)) { e.Cancel = true; return; }
        if (Application.Current is App { ShotDir: not null }) return;
        var b = RestoreBounds;
        _cfg.WinMax = WindowState == WindowState.Maximized;
        if (!b.IsEmpty)
        {
            _cfg.WinX = b.Left;
            _cfg.WinY = b.Top;
            _cfg.WinW = b.Width;
            _cfg.WinH = b.Height;
        }
        _cfg.Save();
    }

    private void SaveDb()
    {
        if (_s == null) return;
        try
        {
            IdbStore.Save(_s.Db, _s.Opt, Here());
            _out.Log($"Veritabanı kaydedildi: {IdbStore.PathFor(_s.Db.FilePath)}");
            SetStatus("Veritabanı kaydedildi.");
        }
        catch (Exception ex) { _out.Log("Kaydetme hatası: " + ex.Message); }
        UpdateTitle();
    }

    private void ResetDb()
    {
        if (_s == null) return;
        if (!Dialogs.Confirm(this, "Veritabanını sıfırla",
                "Kayıtlı isimler, yorumlar, tanımlar ve yamalar silinip dosya baştan analiz edilecek. Emin misin?"))
            return;
        string path = _s.Db.FilePath;
        _s.Db.Dirty = false;
        IdbStore.Delete(path);
        CloseSession(false);
        OpenFile(path, false);
    }

    private void Window_DragEnter(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files) OpenFile(files[0], _cfg.AskLoadOptions);
    }

    // ================= Disa aktarim =================

    private async void ExportListing(bool lst)
    {
        if (_s == null) return;
        var dlg = new SaveFileDialog
        {
            Title = lst ? "LST dosyası oluştur" : "ASM dosyası oluştur",
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + (lst ? ".lst" : ".asm"),
            Filter = lst ? "Listing (*.lst)|*.lst" : "Assembly (*.asm)|*.asm",
        };
        if (dlg.ShowDialog(this) != true) return;
        var worker = _s.List.CloneForWorker();
        string outp = dlg.FileName;
        SetAu(true, "AU:  yazılıyor");
        try
        {
            await Task.Run(() =>
            {
                using var w = new StreamWriter(outp);
                worker.Export(w, lst);
            });
            _out.Log($"{(lst ? "LST" : "ASM")} dosyası oluşturuldu: {outp}");
        }
        catch (Exception ex) { _out.Log("Hata: " + ex.Message); }
        SetAu(false);
    }

    private void ExportDif()
    {
        if (_s == null) return;
        if (_s.Db.Patches.Count == 0) { _out.Log("Yamalı bayt yok."); return; }
        var dlg = new SaveFileDialog { FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + ".dif", Filter = "DIF (*.dif)|*.dif" };
        if (dlg.ShowDialog(this) != true) return;
        _s.ExportDif(dlg.FileName);
        _out.Log($"DIF dosyası oluşturuldu: {dlg.FileName}");
    }

    private void ApplyPatches()
    {
        if (_s == null) return;
        if (_s.Db.Patches.Count == 0) { _out.Log("Uygulanacak yama yok."); return; }
        var dlg = new SaveFileDialog
        {
            Title = "Yamalı dosyayı kaydet",
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + ".patched" + Path.GetExtension(_s.Db.FilePath),
            Filter = "Tüm dosyalar (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        if (string.Equals(Path.GetFullPath(dlg.FileName), Path.GetFullPath(_s.Db.FilePath), StringComparison.OrdinalIgnoreCase)
            && !Dialogs.Confirm(this, "Uyarı", "Orijinal dosyanın üzerine yazılacak. Emin misin?"))
            return;
        int n = _s.ApplyPatchesToFile(dlg.FileName);
        _out.Log($"{n} bayt yaması uygulandı: {dlg.FileName}");
    }

    private void ExportPseudo()
    {
        if (_s == null) return;
        var f = _s.Db.FuncAt(Here());
        if (f == null) { _out.Log("İmleç bir fonksiyon içinde değil."); return; }
        var dlg = new SaveFileDialog { FileName = _s.Db.FuncName(f) + ".c", Filter = "C (*.c)|*.c" };
        if (dlg.ShowDialog(this) != true) return;
        var lines = _pseudoFunc == f ? Enumerable.Range(0, (int)_pv.LineCountPublic).Select(i => _pv.LineAt(i).Plain)
            : _s.Pseudo.Decompile(f).Select(l => l.Plain);
        File.WriteAllLines(dlg.FileName, lines);
        _out.Log($"Pseudocode kaydedildi: {dlg.FileName}");
    }
}
