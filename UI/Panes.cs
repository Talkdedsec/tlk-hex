using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

public sealed class Row
{
    public ulong Ea { get; set; }
    public string[] C { get; set; } = Array.Empty<string>();
    public object? Tag { get; set; }
    public Brush? Fg { get; set; }
}

// Satir rengi yoksa temanin metin rengi
public sealed class FgConv : IValueConverter
{
    public static readonly FgConv I = new();
    public object Convert(object? v, Type t, object? p, System.Globalization.CultureInfo c) => v as Brush ?? Theme.B(Theme.P.Text);
    public object ConvertBack(object? v, Type t, object? p, System.Globalization.CultureInfo c) => throw new NotSupportedException();
}

// IDA "chooser" tarzi liste: siralanabilir sutunlar + hizli filtre
public class ListPane : DockPanel
{
    public readonly DataGrid Grid;
    private readonly TextBox _filter;
    private readonly TextBlock _ph;
    private readonly TextBlock _count;
    private ListCollectionView? _view;
    private List<Row> _rows = new();

    public event Action<Row>? Activated;
    public Func<Row?, ContextMenu?>? MenuFor;

    public ListPane((string Header, double Width)[] cols, bool mono = true)
    {
        Grid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            SelectionMode = DataGridSelectionMode.Extended,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.None,
            CanUserAddRows = false,
            CanUserDeleteRows = false,
            CanUserResizeRows = false,
            EnableRowVirtualization = true,
            EnableColumnVirtualization = false,
            RowHeaderWidth = 0,
            BorderThickness = new Thickness(0),
            FontFamily = new FontFamily(mono ? "Consolas" : "Segoe UI"),
            FontSize = 12.5,
        };
        VirtualizingPanel.SetIsVirtualizing(Grid, true);
        VirtualizingPanel.SetVirtualizationMode(Grid, VirtualizationMode.Recycling);
        for (int i = 0; i < cols.Length; i++)
        {
            var col = new DataGridTextColumn
            {
                Header = Loc.T(cols[i].Header),
                Binding = new Binding($"C[{i}]"),
                Width = cols[i].Width <= 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(cols[i].Width),
                SortMemberPath = $"C[{i}]",
            };
            if (i == 0)
            {
                var st = new Style(typeof(TextBlock));
                st.Setters.Add(new Setter(TextBlock.ForegroundProperty, new Binding("Fg") { Converter = FgConv.I }));
                col.ElementStyle = st;
            }
            Grid.Columns.Add(col);
        }
        Grid.MouseDoubleClick += (_, e) =>
        {
            if (e.OriginalSource is DependencyObject d && FindParent<DataGridColumnHeader>(d) != null) return;
            if (Grid.SelectedItem is Row r) Activated?.Invoke(r);
        };
        Grid.PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && Grid.SelectedItem is Row r)
            {
                Activated?.Invoke(r);
                e.Handled = true;
            }
            else if (e.Key == Key.F && Keyboard.Modifiers == ModifierKeys.Control)
            {
                FocusFilter();
                e.Handled = true;
            }
        };
        Grid.ContextMenuOpening += (_, e) =>
        {
            var m = MenuFor?.Invoke(Grid.SelectedItem as Row);
            if (m == null) { e.Handled = true; return; }
            Grid.ContextMenu = m;
        };
        Grid.ContextMenu = new ContextMenu();

        var bar = new Grid { Margin = new Thickness(0) };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        _filter = new TextBox { BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(4, 2, 4, 2), FontSize = 12 };
        _filter.SetResourceReference(TextBox.BorderBrushProperty, "BorderBrush");
        _ph = new TextBlock
        {
            Text = Loc.T("Hızlı filtre (Ctrl+F)"),
            IsHitTestVisible = false,
            Margin = new Thickness(7, 3, 0, 0),
            FontSize = 12,
        };
        _ph.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        _count = new TextBlock { Margin = new Thickness(6, 3, 6, 0), FontSize = 11.5 };
        _count.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        System.Windows.Controls.Grid.SetColumn(_count, 1);
        bar.Children.Add(_filter);
        bar.Children.Add(_ph);
        bar.Children.Add(_count);
        _filter.TextChanged += (_, _) =>
        {
            _ph.Visibility = _filter.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            _view?.Refresh();
            UpdateCount();
        };
        _filter.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) { _filter.Text = ""; Grid.Focus(); }
            if (e.Key is Key.Down or Key.Enter) { Grid.Focus(); if (Grid.Items.Count > 0 && Grid.SelectedIndex < 0) Grid.SelectedIndex = 0; }
        };
        SetDock(bar, Dock.Bottom);
        Children.Add(bar);
        Children.Add(Grid);
    }

    private static T? FindParent<T>(DependencyObject d) where T : DependencyObject
    {
        while (d != null && d is not T) d = VisualTreeHelper.GetParent(d) ?? LogicalTreeHelper.GetParent(d);
        return d as T;
    }

    public void SetRows(List<Row> rows)
    {
        _rows = rows;
        _view = new ListCollectionView(rows);
        _view.Filter = o =>
        {
            string q = _filter.Text.Trim();
            if (q.Length == 0) return true;
            var r = (Row)o;
            foreach (var c in r.C) if (c != null && c.Contains(q, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        };
        Grid.ItemsSource = _view;
        UpdateCount();
    }

    public List<Row> Rows => _rows;
    public Row? Selected => Grid.SelectedItem as Row;
    public IEnumerable<Row> SelectedRows => Grid.SelectedItems.OfType<Row>();

    private void UpdateCount()
    {
        int shown = _view?.Count ?? 0;
        _count.Text = shown == _rows.Count ? $"{_rows.Count:N0}" : $"{shown:N0} / {_rows.Count:N0}";
    }

    public void FocusFilter()
    {
        _filter.Focus();
        _filter.SelectAll();
    }

    public void SelectEa(ulong ea)
    {
        var r = _rows.FirstOrDefault(x => x.Ea == ea);
        if (r == null || _view == null || !_view.Contains(r)) return;
        Grid.SelectedItem = r;
        Grid.ScrollIntoView(r);
    }
}

// Agac dugumu (Functions klasorleri)
public sealed class TNode
{
    public string Text { get; set; } = "";
    public string Icon { get; set; } = "";
    public Brush? IconBrush { get; set; }
    public ulong Ea { get; set; }
    public bool IsFolder { get; set; }
    public string Folder { get; set; } = "";
    public ObservableCollection<TNode> Kids { get; } = new();
}

// Functions penceresi: liste veya klasorlu agac
public sealed class FunctionsPane : Grid
{
    public readonly ListPane List;
    public readonly TreeView Tree;
    private Session? _s;
    public bool FolderMode { get; private set; }

    public event Action<ulong>? Activated;
    public event Action<ulong>? Previewed;    // tek tik / ok tuslari ile secim
    public event Action? FoldersChanged;

    public FunctionsPane()
    {
        List = new ListPane(new[]
        {
            ("Function name", 160.0), ("Segment", 62.0), ("Start", 128.0), ("Length", 75.0), ("Locals", 60.0),
            ("Arguments", 65.0), ("R", 18.0), ("F", 18.0), ("L", 18.0), ("S", 18.0), ("B", 18.0), ("T", 18.0), ("=", 18.0),
        });
        List.Activated += r => Activated?.Invoke(r.Ea);
        List.Grid.SelectionChanged += (_, _) =>
        {
            if (List.Grid.IsKeyboardFocusWithin && List.Selected is Row r) Previewed?.Invoke(r.Ea);
        };
        List.MenuFor = r => Menu(r?.Ea);

        Tree = new TreeView { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 12.5, Visibility = Visibility.Collapsed };
        Tree.SetResourceReference(Control.BackgroundProperty, "PanelBrush");
        VirtualizingPanel.SetIsVirtualizing(Tree, true);
        VirtualizingPanel.SetVirtualizationMode(Tree, VirtualizationMode.Recycling);
        var tpl = new HierarchicalDataTemplate(typeof(TNode)) { ItemsSource = new Binding("Kids") };
        var sp = new FrameworkElementFactory(typeof(StackPanel));
        sp.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
        var ic = new FrameworkElementFactory(typeof(TextBlock));
        ic.SetBinding(TextBlock.TextProperty, new Binding("Icon"));
        ic.SetBinding(TextBlock.ForegroundProperty, new Binding("IconBrush"));
        ic.SetValue(TextBlock.FontFamilyProperty, new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets, Segoe UI Symbol"));
        ic.SetValue(TextBlock.MarginProperty, new Thickness(0, 1, 6, 0));
        ic.SetValue(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center);
        var tx = new FrameworkElementFactory(typeof(TextBlock));
        tx.SetBinding(TextBlock.TextProperty, new Binding("Text"));
        tx.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        sp.AppendChild(ic);
        sp.AppendChild(tx);
        tpl.VisualTree = sp;
        Tree.ItemTemplate = tpl;
        Tree.SelectedItemChanged += (_, _) =>
        {
            if (Tree.IsKeyboardFocusWithin && Tree.SelectedItem is TNode { IsFolder: false } n) Previewed?.Invoke(n.Ea);
        };
        Tree.MouseDoubleClick += (_, _) =>
        {
            if (Tree.SelectedItem is TNode { IsFolder: false } n) Activated?.Invoke(n.Ea);
        };
        Tree.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && Tree.SelectedItem is TNode { IsFolder: false } n) Activated?.Invoke(n.Ea);
        };
        Tree.ContextMenuOpening += (_, e) =>
        {
            var n = Tree.SelectedItem as TNode;
            var m = Menu(n is { IsFolder: false } ? n.Ea : null, n);
            if (m == null) { e.Handled = true; return; }
            Tree.ContextMenu = m;
        };
        Tree.ContextMenu = new ContextMenu();

        Children.Add(List);
        Children.Add(Tree);
    }

    public void SetSession(Session? s)
    {
        _s = s;
        Reload();
    }

    public void Reload()
    {
        if (_s == null) { List.SetRows(new List<Row>()); Tree.ItemsSource = null; return; }
        var db = _s.Db;
        var rows = new List<Row>();
        foreach (var f in db.Funcs.Values.OrderBy(f => f.Start))
        {
            if (f.Chunks.Count == 0) continue;
            var s = db.SegOf(f.Start);
            ulong len = 0;
            foreach (var c in f.Chunks) len += c.End - c.Start;
            int ptr = db.Ptr;
            rows.Add(new Row
            {
                Ea = f.Start,
                Tag = f,
                Fg = f.IsThunk || f.IsLibrary ? Theme.B(Theme.P.PrefixLib) : null,
                C = new[]
                {
                    db.FuncName(f), s?.Name ?? "", db.AddrStr(f.Start), len.ToString("X8"),
                    f.LocalsSize.ToString("X8"), f.ArgsSize(ptr).ToString("X8"),
                    f.NoReturn ? "." : "R", ".", f.IsLibrary ? "L" : ".", ".", f.BpBased ? "B" : ".", ".", ".",
                },
            });
        }
        List.SetRows(rows);
        if (FolderMode) BuildTree();
    }

    public void ToggleFolders()
    {
        FolderMode = !FolderMode;
        List.Visibility = FolderMode ? Visibility.Collapsed : Visibility.Visible;
        Tree.Visibility = FolderMode ? Visibility.Visible : Visibility.Collapsed;
        if (FolderMode) BuildTree();
    }

    private void BuildTree()
    {
        if (_s == null) return;
        var db = _s.Db;
        var inFolder = new HashSet<ulong>();
        var roots = new List<TNode>();
        var folderBrush = Theme.B(Color.FromRgb(0xE8, 0xB3, 0x3C));
        foreach (var kv in db.Folders.OrderBy(k => k.Key))
        {
            var fn = new TNode { Text = kv.Key, Icon = "", IconBrush = folderBrush, IsFolder = true, Folder = kv.Key };
            foreach (var ea in kv.Value)
            {
                if (!db.Funcs.TryGetValue(ea, out var f)) continue;
                fn.Kids.Add(FuncNode(f));
                inFolder.Add(ea);
            }
            fn.Text = $"{kv.Key}  ({fn.Kids.Count})";
            roots.Add(fn);
        }
        foreach (var f in db.Funcs.Values.OrderBy(f => f.Start))
            if (f.Chunks.Count > 0 && !inFolder.Contains(f.Start)) roots.Add(FuncNode(f));
        Tree.ItemsSource = roots;
    }

    private TNode FuncNode(Function f) => new()
    {
        Text = _s!.Db.FuncName(f),
        Icon = "",
        IconBrush = Theme.B(f.IsThunk || f.IsLibrary ? Theme.P.NavLib : Theme.P.NavFunc),
        Ea = f.Start,
    };

    private ContextMenu? Menu(ulong? ea, TNode? node = null)
    {
        var m = new ContextMenu();
        if (ea is ulong e)
        {
            m.Items.Add(Mi("Atla", () => Activated?.Invoke(e)));
            m.Items.Add(Mi("Klasöre taşı...", () => MoveToFolder(SelectedEas())));
            if (FolderMode && node != null && FindFolderOf(e) != null)
                m.Items.Add(Mi("Klasörden çıkar", () => RemoveFromFolder(e)));
            m.Items.Add(new Separator());
        }
        m.Items.Add(Mi("Yeni klasör oluştur...", () => NewFolder()));
        if (node is { IsFolder: true })
            m.Items.Add(Mi("Klasörü sil", () =>
            {
                _s!.Db.Folders.Remove(node.Folder);
                _s.Db.Dirty = true;
                BuildTree();
                FoldersChanged?.Invoke();
            }));
        m.Items.Add(new Separator());
        m.Items.Add(Mi(FolderMode ? "Düz liste göster" : "Klasörleri göster (ağaç)", ToggleFolders));
        if (!FolderMode) m.Items.Add(Mi("Hızlı filtre\tCtrl+F", List.FocusFilter));
        return m;
    }

    private List<ulong> SelectedEas()
    {
        if (FolderMode) return Tree.SelectedItem is TNode { IsFolder: false } n ? new List<ulong> { n.Ea } : new();
        return List.SelectedRows.Select(r => r.Ea).ToList();
    }

    private string? FindFolderOf(ulong ea) => _s?.Db.Folders.FirstOrDefault(k => k.Value.Contains(ea)).Key;

    private void RemoveFromFolder(ulong ea)
    {
        var f = FindFolderOf(ea);
        if (f == null) return;
        _s!.Db.Folders[f].Remove(ea);
        _s.Db.Dirty = true;
        BuildTree();
        FoldersChanged?.Invoke();
    }

    private void NewFolder()
    {
        if (_s == null) return;
        var name = Dialogs.Input(Window.GetWindow(this), "Klasör oluştur", "Klasör adı:", "");
        if (string.IsNullOrWhiteSpace(name)) return;
        _s.Db.Folders.TryAdd(name.Trim(), new List<ulong>());
        _s.Db.Dirty = true;
        if (!FolderMode) ToggleFolders(); else BuildTree();
        FoldersChanged?.Invoke();
    }

    private void MoveToFolder(List<ulong> eas)
    {
        if (_s == null || eas.Count == 0) return;
        var names = _s.Db.Folders.Keys.OrderBy(k => k).ToList();
        var name = Dialogs.Input(Window.GetWindow(this), "Klasöre taşı",
            "Klasör adı (yoksa oluşturulur):", names.FirstOrDefault() ?? "", false, names);
        if (string.IsNullOrWhiteSpace(name)) return;
        name = name.Trim();
        foreach (var kv in _s.Db.Folders) kv.Value.RemoveAll(eas.Contains);
        if (!_s.Db.Folders.TryGetValue(name, out var l)) _s.Db.Folders[name] = l = new List<ulong>();
        l.AddRange(eas);
        _s.Db.Dirty = true;
        if (!FolderMode) ToggleFolders(); else BuildTree();
        FoldersChanged?.Invoke();
    }

    public static MenuItem Mi(string header, Action act)
    {
        var parts = header.Split('\t');
        var mi = new MenuItem { Header = Loc.T(parts[0]) };
        if (parts.Length > 1) mi.InputGestureText = parts[1];
        mi.Click += (_, _) => act();
        return mi;
    }

    public void SelectEa(ulong ea)
    {
        if (!FolderMode) List.SelectEa(ea);
    }
}

// Fonksiyon cagri agaci (cagiranlar / cagrilanlar)
public sealed class CallTreePane : DockPanel
{
    private readonly TreeView _tree;
    private readonly TextBlock _title;
    private Session? _s;
    private Function? _cur;
    public bool Follow = true;
    public event Action<ulong>? Activated;

    public CallTreePane()
    {
        _title = new TextBlock { Margin = new Thickness(6, 4, 6, 4), FontWeight = FontWeights.SemiBold, FontSize = 12 };
        _title.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        var chk = new CheckBox { Content = Loc.T("İmleci izle"), IsChecked = true, Margin = new Thickness(6, 4, 6, 4), FontSize = 11.5 };
        chk.SetResourceReference(Control.ForegroundProperty, "TextDimBrush");
        chk.Checked += (_, _) => Follow = true;
        chk.Unchecked += (_, _) => Follow = false;
        var top = new DockPanel();
        DockPanel.SetDock(chk, Dock.Right);
        top.Children.Add(chk);
        top.Children.Add(_title);
        SetDock(top, Dock.Top);
        Children.Add(top);
        _tree = new TreeView { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 12.5 };
        _tree.SetResourceReference(Control.BackgroundProperty, "PanelBrush");
        _tree.MouseDoubleClick += (_, e) =>
        {
            if (_tree.SelectedItem is TreeViewItem { Tag: ulong ea }) { Activated?.Invoke(ea); e.Handled = true; }
        };
        Children.Add(_tree);
    }

    public void SetSession(Session? s)
    {
        _s = s;
        _cur = null;
        _tree.Items.Clear();
        _title.Text = "";
    }

    public void Show(Function? f, bool force = false)
    {
        if (_s == null || f == null || (!Follow && !force) || f == _cur) return;
        _cur = f;
        _tree.Items.Clear();
        _title.Text = _s.Db.FuncName(f);
        var root = Item(_s.Db.FuncName(f), f.Start, "", Theme.P.NavFunc, false);
        var callers = Callers(f);
        var callees = Callees(f);
        var up = Item(Loc.F("Çağıranlar ({0})", callers.Count), null, "", Theme.P.EdgeTrue, false);
        foreach (var c in callers) up.Items.Add(FuncItem(c.ea, c.name, c.isImport, true));
        var down = Item(Loc.F("Çağrılanlar ({0})", callees.Count), null, "", Theme.P.EdgeFalse, false);
        foreach (var c in callees) down.Items.Add(FuncItem(c.ea, c.name, c.isImport, false));
        root.Items.Add(up);
        root.Items.Add(down);
        up.IsExpanded = down.IsExpanded = root.IsExpanded = true;
        _tree.Items.Add(root);
    }

    private TreeViewItem FuncItem(ulong ea, string name, bool isImport, bool upward)
    {
        var it = Item(name, ea, isImport ? "" : "", isImport ? Theme.P.NavExt : Theme.P.NavFunc, false);
        if (!isImport && _s!.Db.Funcs.ContainsKey(ea))
        {
            it.Items.Add(new TreeViewItem { Header = "..." });
            it.Expanded += (_, e) =>
            {
                if (e.OriginalSource != it) return;
                if (it.Items.Count == 1 && it.Items[0] is TreeViewItem { Tag: null, Header: "..." })
                {
                    it.Items.Clear();
                    var f = _s.Db.Funcs[ea];
                    var list = upward ? Callers(f) : Callees(f);
                    foreach (var c in list.Take(500)) it.Items.Add(FuncItem(c.ea, c.name, c.isImport, upward));
                    if (list.Count == 0) it.Items.Add(new TreeViewItem { Header = "(yok)", IsEnabled = false });
                }
            };
        }
        return it;
    }

    private static TreeViewItem Item(string text, ulong? ea, string icon, Color c, bool expanded)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        sp.Children.Add(new TextBlock
        {
            Text = icon,
            FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
            Foreground = Theme.B(c),
            Margin = new Thickness(0, 1, 6, 0),
            VerticalAlignment = VerticalAlignment.Center,
        });
        var tb = new TextBlock { Text = text };
        tb.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        sp.Children.Add(tb);
        return new TreeViewItem { Header = sp, Tag = ea, IsExpanded = expanded };
    }

    private List<(ulong ea, string name, bool isImport)> Callers(Function f)
    {
        var db = _s!.Db;
        var res = new Dictionary<ulong, (ulong, string, bool)>();
        foreach (var x in db.XrefsTo(f.Start))
        {
            var cf = db.FuncAt(x.From);
            if (cf == null) continue;
            res.TryAdd(cf.Start, (cf.Start, db.FuncName(cf) + (x.Type == XrefType.Offset ? "  (ofs)" : ""), false));
        }
        return res.Values.OrderBy(v => v.Item2).ToList();
    }

    private List<(ulong ea, string name, bool isImport)> Callees(Function f)
    {
        var db = _s!.Db;
        var res = new Dictionary<ulong, (ulong, string, bool)>();
        foreach (var ins in f.Instrs)
            foreach (var x in db.XrefsFrom(ins))
            {
                if (x.Type is not (XrefType.Call or XrefType.Jump)) continue;
                if (db.ImportAt.ContainsKey(x.To)) res.TryAdd(x.To, (x.To, db.NameAt(x.To) ?? "?", true));
                else if (db.Funcs.TryGetValue(x.To, out var cf) && cf != f) res.TryAdd(cf.Start, (cf.Start, db.FuncName(cf), false));
            }
        return res.Values.OrderBy(v => v.Item2).ToList();
    }
}

// Output penceresi: kayit + IDC/AI komut satiri
public sealed class OutputPane : DockPanel
{
    private readonly TextBox _log;
    private readonly TextBox _input;
    private readonly ComboBox _mode;
    private readonly List<string> _hist = new();
    private int _hi;

    public event Action<string, string>? Command;

    public OutputPane()
    {
        var bar = new Grid();
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        _mode = new ComboBox { Width = 64, Margin = new Thickness(2), FontSize = 12 };
        _mode.Items.Add("IDC");
        _mode.Items.Add("AI");
        _mode.SelectedIndex = 0;
        _input = new TextBox { Margin = new Thickness(2), FontFamily = new FontFamily("Consolas"), FontSize = 12.5, Padding = new Thickness(3, 1, 3, 1) };
        Grid.SetColumn(_input, 1);
        bar.Children.Add(_mode);
        bar.Children.Add(_input);
        _input.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter && _input.Text.Trim().Length > 0)
            {
                string t = _input.Text.Trim();
                _hist.Add(t);
                _hi = _hist.Count;
                _input.Text = "";
                Command?.Invoke(_mode.SelectedItem?.ToString() ?? "IDC", t);
                e.Handled = true;
            }
            else if (e.Key == Key.Up && _hist.Count > 0)
            {
                _hi = Math.Max(0, _hi - 1);
                _input.Text = _hist[_hi];
                _input.CaretIndex = _input.Text.Length;
            }
            else if (e.Key == Key.Down && _hist.Count > 0)
            {
                _hi = Math.Min(_hist.Count, _hi + 1);
                _input.Text = _hi < _hist.Count ? _hist[_hi] : "";
            }
        };
        SetDock(bar, Dock.Bottom);
        Children.Add(bar);
        _log = new TextBox
        {
            IsReadOnly = true,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            TextWrapping = TextWrapping.NoWrap,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(4, 2, 4, 2),
        };
        _log.SetResourceReference(TextBox.BackgroundProperty, "ViewBgBrush");
        _log.SetResourceReference(TextBox.ForegroundProperty, "TextBrush");
        Children.Add(_log);
    }

    public string Mode
    {
        get => _mode.SelectedItem?.ToString() ?? "IDC";
        set => _mode.SelectedItem = value;
    }

    public void Log(string s)
    {
        if (_log.Text.Length > 400_000) _log.Text = _log.Text[^200_000..];
        _log.AppendText(Loc.T(s) + Environment.NewLine);
        _log.ScrollToEnd();
    }

    public void Clear() => _log.Clear();
    public void FocusInput() => _input.Focus();
}
