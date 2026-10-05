using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;

namespace tlk_hex.UI;

// Arac cubugundaki "Git / Ara" kutusu: isim, adres veya metin; yazdikca oneri listesi
public sealed class GoBox : Grid
{
    public sealed record Item(string Name, ulong Ea, string Kind, string Addr);

    private readonly TextBox _tb;
    private readonly TextBlock _ph;
    private readonly Popup _pop;
    private readonly ListBox _list;
    private List<Item> _all = new();
    private bool _suppress;

    public event Action<Item>? Picked;          // listeden secildi
    public event Action<string, Item?>? Submitted;   // Enter: metin + listede secili oge

    public GoBox()
    {
        Width = 300;
        Height = 24;
        Margin = new Thickness(6, 0, 6, 0);
        var border = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(3) };
        border.SetResourceReference(Border.BorderBrushProperty, "BorderBrush");
        border.SetResourceReference(Border.BackgroundProperty, "PanelBrush");
        var inner = new Grid();
        inner.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        inner.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var icon = new TextBlock
        {
            Text = "",
            FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"),
            Margin = new Thickness(7, 0, 4, 0),
            VerticalAlignment = VerticalAlignment.Center,
            FontSize = 12,
        };
        icon.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        _tb = new TextBox
        {
            BorderThickness = new Thickness(0),
            Background = Brushes.Transparent,
            VerticalContentAlignment = VerticalAlignment.Center,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12.5,
        };
        _ph = new TextBlock
        {
            Text = "Git / ara: isim, adres veya metin  (Ctrl+F)",
            IsHitTestVisible = false,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(3, 0, 0, 0),
            FontSize = 12,
        };
        _ph.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        Grid.SetColumn(_tb, 1);
        Grid.SetColumn(_ph, 1);
        inner.Children.Add(icon);
        inner.Children.Add(_tb);
        inner.Children.Add(_ph);
        border.Child = inner;
        Children.Add(border);

        _list = new ListBox { MaxHeight = 380, MinWidth = 420, BorderThickness = new Thickness(1), FontFamily = new FontFamily("Consolas"), FontSize = 12.5 };
        _list.ItemTemplate = BuildTemplate();
        _list.PreviewMouseLeftButtonUp += (_, e) =>
        {
            if (_list.SelectedItem is Item it) Pick(it);
        };
        _pop = new Popup
        {
            PlacementTarget = this,
            Placement = PlacementMode.Bottom,
            StaysOpen = false,
            AllowsTransparency = true,
            Child = _list,
        };

        _tb.TextChanged += (_, _) =>
        {
            _ph.Visibility = _tb.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (!_suppress) Suggest();
        };
        _tb.PreviewKeyDown += OnKey;
        _tb.GotKeyboardFocus += (_, _) => _tb.SelectAll();
        _tb.LostKeyboardFocus += (_, _) =>
        {
            if (!_list.IsKeyboardFocusWithin && !_list.IsMouseOver) _pop.IsOpen = false;
        };
    }

    private static DataTemplate BuildTemplate()
    {
        var t = new DataTemplate(typeof(Item));
        var g = new FrameworkElementFactory(typeof(Grid));
        var c0 = new FrameworkElementFactory(typeof(ColumnDefinition));
        c0.SetValue(ColumnDefinition.WidthProperty, new GridLength(62));
        var c1 = new FrameworkElementFactory(typeof(ColumnDefinition));
        c1.SetValue(ColumnDefinition.WidthProperty, new GridLength(1, GridUnitType.Star));
        var c2 = new FrameworkElementFactory(typeof(ColumnDefinition));
        c2.SetValue(ColumnDefinition.WidthProperty, GridLength.Auto);
        g.AppendChild(c0);
        g.AppendChild(c1);
        g.AppendChild(c2);
        var k = new FrameworkElementFactory(typeof(TextBlock));
        k.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Kind"));
        k.SetResourceReference(TextBlock.ForegroundProperty, "AccentBrush");
        var n = new FrameworkElementFactory(typeof(TextBlock));
        n.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Name"));
        n.SetValue(Grid.ColumnProperty, 1);
        n.SetValue(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis);
        n.SetResourceReference(TextBlock.ForegroundProperty, "TextBrush");
        var a = new FrameworkElementFactory(typeof(TextBlock));
        a.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Addr"));
        a.SetValue(Grid.ColumnProperty, 2);
        a.SetValue(TextBlock.MarginProperty, new Thickness(14, 0, 0, 0));
        a.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        g.AppendChild(k);
        g.AppendChild(n);
        g.AppendChild(a);
        t.VisualTree = g;
        return t;
    }

    public void SetItems(List<Item> items) => _all = items;

    public void FocusBox()
    {
        _tb.Focus();
        _tb.SelectAll();
    }

    public string Text => _tb.Text;
    public void SetText(string t) => _tb.Text = t;     // test
    public FrameworkElement SuggestionList => _list;

    private void Suggest()
    {
        string q = _tb.Text.Trim();
        if (q.Length == 0 || _all.Count == 0) { _pop.IsOpen = false; return; }
        var starts = new List<Item>();
        var contains = new List<Item>();
        foreach (var it in _all)
        {
            if (it.Name.StartsWith(q, StringComparison.OrdinalIgnoreCase)) { if (starts.Count < 40) starts.Add(it); }
            else if (contains.Count < 40 && it.Name.Contains(q, StringComparison.OrdinalIgnoreCase)) contains.Add(it);
            if (starts.Count >= 40) break;
        }
        var res = starts.Concat(contains).Take(40).ToList();
        _list.ItemsSource = res;
        if (res.Count == 0) { _pop.IsOpen = false; return; }
        _list.SelectedIndex = 0;
        _pop.IsOpen = true;
    }

    private void Pick(Item it)
    {
        _pop.IsOpen = false;
        _suppress = true;
        _tb.Text = it.Name;
        _suppress = false;
        Picked?.Invoke(it);
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Down when _pop.IsOpen:
                _list.SelectedIndex = Math.Min(_list.Items.Count - 1, _list.SelectedIndex + 1);
                _list.ScrollIntoView(_list.SelectedItem);
                e.Handled = true;
                break;
            case Key.Up when _pop.IsOpen:
                _list.SelectedIndex = Math.Max(0, _list.SelectedIndex - 1);
                _list.ScrollIntoView(_list.SelectedItem);
                e.Handled = true;
                break;
            case Key.Enter:
                e.Handled = true;
                string q = _tb.Text.Trim();
                if (q.Length == 0) return;
                // tam isim eslesmesi once
                var exact = _all.FirstOrDefault(i => i.Name.Equals(q, StringComparison.Ordinal));
                if (exact != null) { Pick(exact); return; }
                var hl = _pop.IsOpen ? _list.SelectedItem as Item : null;
                _pop.IsOpen = false;
                Submitted?.Invoke(q, hl);
                break;
            case Key.Tab when _pop.IsOpen && _list.SelectedItem is Item sel:
                Pick(sel);
                e.Handled = true;
                break;
            case Key.Escape:
                _pop.IsOpen = false;
                _tb.Text = "";
                e.Handled = true;
                Keyboard.ClearFocus();
                break;
        }
    }

    // Enter ile acik listede secili oge varsa onu sec
    public Item? Highlighted => _pop.IsOpen ? _list.SelectedItem as Item : null;
}
