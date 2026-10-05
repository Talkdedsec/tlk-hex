using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using tlk_hex.Core;

namespace tlk_hex.UI;

// Arama paneli: yazdikca arar, sonuca tiklayinca gider
public sealed class SearchPane : DockPanel
{
    private readonly TextBox _box;
    private readonly TextBlock _ph;
    private readonly ComboBox _scope;
    private readonly CheckBox _case, _regex;
    private readonly TextBlock _status;
    public readonly ListPane Results;
    private readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(350) };

    private static readonly (string Id, string Label)[] Scopes =
    {
        ("all", "Tümü"), ("names", "İsimler"), ("strings", "Metinler (string)"), ("code", "Kod satırları"),
        ("comments", "Yorumlar"), ("bytes", "Bayt dizisi / ham metin"), ("imm", "Sabit değer"),
    };

    public event Action<SearchQuery>? SearchRequested;
    public event Action<Row>? Activated;
    public event Action<Row>? Previewed;

    public SearchPane()
    {
        var bar = new Grid { Margin = new Thickness(4) };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (int i = 0; i < 4; i++) bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var boxHost = new Grid();
        _box = new TextBox { FontFamily = new FontFamily("Consolas"), FontSize = 13, Padding = new Thickness(4, 2, 4, 2), VerticalContentAlignment = VerticalAlignment.Center };
        _ph = new TextBlock
        {
            Text = "Ara: isim, metin, komut, adres, bayt (48 8B ?? 05) ...",
            IsHitTestVisible = false,
            Margin = new Thickness(7, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
        };
        _ph.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        boxHost.Children.Add(_box);
        boxHost.Children.Add(_ph);
        bar.Children.Add(boxHost);

        _scope = new ComboBox { Width = 175, Margin = new Thickness(6, 0, 0, 0) };
        foreach (var s in Scopes) _scope.Items.Add(s.Label);
        _scope.SelectedIndex = 0;
        Grid.SetColumn(_scope, 1);
        bar.Children.Add(_scope);

        _case = new CheckBox { Content = "Aa", ToolTip = "Büyük/küçük harf duyarlı", Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(_case, 2);
        bar.Children.Add(_case);
        _regex = new CheckBox { Content = ".*", ToolTip = "Düzenli ifade (regex)", Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        Grid.SetColumn(_regex, 3);
        bar.Children.Add(_regex);
        var go = new Button { Content = "Ara", Padding = new Thickness(14, 2, 14, 2), Margin = new Thickness(10, 0, 0, 0) };
        Grid.SetColumn(go, 4);
        bar.Children.Add(go);
        SetDock(bar, Dock.Top);
        Children.Add(bar);

        _status = new TextBlock { Margin = new Thickness(8, 0, 8, 3), FontSize = 11.5 };
        _status.SetResourceReference(TextBlock.ForegroundProperty, "TextDimBrush");
        SetDock(_status, Dock.Top);
        Children.Add(_status);

        Results = new ListPane(new[] { ("Tür", 70.0), ("Adres", 190.0), ("Fonksiyon", 200.0), ("Eşleşme", -1.0) });
        Results.Activated += r => Activated?.Invoke(r);
        Results.Grid.SelectionChanged += (_, _) =>
        {
            if (Results.Grid.IsKeyboardFocusWithin && Results.Selected is Row r) Previewed?.Invoke(r);
        };
        Children.Add(Results);

        _box.TextChanged += (_, _) =>
        {
            _ph.Visibility = _box.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            _debounce.Stop();
            _debounce.Start();
        };
        _debounce.Tick += (_, _) => { _debounce.Stop(); Fire(); };
        _box.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) { _debounce.Stop(); Fire(); e.Handled = true; }
            else if (e.Key == Key.Down) { Results.Grid.Focus(); if (Results.Grid.Items.Count > 0) Results.Grid.SelectedIndex = 0; e.Handled = true; }
        };
        go.Click += (_, _) => Fire();
        _scope.SelectionChanged += (_, _) => Fire();
        _case.Checked += (_, _) => Fire();
        _case.Unchecked += (_, _) => Fire();
        _regex.Checked += (_, _) => Fire();
        _regex.Unchecked += (_, _) => Fire();
    }

    private void Fire()
    {
        if (_box.Text.Trim().Length == 0) { Results.SetRows(new List<Row>()); _status.Text = ""; return; }
        SearchRequested?.Invoke(new SearchQuery
        {
            Text = _box.Text.Trim(),
            Scope = Scopes[Math.Max(0, _scope.SelectedIndex)].Id,
            MatchCase = _case.IsChecked == true,
            Regex = _regex.IsChecked == true,
        });
    }

    public void Start(string text, string scope = "all")
    {
        int i = Array.FindIndex(Scopes, s => s.Id == scope);
        _scope.SelectedIndex = Math.Max(0, i);
        _box.Text = text;
        _debounce.Stop();
        Fire();
        FocusBox();
    }

    public void FocusBox()
    {
        _box.Focus();
        _box.CaretIndex = _box.Text.Length;
    }

    public void SetStatus(string s) => _status.Text = s;
}
