using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

// Cizim yuzeyi: tum cizimi sahibine devreder
public sealed class Surface : FrameworkElement
{
    private readonly Action<DrawingContext> _render;
    public Surface(Action<DrawingContext> render)
    {
        _render = render;
        ClipToBounds = true;
        Focusable = false;
    }
    protected override void OnRender(DrawingContext dc) => _render(dc);
}

// Sanal (milyonlarca satir) metin gorunumu: IDA View, Hex View, Pseudocode bunun ustune kurulu
public abstract class LineView : Grid
{
    protected readonly Surface Surf;
    private readonly ScrollBar _vbar, _hbar;
    private readonly Dictionary<long, Line> _cache = new();
    private bool _syncing, _dragging;
    private double _dpi = 1;

    public long Top { get; private set; }
    public long Cursor { get; private set; }
    public int CursorCol { get; protected set; }
    public long SelAnchor { get; set; } = -1;
    public string? HighlightWord { get; set; }
    public double CharW { get; private set; } = 7;
    public double LineH { get; private set; } = 15;
    protected Typeface Tf = new("Consolas");
    protected double Fs = 13;
    protected double Gutter;
    protected int HOff;

    public event Action? CursorMoved;
    public event Action? LineActivated;
    public event Action<Point>? MenuRequested;
    public event Action<string, Point>? WordHover;   // fare bir kelimede bekledi
    public event Action? HoverEnd;

    private readonly System.Windows.Threading.DispatcherTimer _hoverTimer = new() { Interval = TimeSpan.FromMilliseconds(450) };
    private string? _hoverWord;
    private Point _hoverPt;

    protected abstract long LineCount { get; }
    protected abstract Line BuildLine(long i);

    protected LineView()
    {
        ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        Surf = new Surface(Render);
        _vbar = new ScrollBar { Orientation = Orientation.Vertical, SmallChange = 1 };
        _hbar = new ScrollBar { Orientation = Orientation.Horizontal, SmallChange = 1 };
        SetColumn(_vbar, 1);
        SetRow(_hbar, 1);
        Children.Add(Surf);
        Children.Add(_vbar);
        Children.Add(_hbar);

        _vbar.ValueChanged += (_, e) =>
        {
            if (_syncing) return;
            Top = (long)Math.Round(e.NewValue);
            Surf.InvalidateVisual();
        };
        _hbar.ValueChanged += (_, e) =>
        {
            if (_syncing) return;
            HOff = (int)Math.Round(e.NewValue);
            Surf.InvalidateVisual();
        };

        Focusable = true;
        FocusVisualStyle = null;
        ClipToBounds = true;
        Background = Brushes.Transparent;
        Surf.SizeChanged += (_, _) => UpdateBars();
        Surf.MouseDown += SurfMouseDown;
        Surf.MouseMove += SurfMouseMove;
        Surf.MouseUp += (_, _) => { _dragging = false; Surf.ReleaseMouseCapture(); };
        Surf.MouseLeave += (_, _) => EndHover();
        _hoverTimer.Tick += (_, _) =>
        {
            _hoverTimer.Stop();
            if (_hoverWord != null && IsMouseOver) WordHover?.Invoke(_hoverWord, _hoverPt);
        };
        GotKeyboardFocus += (_, _) => Surf.InvalidateVisual();
        LostKeyboardFocus += (_, _) => Surf.InvalidateVisual();
        Theme.Changed += () => { ClearCache(); Surf.InvalidateVisual(); };
        Loaded += (_, _) =>
        {
            try { _dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip; } catch { }
            UpdateBars();
        };
        SetFont("Consolas", 13);
    }

    public void SetFont(string family, double size)
    {
        Tf = new Typeface(new FontFamily(family + ", Consolas, Courier New"), FontStyles.Normal, FontWeights.Normal,
            FontStretches.Normal);
        Fs = size;
        var ft = new FormattedText("MMMMMMMMMM", CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Tf, Fs,
            Brushes.Black, _dpi);
        CharW = ft.WidthIncludingTrailingWhitespace / 10;
        LineH = Math.Ceiling(ft.Height + 1);
        Refresh();
    }

    public int VisibleLines => Math.Max(1, (int)(Surf.ActualHeight / LineH));

    public void ClearCache() => _cache.Clear();

    public void Refresh()
    {
        ClearCache();
        long n = LineCount;
        if (Cursor >= n) Cursor = Math.Max(0, n - 1);
        if (Top >= n) Top = Math.Max(0, n - 1);
        UpdateBars();
        Surf.InvalidateVisual();
    }

    public void Redraw() => Surf.InvalidateVisual();

    protected Line GetLine(long i)
    {
        if (_cache.TryGetValue(i, out var l)) return l;
        if (_cache.Count > 6000) _cache.Clear();
        l = BuildLine(i);
        _cache[i] = l;
        return l;
    }

    public Line LineAt(long i) => GetLine(i);

    private void UpdateBars()
    {
        _syncing = true;
        long n = LineCount;
        _vbar.Maximum = Math.Max(0, n - 1);
        _vbar.ViewportSize = VisibleLines;
        _vbar.LargeChange = Math.Max(1, VisibleLines - 1);
        _vbar.Value = Top;
        double cols = Math.Max(1, (Surf.ActualWidth - Gutter) / CharW);
        _hbar.Maximum = Math.Max(0, 300 - cols);
        _hbar.ViewportSize = cols;
        _hbar.LargeChange = Math.Max(1, cols / 2);
        _hbar.Value = HOff;
        _syncing = false;
    }

    public void ScrollTo(long top)
    {
        Top = Math.Clamp(top, 0, Math.Max(0, LineCount - 1));
        UpdateBars();
        Surf.InvalidateVisual();
    }

    public void EnsureVisible(long line)
    {
        int vis = VisibleLines;
        if (line < Top) ScrollTo(line);
        else if (line >= Top + vis) ScrollTo(line - vis + 1);
    }

    // IDA gibi: hedef gorunmuyorsa ust ceyrege getir
    public void Reveal(long line)
    {
        int vis = VisibleLines;
        if (line < Top || line >= Top + vis) ScrollTo(line - vis / 4);
    }

    public void SetCursor(long line, int col = -1, bool extend = false, bool reveal = false)
    {
        long n = LineCount;
        if (n == 0) return;
        line = Math.Clamp(line, 0, n - 1);
        if (extend) { if (SelAnchor < 0) SelAnchor = Cursor; }
        else SelAnchor = -1;
        Cursor = line;
        if (col >= 0) CursorCol = col;
        if (reveal) Reveal(line); else EnsureVisible(line);
        Surf.InvalidateVisual();
        CursorMoved?.Invoke();
    }

    public (long A, long B)? Selection =>
        SelAnchor < 0 || SelAnchor == Cursor ? null : (Math.Min(SelAnchor, Cursor), Math.Max(SelAnchor, Cursor));

    // ================= Cizim =================

    private void Render(DrawingContext dc)
    {
        var p = Theme.P;
        double w = Surf.ActualWidth, h = Surf.ActualHeight;
        Theme.DrawBackground(dc, new Rect(0, 0, w, h), p.Bg);
        long n = LineCount;
        int vis = VisibleLines + 1;
        var sel = Selection;
        double x0 = Gutter - HOff * CharW;
        var hl = Theme.B(p.Highlight);
        dc.PushClip(new RectangleGeometry(new Rect(Gutter, 0, Math.Max(0, w - Gutter), h)));

        for (int r = 0; r < vis; r++)
        {
            long li = Top + r;
            if (li >= n) break;
            double y = r * LineH;
            var line = GetLine(li);
            if (li == Cursor) dc.DrawRectangle(Theme.B(p.CurLine), null, new Rect(Gutter, y, w, LineH));
            if (sel is var (a, b) && li >= a && li <= b)
                dc.DrawRectangle(Theme.B(p.Selection), null, new Rect(Gutter, y, w, LineH));
            DrawLineBackground(dc, line, li, y, x0);

            if (HighlightWord is { Length: > 0 } hw)
            {
                string plain = line.Plain;
                int idx = 0;
                while ((idx = plain.IndexOf(hw, idx, StringComparison.Ordinal)) >= 0)
                {
                    bool lb = idx == 0 || !IsW(plain[idx - 1]);
                    bool rb = idx + hw.Length >= plain.Length || !IsW(plain[idx + hw.Length]);
                    if (lb && rb) dc.DrawRectangle(hl, null, new Rect(x0 + idx * CharW, y, hw.Length * CharW, LineH));
                    idx += hw.Length;
                }
            }

            double x = x0;
            foreach (var t in line.Toks)
            {
                int len = t.Text.Length;
                if (len == 0) continue;
                double tw = len * CharW;
                if (x + tw > Gutter - CharW && x < w && !string.IsNullOrWhiteSpace(t.Text))
                    DrawText(dc, t.Text, Theme.Tok(t.Kind), x, y);
                x += tw;
            }

            if (li == Cursor && IsKeyboardFocusWithin)
                dc.DrawRectangle(Theme.B(p.Caret), null, new Rect(x0 + CursorCol * CharW, y + 1, 1.5, LineH - 2));
        }

        dc.Pop();
        if (Gutter > 0) DrawGutter(dc, Top, vis);
        DrawOverlay(dc, w, h);
    }

    protected void DrawText(DrawingContext dc, string text, Brush brush, double x, double y)
    {
        var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Tf, Fs, brush, _dpi);
        dc.DrawText(ft, new Point(x, y));
    }

    protected virtual void DrawLineBackground(DrawingContext dc, Line line, long li, double y, double x0) { }
    protected virtual void DrawGutter(DrawingContext dc, long top, int vis) { }
    protected virtual void DrawOverlay(DrawingContext dc, double w, double h) { }

    // ================= Girdi =================

    protected (long Line, int Col) HitTest(Point pt) =>
        (Top + (long)(pt.Y / LineH), Math.Max(0, (int)((pt.X - Gutter) / CharW + HOff)));

    private void SurfMouseDown(object sender, MouseButtonEventArgs e)
    {
        Focus();
        var pt = e.GetPosition(Surf);
        var (l, c) = HitTest(pt);
        if (l >= LineCount) l = LineCount - 1;
        if (e.ChangedButton == MouseButton.Left)
        {
            if (e.ClickCount == 2)
            {
                SetCursor(l, c);
                HighlightWord = WordAt(l, c) ?? HighlightWord;
                LineActivated?.Invoke();
                e.Handled = true;
                return;
            }
            bool shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);
            HighlightWord = WordAt(Math.Clamp(l, 0, Math.Max(0, LineCount - 1)), c);
            SetCursor(l, c, shift);
            OnClicked(l, c);
            _dragging = true;
            Surf.CaptureMouse();
            Surf.InvalidateVisual();
        }
        else if (e.ChangedButton == MouseButton.Right)
        {
            var sel = Selection;
            if (sel == null || l < sel.Value.A || l > sel.Value.B) SetCursor(l, c);
            HighlightWord = WordAt(l, c) ?? HighlightWord;
            Surf.InvalidateVisual();
            MenuRequested?.Invoke(e.GetPosition(this));
            e.Handled = true;
        }
    }

    protected virtual void OnClicked(long line, int col) { }

    private void EndHover()
    {
        _hoverTimer.Stop();
        if (_hoverWord != null) { _hoverWord = null; HoverEnd?.Invoke(); }
    }

    private void SurfMouseMove(object sender, MouseEventArgs e)
    {
        if (!_dragging || e.LeftButton != MouseButtonState.Pressed)
        {
            var pt = e.GetPosition(Surf);
            var (hl, hc) = HitTest(pt);
            string? w = hl < LineCount ? WordAt(hl, hc) : null;
            if (w != _hoverWord)
            {
                if (_hoverWord != null) HoverEnd?.Invoke();
                _hoverWord = w;
                _hoverTimer.Stop();
                if (w != null) { _hoverPt = e.GetPosition(this); _hoverTimer.Start(); }
            }
            return;
        }
        EndHover();
        var (l, c) = HitTest(e.GetPosition(Surf));
        l = Math.Clamp(l, 0, Math.Max(0, LineCount - 1));
        if (l == Cursor) return;
        if (SelAnchor < 0) SelAnchor = Cursor;
        Cursor = l;
        CursorCol = c;
        EnsureVisible(l);
        Surf.InvalidateVisual();
    }

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            SetFont(Tf.FontFamily.Source.Split(',')[0], Math.Clamp(Fs + (e.Delta > 0 ? 1 : -1), 8, 30));
        }
        else ScrollTo(Top - e.Delta / 120 * 3);
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        bool shift = Keyboard.Modifiers.HasFlag(ModifierKeys.Shift);
        bool ctrl = Keyboard.Modifiers.HasFlag(ModifierKeys.Control);
        int vis = VisibleLines;
        switch (e.Key)
        {
            case Key.Up: SetCursor(Cursor - 1, -1, shift); break;
            case Key.Down: SetCursor(Cursor + 1, -1, shift); break;
            case Key.PageUp:
                ScrollTo(Top - vis);
                SetCursor(Cursor - vis, -1, shift);
                break;
            case Key.PageDown:
                ScrollTo(Top + vis);
                SetCursor(Cursor + vis, -1, shift);
                break;
            case Key.Home:
                if (ctrl) SetCursor(0, 0, shift); else { CursorCol = 0; Surf.InvalidateVisual(); }
                break;
            case Key.End:
                if (ctrl) SetCursor(LineCount - 1, 0, shift);
                else { CursorCol = GetLine(Cursor).Plain.Length; Surf.InvalidateVisual(); }
                break;
            case Key.Left:
                CursorCol = Math.Max(0, CursorCol - 1);
                if (CursorCol < HOff) { HOff = CursorCol; UpdateBars(); }
                Surf.InvalidateVisual();
                break;
            case Key.Right:
                CursorCol++;
                Surf.InvalidateVisual();
                break;
            default:
                base.OnKeyDown(e);
                return;
        }
        e.Handled = true;
    }

    public static bool IsW(char c) => char.IsLetterOrDigit(c) || c is '_' or '$' or '@' or '?' or '.';

    public string? WordAt(long line, int col)
    {
        if (line < 0 || line >= LineCount) return null;
        string p = GetLine(line).Plain;
        if (col >= p.Length || col < 0 || !IsW(p[col])) return null;
        int a = col, b = col;
        while (a > 0 && IsW(p[a - 1])) a--;
        while (b < p.Length && IsW(p[b])) b++;
        string w = p[a..b].Trim('.');
        return w.Length > 0 ? w : null;
    }

    public string? WordAtCursor() => WordAt(Cursor, CursorCol) ?? HighlightWord;

    public string SelectedText()
    {
        var sel = Selection ?? (Cursor, Cursor);
        var sb = new System.Text.StringBuilder();
        for (long l = sel.A; l <= sel.B && l - sel.A < 200000; l++) sb.AppendLine(GetLine(l).Plain.TrimEnd());
        return sb.ToString();
    }
}
