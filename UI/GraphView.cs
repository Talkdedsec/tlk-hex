using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

// IDA graph gorunumu: temel bloklar, katmanli yerlesim (Sugiyama benzeri), renkli kenarlar
public sealed class GraphView : FrameworkElement
{
    private sealed class Node
    {
        public int Id;
        public BBlock? B;
        public List<Line> Lines = new();
        public double W, H, X, Y;
        public int Layer;
        public double Pos;
        public bool Dummy;
        public List<int> Up = new(), Down = new();
    }

    private sealed class GEdge
    {
        public int From, To;
        public EdgeKind Kind;
        public bool Back;
        public List<int> Chain = new();
        public List<Point> Pts = new();
    }

    private Session? _s;
    private Function? _f;
    private bool _dirty = true;
    private readonly List<Node> _nodes = new();
    private readonly List<GEdge> _edges = new();
    private double _scale = 1;
    private Vector _off;
    private Rect _bounds;
    private Point _panStart;
    private Vector _panOff;
    private bool _panning;
    private double _dpi = 1;
    private Typeface _tf = new("Consolas");
    private double _fs = 13;
    private double _cw = 7, _lh = 15;
    private const double Pad = 6, GapX = 40, GapY = 60;

    public ulong CursorEa { get; private set; }
    public string? HighlightWord { get; set; }
    public Function? Func => _f;
    public double Zoom => _scale;
    public Rect Bounds => _bounds;

    public event Action? CursorMoved;
    public event Action? LineActivated;
    public event Action<Point>? MenuRequested;
    public event Action? ViewChanged;
    public event Action<string, Point>? WordHover;
    public event Action? HoverEnd;
    private readonly System.Windows.Threading.DispatcherTimer _hoverTimer = new() { Interval = TimeSpan.FromMilliseconds(450) };
    private string? _hoverWord;
    private Point _hoverPt;

    public GraphView()
    {
        Focusable = true;
        FocusVisualStyle = null;
        ClipToBounds = true;
        Theme.Changed += InvalidateVisual;
        Loaded += (_, _) =>
        {
            try { _dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip; } catch { }
        };
        _hoverTimer.Tick += (_, _) =>
        {
            _hoverTimer.Stop();
            if (_hoverWord != null && IsMouseOver) WordHover?.Invoke(_hoverWord, _hoverPt);
        };
        MouseLeave += (_, _) =>
        {
            _hoverTimer.Stop();
            if (_hoverWord != null) { _hoverWord = null; HoverEnd?.Invoke(); }
        };
        SetFont("Consolas", 13);
    }

    public void SetFont(string family, double size)
    {
        _tf = new Typeface(new FontFamily(family + ", Consolas, Courier New"), FontStyles.Normal, FontWeights.Normal,
            FontStretches.Normal);
        _fs = size;
        var ft = new FormattedText("MMMMMMMMMM", CultureInfo.InvariantCulture, FlowDirection.LeftToRight, _tf, _fs,
            Brushes.Black, _dpi);
        _cw = ft.WidthIncludingTrailingWhitespace / 10;
        _lh = Math.Ceiling(ft.Height + 1);
        _dirty = true;
    }

    public void MarkDirty() => _dirty = true;

    public bool Show(Session s, Function f, ulong ea)
    {
        bool rebuilt = false;
        if (_dirty || _s != s || _f != f)
        {
            _s = s;
            _f = f;
            Build();
            _dirty = false;
            rebuilt = true;
            _scale = 1;
        }
        SelectEa(ea, rebuilt);
        return true;
    }

    // ================= Yerlesim =================

    private void Build()
    {
        _nodes.Clear();
        _edges.Clear();
        if (_s == null || _f == null) return;
        var bbs = FlowGraph.Build(_s.Db, _s.Dis, _f);
        foreach (var b in bbs)
        {
            var n = new Node { Id = _nodes.Count, B = b };
            foreach (var ea in b.Insns) n.Lines.AddRange(_s.List.ItemLinesForGraph(ea));
            int maxc = 8;
            foreach (var l in n.Lines) maxc = Math.Max(maxc, l.Plain.Length);
            n.W = Math.Min(maxc, 140) * _cw + 2 * Pad;
            n.H = n.Lines.Count * _lh + 2 * Pad;
            _nodes.Add(n);
        }
        int real = _nodes.Count;
        if (real == 0) return;
        foreach (var b in bbs)
            foreach (var (to, k) in b.Succ)
                _edges.Add(new GEdge { From = b.Index, To = to, Kind = k });

        // geri kenarlar (DFS)
        var state = new int[real];
        var order = new List<int>();
        var outE = new List<GEdge>[real];
        for (int i = 0; i < real; i++) outE[i] = new List<GEdge>();
        foreach (var e in _edges) outE[e.From].Add(e);
        for (int root = 0; root < real; root++)
        {
            if (state[root] != 0) continue;
            var st = new Stack<(int v, int i)>();
            st.Push((root, 0));
            state[root] = 1;
            while (st.Count > 0)
            {
                var (v, i) = st.Pop();
                if (i < outE[v].Count)
                {
                    st.Push((v, i + 1));
                    var e = outE[v][i];
                    if (state[e.To] == 1) e.Back = true;
                    else if (state[e.To] == 0)
                    {
                        state[e.To] = 1;
                        st.Push((e.To, 0));
                    }
                }
                else
                {
                    state[v] = 2;
                    order.Add(v);
                }
            }
        }
        order.Reverse(); // topolojik

        // katmanlar: en uzun yol
        var layer = new int[real];
        foreach (var v in order)
            foreach (var e in outE[v])
                if (!e.Back && e.To != v) layer[e.To] = Math.Max(layer[e.To], layer[v] + 1);
        for (int i = 0; i < real; i++) _nodes[i].Layer = layer[i];

        // uzun kenarlar icin sahte dugumler
        foreach (var e in _edges)
        {
            if (e.Back) continue;
            int lf = layer[e.From], lt = layer[e.To];
            int prev = e.From;
            for (int L = lf + 1; L < lt; L++)
            {
                var d = new Node { Id = _nodes.Count, Dummy = true, Layer = L, W = 2, H = 0 };
                _nodes.Add(d);
                _nodes[prev].Down.Add(d.Id);
                d.Up.Add(prev);
                e.Chain.Add(d.Id);
                prev = d.Id;
            }
            if (prev != e.To || lt > lf)
            {
                _nodes[prev].Down.Add(e.To);
                _nodes[e.To].Up.Add(prev);
            }
        }

        int maxL = _nodes.Max(n => n.Layer);
        var layers = new List<List<Node>>();
        for (int L = 0; L <= maxL; L++) layers.Add(new List<Node>());
        foreach (var n in _nodes) layers[n.Layer].Add(n);
        // baslangic sirasi: adrese gore
        foreach (var l in layers)
        {
            l.Sort((a, b) => (a.B?.Start ?? ulong.MaxValue).CompareTo(b.B?.Start ?? ulong.MaxValue));
            for (int i = 0; i < l.Count; i++) l[i].Pos = i;
        }
        // barycenter
        for (int it = 0; it < 8; it++)
        {
            bool down = it % 2 == 0;
            var range = down ? Enumerable.Range(1, maxL) : Enumerable.Range(0, maxL).Reverse();
            foreach (var L in range)
            {
                var l = layers[L];
                foreach (var n in l)
                {
                    var nb = down ? n.Up : n.Down;
                    if (nb.Count > 0) n.Pos = nb.Average(id => _nodes[id].Pos);
                }
                l.Sort((a, b) => a.Pos.CompareTo(b.Pos));
                for (int i = 0; i < l.Count; i++) l[i].Pos = i;
            }
        }

        // y koordinatlari
        var layerY = new double[maxL + 2];
        var layerH = new double[maxL + 1];
        for (int L = 0; L <= maxL; L++) layerH[L] = layers[L].Count == 0 ? 0 : layers[L].Max(n => n.H);
        double y = 0;
        for (int L = 0; L <= maxL; L++)
        {
            layerY[L] = y;
            y += layerH[L] + GapY + Math.Min(60, layers[L].Count * 4);
        }
        layerY[maxL + 1] = y;
        foreach (var n in _nodes) n.Y = layerY[n.Layer];

        // x koordinatlari
        foreach (var l in layers)
        {
            double x = 0;
            foreach (var n in l) { n.X = x; x += n.W + (n.Dummy ? GapX / 3 : GapX); }
        }
        for (int it = 0; it < 6; it++)
        {
            bool down = it % 2 == 0;
            var range = down ? Enumerable.Range(1, maxL) : Enumerable.Range(0, maxL).Reverse();
            foreach (var L in range) PlaceLayer(layers[L], down);
        }
        if (_nodes.Count > 0)
        {
            double minX = _nodes.Min(n => n.X);
            foreach (var n in _nodes) n.X -= minX;
        }

        RouteEdges(layerY, layerH);
        _bounds = Rect.Empty;
        foreach (var n in _nodes.Where(n => !n.Dummy)) _bounds.Union(new Rect(n.X, n.Y, n.W, n.H));
        foreach (var e in _edges) foreach (var p in e.Pts) _bounds.Union(p);
        if (_bounds.IsEmpty) _bounds = new Rect(0, 0, 10, 10);
    }

    private void PlaceLayer(List<Node> l, bool down)
    {
        if (l.Count == 0) return;
        var want = new double[l.Count];
        for (int i = 0; i < l.Count; i++)
        {
            var n = l[i];
            var nb = down ? n.Up : n.Down;
            want[i] = nb.Count > 0 ? nb.Average(id => _nodes[id].X + _nodes[id].W / 2) - n.W / 2 : n.X;
        }
        // soldan saga cakisma cozumu
        double right = double.MinValue;
        for (int i = 0; i < l.Count; i++)
        {
            var n = l[i];
            double gap = i == 0 ? 0 : (n.Dummy || l[i - 1].Dummy ? GapX / 3 : GapX);
            n.X = Math.Max(want[i], right + gap);
            right = n.X + n.W;
        }
        // sagdan sola: istenenden saga kaymis bloklari geri cek
        double left = double.MaxValue;
        for (int i = l.Count - 1; i >= 0; i--)
        {
            var n = l[i];
            double gap = i == l.Count - 1 ? 0 : (n.Dummy || l[i + 1].Dummy ? GapX / 3 : GapX);
            double maxX = left - gap - n.W;
            if (n.X > maxX) n.X = maxX;
            if (n.X < want[i] && want[i] <= maxX) n.X = want[i];
            left = n.X;
        }
    }

    private void RouteEdges(double[] layerY, double[] layerH)
    {
        // cikis/giris noktalarini dagit
        var outs = new Dictionary<int, List<GEdge>>();
        var ins = new Dictionary<int, List<GEdge>>();
        foreach (var e in _edges)
        {
            (outs.TryGetValue(e.From, out var lo) ? lo : outs[e.From] = new List<GEdge>()).Add(e);
            (ins.TryGetValue(e.To, out var li) ? li : ins[e.To] = new List<GEdge>()).Add(e);
        }
        double FirstX(GEdge e) => e.Chain.Count > 0 ? _nodes[e.Chain[0]].X : _nodes[e.To].X + _nodes[e.To].W / 2;
        double LastX(GEdge e) => e.Chain.Count > 0 ? _nodes[e.Chain[^1]].X : _nodes[e.From].X + _nodes[e.From].W / 2;
        var exitX = new Dictionary<GEdge, double>();
        var entryX = new Dictionary<GEdge, double>();
        foreach (var (id, l) in outs)
        {
            var n = _nodes[id];
            var sorted = l.OrderBy(e => e.Back ? double.MaxValue : FirstX(e)).ToList();
            for (int k = 0; k < sorted.Count; k++) exitX[sorted[k]] = n.X + (k + 1) * n.W / (sorted.Count + 1);
        }
        foreach (var (id, l) in ins)
        {
            var n = _nodes[id];
            var sorted = l.OrderBy(e => e.Back ? double.MaxValue : LastX(e)).ToList();
            for (int k = 0; k < sorted.Count; k++) entryX[sorted[k]] = n.X + (k + 1) * n.W / (sorted.Count + 1);
        }

        var chanIdx = new Dictionary<int, int>();
        double Chan(int L)
        {
            int c = chanIdx.TryGetValue(L, out var v) ? v : 0;
            chanIdx[L] = c + 1;
            return layerY[L] + layerH[L] + GapY * 0.35 + (c % 6) * 6;
        }

        int backIdx = 0;
        foreach (var e in _edges)
        {
            var u = _nodes[e.From];
            var v = _nodes[e.To];
            double ex = exitX[e], ix = entryX[e];
            var pts = e.Pts;
            pts.Clear();
            pts.Add(new Point(ex, u.Y + u.H));
            if (e.Back || v.Layer <= u.Layer)
            {
                int lo = Math.Min(u.Layer, v.Layer), hi = Math.Max(u.Layer, v.Layer);
                double xr = _nodes.Where(n => n.Layer >= lo && n.Layer <= hi).Max(n => n.X + n.W) + 18 + backIdx++ * 7;
                double y1 = u.Y + u.H + 10 + (backIdx % 4) * 4;
                double y2 = v.Y - 12 - (backIdx % 4) * 4;
                pts.Add(new Point(ex, y1));
                pts.Add(new Point(xr, y1));
                pts.Add(new Point(xr, y2));
                pts.Add(new Point(ix, y2));
            }
            else
            {
                double cy = Chan(u.Layer);
                pts.Add(new Point(ex, cy));
                foreach (var d in e.Chain)
                {
                    var dn = _nodes[d];
                    pts.Add(new Point(dn.X, cy));
                    cy = Chan(dn.Layer);
                    pts.Add(new Point(dn.X, cy));
                }
                pts.Add(new Point(ix, cy));
            }
            pts.Add(new Point(ix, v.Y));
        }
    }

    // ================= Secim / gezinme =================

    private (Node n, int line)? FindLine(ulong ea)
    {
        foreach (var n in _nodes)
        {
            if (n.Dummy) continue;
            for (int i = 0; i < n.Lines.Count; i++)
                if (n.Lines[i].Ea == ea && n.Lines[i].Type == LT.Main) return (n, i);
        }
        return null;
    }

    public void SelectEa(ulong ea, bool center)
    {
        var hit = FindLine(ea);
        if (hit == null)
        {
            var n0 = _nodes.FirstOrDefault(n => !n.Dummy && n.B != null && ea >= n.B.Start && ea < n.B.End);
            if (n0 != null) hit = (n0, 0);
        }
        CursorEa = ea;
        if (hit is var (n, li))
        {
            var r = new Rect(n.X, n.Y + Pad + li * _lh, n.W, _lh);
            if (center) CenterOn(new Rect(n.X, n.Y, n.W, Math.Min(n.H, ActualHeight / Math.Max(_scale, 0.1) * 0.5)), true);
            else EnsureVisible(r);
        }
        InvalidateVisual();
        ViewChanged?.Invoke();
    }

    private void CenterOn(Rect r, bool topThird)
    {
        double w = ActualWidth > 0 ? ActualWidth : 800, h = ActualHeight > 0 ? ActualHeight : 600;
        var c = new Point(r.X + r.Width / 2, r.Y + (topThird ? 0 : r.Height / 2));
        _off = new Vector(w / 2 - c.X * _scale, (topThird ? h * 0.15 : h / 2) - c.Y * _scale);
    }

    private void EnsureVisible(Rect r)
    {
        double w = ActualWidth, h = ActualHeight;
        if (w <= 0 || h <= 0) return;
        var s = new Rect(r.X * _scale + _off.X, r.Y * _scale + _off.Y, r.Width * _scale, r.Height * _scale);
        if (s.Top < 10) _off.Y += 10 - s.Top + 40;
        else if (s.Bottom > h - 10) _off.Y -= s.Bottom - (h - 10) + 40;
        if (s.Left > w - 40 || s.Right < 40) _off.X += w / 2 - (s.Left + s.Width / 2);
    }

    public void CenterAt(Point world)
    {
        _off = new Vector(ActualWidth / 2 - world.X * _scale, ActualHeight / 2 - world.Y * _scale);
        InvalidateVisual();
        ViewChanged?.Invoke();
    }

    public Rect ViewportWorld => new((-_off.X) / _scale, (-_off.Y) / _scale, ActualWidth / _scale, ActualHeight / _scale);

    public IEnumerable<Rect> BlockRects => _nodes.Where(n => !n.Dummy).Select(n => new Rect(n.X, n.Y, n.W, n.H));
    public IEnumerable<(List<Point> Pts, EdgeKind Kind)> EdgePaths => _edges.Select(e => (e.Pts, e.Kind));

    public void ZoomTo(double s)
    {
        var c = new Point(ActualWidth / 2, ActualHeight / 2);
        ZoomAt(c, s);
    }

    private void ZoomAt(Point screen, double ns)
    {
        ns = Math.Clamp(ns, 0.05, 3);
        var world = new Point((screen.X - _off.X) / _scale, (screen.Y - _off.Y) / _scale);
        _scale = ns;
        _off = new Vector(screen.X - world.X * _scale, screen.Y - world.Y * _scale);
        InvalidateVisual();
        ViewChanged?.Invoke();
    }

    public void FitAll()
    {
        if (_bounds.IsEmpty || ActualWidth <= 0) return;
        double s = Math.Min(ActualWidth / (_bounds.Width + 40), ActualHeight / (_bounds.Height + 40));
        _scale = Math.Clamp(s, 0.05, 1);
        CenterOn(_bounds, false);
        InvalidateVisual();
        ViewChanged?.Invoke();
    }

    // ================= Cizim =================

    protected override void OnRender(DrawingContext dc)
    {
        var p = Theme.P;
        Theme.DrawBackground(dc, new Rect(0, 0, ActualWidth, ActualHeight), p.GraphBg);
        if (_nodes.Count == 0) return;
        dc.PushTransform(new MatrixTransform(_scale, 0, 0, _scale, _off.X, _off.Y));
        var view = ViewportWorld;
        view.Inflate(50, 50);

        double th = Math.Max(1, 1.2 / Math.Max(_scale, 0.3));
        var pens = new Dictionary<EdgeKind, Pen>
        {
            [EdgeKind.True] = new Pen(Theme.B(p.EdgeTrue), th),
            [EdgeKind.False] = new Pen(Theme.B(p.EdgeFalse), th),
            [EdgeKind.Uncond] = new Pen(Theme.B(p.EdgeUncond), th),
        };
        var curNode = _nodes.FirstOrDefault(n => !n.Dummy && n.B != null && CursorEa >= n.B.Start && CursorEa < n.B.End);
        foreach (var e in _edges)
        {
            if (e.Pts.Count < 2) continue;
            bool hot = curNode != null && (e.From == curNode.Id || e.To == curNode.Id);
            var pen = hot ? new Pen(pens[e.Kind].Brush, th * 2) : pens[e.Kind];
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                c.BeginFigure(e.Pts[0], false, false);
                for (int i = 1; i < e.Pts.Count; i++) c.LineTo(e.Pts[i], true, false);
            }
            g.Freeze();
            dc.DrawGeometry(null, pen, g);
            var end = e.Pts[^1];
            var head = new StreamGeometry();
            using (var c = head.Open())
            {
                c.BeginFigure(end, true, true);
                c.LineTo(new Point(end.X - 4.5, end.Y - 9), true, false);
                c.LineTo(new Point(end.X + 4.5, end.Y - 9), true, false);
            }
            head.Freeze();
            dc.DrawGeometry(pen.Brush, null, head);
        }

        var shadow = Theme.B(p.BlockShadow);
        var bg = Theme.B(p.BlockBg);
        var border = new Pen(Theme.B(p.BlockBorder), 1);
        var selBorder = new Pen(Theme.B(p.ArrowHot), 2);
        var hl = Theme.B(p.Highlight);
        bool text = _scale >= 0.35;
        foreach (var n in _nodes)
        {
            if (n.Dummy) continue;
            var r = new Rect(n.X, n.Y, n.W, n.H);
            if (!r.IntersectsWith(view)) continue;
            dc.DrawRectangle(shadow, null, new Rect(n.X + 4, n.Y + 4, n.W, n.H));
            dc.DrawRectangle(bg, n == curNode ? selBorder : border, r);
            for (int i = 0; i < n.Lines.Count; i++)
            {
                var ln = n.Lines[i];
                double ly = n.Y + Pad + i * _lh;
                if (ln.Ea == CursorEa && ln.Type == LT.Main)
                    dc.DrawRectangle(Theme.B(p.CurLine), null, new Rect(n.X + 1, ly, n.W - 2, _lh));
                if (!text)
                {
                    int len = Math.Min(ln.Plain.TrimEnd().Length, 120);
                    if (len > 0) dc.DrawRectangle(Theme.B(Color.FromArgb(0x60, p.Fg.R, p.Fg.G, p.Fg.B)), null,
                        new Rect(n.X + Pad, ly + _lh * 0.3, len * _cw, _lh * 0.4));
                    continue;
                }
                if (HighlightWord is { Length: > 0 } hw)
                {
                    string plain = ln.Plain;
                    int idx = 0;
                    while ((idx = plain.IndexOf(hw, idx, StringComparison.Ordinal)) >= 0)
                    {
                        bool lb = idx == 0 || !LineView.IsW(plain[idx - 1]);
                        bool rb = idx + hw.Length >= plain.Length || !LineView.IsW(plain[idx + hw.Length]);
                        if (lb && rb) dc.DrawRectangle(hl, null, new Rect(n.X + Pad + idx * _cw, ly, hw.Length * _cw, _lh));
                        idx += hw.Length;
                    }
                }
                double x = n.X + Pad;
                double maxX = n.X + n.W - Pad / 2;
                foreach (var t in ln.Toks)
                {
                    if (t.Text.Length == 0) continue;
                    double tw = t.Text.Length * _cw;
                    if (x >= maxX) break;
                    if (!string.IsNullOrWhiteSpace(t.Text))
                    {
                        var ft = new FormattedText(t.Text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, _tf, _fs,
                            Theme.Tok(t.Kind), _dpi);
                        ft.MaxTextWidth = Math.Max(1, maxX - x);
                        ft.MaxLineCount = 1;
                        ft.Trimming = TextTrimming.CharacterEllipsis;
                        dc.DrawText(ft, new Point(x, ly));
                    }
                    x += tw;
                }
            }
        }
        dc.Pop();
    }

    // ================= Girdi =================

    private (Node n, int line, int col)? Hit(Point screen)
    {
        var w = new Point((screen.X - _off.X) / _scale, (screen.Y - _off.Y) / _scale);
        foreach (var n in _nodes)
        {
            if (n.Dummy) continue;
            if (w.X < n.X || w.X > n.X + n.W || w.Y < n.Y || w.Y > n.Y + n.H) continue;
            int li = (int)((w.Y - n.Y - Pad) / _lh);
            li = Math.Clamp(li, 0, Math.Max(0, n.Lines.Count - 1));
            int col = (int)((w.X - n.X - Pad) / _cw);
            return (n, li, col);
        }
        return null;
    }

    private static string? WordIn(string p, int col)
    {
        if (col < 0 || col >= p.Length || !LineView.IsW(p[col])) return null;
        int a = col, b = col;
        while (a > 0 && LineView.IsW(p[a - 1])) a--;
        while (b < p.Length && LineView.IsW(p[b])) b++;
        var w = p[a..b].Trim('.');
        return w.Length > 0 ? w : null;
    }

    public string? WordAtCursor => HighlightWord;

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        Focus();
        var pt = e.GetPosition(this);
        var h = Hit(pt);
        if (e.ChangedButton == MouseButton.Left)
        {
            if (h is var (n, li, col) && n.Lines.Count > 0)
            {
                var ln = n.Lines[li];
                CursorEa = ln.Ea;
                HighlightWord = WordIn(ln.Plain, col);
                InvalidateVisual();
                CursorMoved?.Invoke();
                if (e.ClickCount == 2) LineActivated?.Invoke();
            }
            else
            {
                _panning = true;
                _panStart = pt;
                _panOff = _off;
                CaptureMouse();
                Cursor = Cursors.SizeAll;
            }
            e.Handled = true;
        }
        else if (e.ChangedButton == MouseButton.Right)
        {
            if (h is var (n, li, col) && n.Lines.Count > 0)
            {
                var ln = n.Lines[li];
                CursorEa = ln.Ea;
                HighlightWord = WordIn(ln.Plain, col) ?? HighlightWord;
                InvalidateVisual();
                CursorMoved?.Invoke();
            }
            MenuRequested?.Invoke(pt);
            e.Handled = true;
        }
        else if (e.ChangedButton == MouseButton.Middle)
        {
            _panning = true;
            _panStart = pt;
            _panOff = _off;
            CaptureMouse();
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (!_panning)
        {
            var pt = e.GetPosition(this);
            string? w = Hit(pt) is var (n, li, col) && n.Lines.Count > 0 ? WordIn(n.Lines[li].Plain, col) : null;
            if (w != _hoverWord)
            {
                if (_hoverWord != null) HoverEnd?.Invoke();
                _hoverWord = w;
                _hoverTimer.Stop();
                if (w != null) { _hoverPt = pt; _hoverTimer.Start(); }
            }
            return;
        }
        var d = e.GetPosition(this) - _panStart;
        _off = _panOff + d;
        InvalidateVisual();
        ViewChanged?.Invoke();
    }

    protected override void OnMouseUp(MouseButtonEventArgs e)
    {
        if (_panning)
        {
            _panning = false;
            ReleaseMouseCapture();
            Cursor = null;
        }
    }

    protected override void OnMouseWheel(MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
            ZoomAt(e.GetPosition(this), _scale * (e.Delta > 0 ? 1.15 : 1 / 1.15));
        else if (Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
        {
            _off.X += e.Delta * 0.6;
            InvalidateVisual();
            ViewChanged?.Invoke();
        }
        else
        {
            _off.Y += e.Delta * 0.6;
            InvalidateVisual();
            ViewChanged?.Invoke();
        }
        e.Handled = true;
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        var all = new List<(Node n, int i)>();
        foreach (var n in _nodes.Where(n => !n.Dummy).OrderBy(n => n.B!.Start))
            for (int i = 0; i < n.Lines.Count; i++)
                if (n.Lines[i].Type == LT.Main) all.Add((n, i));
        int cur = all.FindIndex(x => x.n.Lines[x.i].Ea == CursorEa);
        int next = cur;
        switch (e.Key)
        {
            case Key.Up: next = Math.Max(0, cur - 1); break;
            case Key.Down: next = Math.Min(all.Count - 1, cur + 1); break;
            case Key.Home: next = 0; break;
            case Key.End: next = all.Count - 1; break;
            case Key.Add:
            case Key.OemPlus: ZoomTo(_scale * 1.2); e.Handled = true; return;
            case Key.Subtract:
            case Key.OemMinus: ZoomTo(_scale / 1.2); e.Handled = true; return;
            case Key.D1 when Keyboard.Modifiers == ModifierKeys.None: ZoomTo(1); e.Handled = true; return;
            case Key.W when Keyboard.Modifiers == ModifierKeys.None: FitAll(); e.Handled = true; return;
            default: base.OnKeyDown(e); return;
        }
        if (next >= 0 && next < all.Count)
        {
            var (n, i) = all[next];
            CursorEa = n.Lines[i].Ea;
            EnsureVisible(new Rect(n.X, n.Y + Pad + i * _lh, n.W, _lh));
            InvalidateVisual();
            CursorMoved?.Invoke();
            ViewChanged?.Invoke();
        }
        e.Handled = true;
    }

    public string BlockText()
    {
        var sb = new System.Text.StringBuilder();
        foreach (var n in _nodes.Where(n => !n.Dummy).OrderBy(n => n.B!.Start))
        {
            foreach (var l in n.Lines) sb.AppendLine(l.Plain);
            sb.AppendLine();
        }
        return sb.ToString();
    }
}

// Graph overview: kucuk resim + gorunen alan
public sealed class GraphOverview : FrameworkElement
{
    private GraphView? _g;
    private bool _drag;

    public GraphView? Graph
    {
        get => _g;
        set
        {
            if (_g != null) _g.ViewChanged -= InvalidateVisual;
            _g = value;
            if (_g != null) _g.ViewChanged += InvalidateVisual;
            InvalidateVisual();
        }
    }

    public GraphOverview()
    {
        ClipToBounds = true;
        Theme.Changed += InvalidateVisual;
    }

    private (double s, Vector o) Map()
    {
        var b = _g!.Bounds;
        double s = Math.Min((ActualWidth - 10) / Math.Max(1, b.Width), (ActualHeight - 10) / Math.Max(1, b.Height));
        s = Math.Min(s, 0.5);
        var o = new Vector((ActualWidth - b.Width * s) / 2 - b.X * s, (ActualHeight - b.Height * s) / 2 - b.Y * s);
        return (s, o);
    }

    protected override void OnRender(DrawingContext dc)
    {
        var p = Theme.P;
        dc.DrawRectangle(Theme.B(p.GraphBg), null, new Rect(0, 0, ActualWidth, ActualHeight));
        if (_g == null || _g.Func == null || _g.Bounds.IsEmpty) return;
        var (s, o) = Map();
        var pen = new Pen(Theme.B(p.EdgeUncond), 0.6);
        foreach (var (pts, kind) in _g.EdgePaths)
        {
            if (pts.Count < 2) continue;
            var ep = new Pen(Theme.B(kind == EdgeKind.True ? p.EdgeTrue : kind == EdgeKind.False ? p.EdgeFalse : p.EdgeUncond), 0.7);
            for (int i = 1; i < pts.Count; i++)
                dc.DrawLine(ep, new Point(pts[i - 1].X * s + o.X, pts[i - 1].Y * s + o.Y),
                    new Point(pts[i].X * s + o.X, pts[i].Y * s + o.Y));
        }
        var fill = Theme.B(p.BlockBg);
        var bd = new Pen(Theme.B(p.BlockBorder), 0.7);
        foreach (var r in _g.BlockRects)
            dc.DrawRectangle(fill, bd, new Rect(r.X * s + o.X, r.Y * s + o.Y, Math.Max(2, r.Width * s), Math.Max(2, r.Height * s)));
        var v = _g.ViewportWorld;
        var vr = new Rect(v.X * s + o.X, v.Y * s + o.Y, v.Width * s, v.Height * s);
        dc.DrawRectangle(Theme.B(Color.FromArgb(0x28, p.Accent.R, p.Accent.G, p.Accent.B)), new Pen(Theme.B(p.Accent), 1.2), vr);
    }

    private void MoveTo(Point pt)
    {
        if (_g == null || _g.Bounds.IsEmpty) return;
        var (s, o) = Map();
        _g.CenterAt(new Point((pt.X - o.X) / s, (pt.Y - o.Y) / s));
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        _drag = true;
        CaptureMouse();
        MoveTo(e.GetPosition(this));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_drag && e.LeftButton == MouseButtonState.Pressed) MoveTo(e.GetPosition(this));
    }

    protected override void OnMouseUp(MouseButtonEventArgs e)
    {
        _drag = false;
        ReleaseMouseCapture();
    }
}
