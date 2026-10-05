using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

// IDA View-A (metin modu)
public sealed class DisasmView : LineView
{
    private Session? _s;

    public DisasmView()
    {
        Gutter = 48;
    }

    public Session? Session
    {
        get => _s;
        set
        {
            _s = value;
            SelAnchor = -1;
            ScrollTo(0);
            Refresh();
        }
    }

    protected override long LineCount => _s?.List.TotalLines ?? 0;
    protected override Line BuildLine(long i) => _s!.List.GetLine(i);

    public ulong CurrentEa => _s == null || LineCount == 0 ? 0 : _s.List.EaOfLine(Cursor);

    public void JumpTo(ulong ea, bool reveal = true)
    {
        if (_s == null) return;
        long l = _s.List.LineOfEa(ea);
        int col = CursorCol;
        SetCursor(l, col, false, reveal);
    }

    // Atlama oklari (sol bosluk)
    protected override void DrawGutter(DrawingContext dc, long top, int vis)
    {
        if (_s == null) return;
        var p = Theme.P;
        long n = LineCount;
        long end = Math.Min(n, top + vis);
        double h = Surf.ActualHeight;
        var arrows = new List<(long Src, long Dst, bool Cond)>();
        var seen = new HashSet<(long, long)>();

        for (long li = top; li < end; li++)
        {
            var line = GetLine(li);
            if (line.HasBranch && _s.Db.IsMapped(line.BranchTarget))
            {
                long dst = _s.List.LineOfEa(line.BranchTarget);
                if (Math.Abs(dst - li) < 20000 && seen.Add((li, dst))) arrows.Add((li, dst, line.IsCond));
            }
            if (line.Type is LT.Label or LT.Proc)
            {
                foreach (var x in _s.Db.XrefsTo(line.Ea))
                {
                    if (x.Type != XrefType.Jump) continue;
                    long src = _s.List.LineOfEa(x.From, false);
                    if (src >= top && src < end) continue;
                    if (Math.Abs(src - li) > 20000) continue;
                    if (!seen.Add((src, li))) continue;
                    bool cond = _s.Dis.TryDecode(x.From, out var ins) &&
                                ins.FlowControl == Iced.Intel.FlowControl.ConditionalBranch;
                    arrows.Add((src, li, cond));
                }
            }
        }
        if (arrows.Count == 0) return;

        arrows.Sort((a, b) => Math.Abs(a.Dst - a.Src).CompareTo(Math.Abs(b.Dst - b.Src)));
        var levels = new List<List<(long, long)>>();
        double half = LineH / 2;
        double Y(long l) => Math.Clamp((l - top) * LineH + half, -4, h + 4);
        var penU = new Pen(Theme.B(p.ArrowUncond), 1);
        var penC = new Pen(Theme.B(p.ArrowCond), 1) { DashStyle = DashStyles.Dash };
        var penH = new Pen(Theme.B(p.ArrowHot), 1.6);

        foreach (var (src, dst, cond) in arrows)
        {
            long lo = Math.Min(src, dst), hi = Math.Max(src, dst);
            int lv = 0;
            for (; lv < levels.Count; lv++)
                if (!levels[lv].Any(r => r.Item1 <= hi && lo <= r.Item2)) break;
            if (lv == levels.Count) levels.Add(new List<(long, long)>());
            levels[lv].Add((lo, hi));
            double x = Math.Max(3, Gutter - 8 - lv * 5);
            bool hot = src == Cursor || dst == Cursor;
            var pen = hot ? penH : cond ? penC : penU;
            double ys = Y(src), yd = Y(dst);
            double gx = Gutter - 2;
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                bool srcVis = src >= top && src < top + vis;
                c.BeginFigure(srcVis ? new Point(gx, ys) : new Point(x, ys), false, false);
                if (srcVis) c.LineTo(new Point(x, ys), true, false);
                c.LineTo(new Point(x, yd), true, false);
                c.LineTo(new Point(gx, yd), true, false);
            }
            g.Freeze();
            dc.DrawGeometry(null, pen, g);
            if (dst >= top && dst < top + vis)
            {
                var head = new StreamGeometry();
                using (var c = head.Open())
                {
                    c.BeginFigure(new Point(gx + 1, yd), true, true);
                    c.LineTo(new Point(gx - 5, yd - 3.5), true, false);
                    c.LineTo(new Point(gx - 5, yd + 3.5), true, false);
                }
                head.Freeze();
                dc.DrawGeometry(pen.Brush, null, head);
            }
        }
    }
}

// Hex View-1
public sealed class HexView : LineView
{
    private Session? _s;
    private long[] _segRow = Array.Empty<long>();
    private long _rows;
    public ulong HlStart, HlEnd;
    public bool EditMode { get; private set; }
    private int _nib;

    public event Action<ulong>? BytePatched;
    public event Action? EditModeChanged;

    public Session? Session
    {
        get => _s;
        set
        {
            _s = value;
            Recount();
            ScrollTo(0);
            Refresh();
        }
    }

    private void Recount()
    {
        if (_s == null) { _rows = 0; return; }
        _segRow = new long[_s.Db.Segs.Count + 1];
        long r = 0;
        for (int i = 0; i < _s.Db.Segs.Count; i++)
        {
            _segRow[i] = r;
            r += (_s.Db.Segs[i].Size + 15) / 16;
        }
        _segRow[^1] = r;
        _rows = r;
    }

    protected override long LineCount => _rows;

    private (Segment s, ulong ea) RowEa(long row)
    {
        int lo = 0, hi = _s!.Db.Segs.Count - 1, ans = 0;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_segRow[mid] <= row) { ans = mid; lo = mid + 1; } else hi = mid - 1;
        }
        var s = _s.Db.Segs[ans];
        return (s, s.Start + (ulong)((row - _segRow[ans]) * 16));
    }

    private int PrefixLen(Segment s) => s.Name.Length + 1 + _s!.Db.AddrDigits;
    private int ByteCol(Segment s, int j) => PrefixLen(s) + 2 + j * 3 + (j >= 8 ? 1 : 0);
    private int AsciiCol(Segment s) => PrefixLen(s) + 2 + 16 * 3 + 2;

    protected override Line BuildLine(long row)
    {
        var ln = new Line();
        if (_s == null) return ln;
        var (s, ea) = RowEa(row);
        ln.Ea = ea;
        ln.Toks.Add(new Tok(s.Name + ":" + _s.Db.AddrStr(ea), Tk.Prefix));
        ln.Toks.Add(new Tok("  ", Tk.Text));
        var asc = new System.Text.StringBuilder();
        for (int j = 0; j < 16; j++)
        {
            ulong a = ea + (ulong)j;
            if (j == 8) ln.Toks.Add(new Tok(" ", Tk.Text));
            if (a >= s.End) { ln.Toks.Add(new Tok("   ", Tk.Text)); asc.Append(' '); continue; }
            if (_s.Db.TryByte(a, out var b))
            {
                ln.Toks.Add(new Tok(b.ToString("X2") + " ", _s.Db.Patches.ContainsKey(a) ? Tk.Error : Tk.Text));
                asc.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            else
            {
                ln.Toks.Add(new Tok("?? ", Tk.Bytes));
                asc.Append('.');
            }
        }
        ln.Toks.Add(new Tok(" " + asc, Tk.Str));
        return ln;
    }

    public ulong CursorEa
    {
        get
        {
            if (_s == null || _rows == 0) return 0;
            var (s, ea) = RowEa(Cursor);
            int j = ColToByte(s, CursorCol);
            return ea + (ulong)Math.Max(0, j);
        }
    }

    private int ColToByte(Segment s, int col)
    {
        int ac = AsciiCol(s);
        if (col >= ac) return Math.Clamp(col - ac, 0, 15);
        for (int j = 15; j >= 0; j--) if (col >= ByteCol(s, j)) return j;
        return 0;
    }

    public void GotoEa(ulong ea, bool reveal = true)
    {
        if (_s == null) return;
        var s = _s.Db.SegOf(ea);
        if (s == null) return;
        long row = _segRow[s.Index] + (long)(ea - s.Start) / 16;
        int j = (int)((ea - s.Start) % 16);
        _nib = 0;
        SetCursor(row, ByteCol(s, j), false, reveal);
    }

    public void SetHighlight(ulong a, ulong b)
    {
        HlStart = a;
        HlEnd = b;
        Redraw();
    }

    protected override void DrawLineBackground(DrawingContext dc, Line line, long li, double y, double x0)
    {
        if (_s == null) return;
        var (s, ea) = RowEa(li);
        var hb = Theme.B(Color.FromArgb(0x90, Theme.P.Highlight.R, Theme.P.Highlight.G, Theme.P.Highlight.B));
        if (HlEnd > HlStart && ea < HlEnd && ea + 16 > HlStart)
        {
            for (int j = 0; j < 16; j++)
            {
                ulong a = ea + (ulong)j;
                if (a < HlStart || a >= HlEnd) continue;
                dc.DrawRectangle(hb, null, new Rect(x0 + ByteCol(s, j) * CharW, y, 2 * CharW, LineH));
                dc.DrawRectangle(hb, null, new Rect(x0 + (AsciiCol(s) + j) * CharW, y, CharW, LineH));
            }
        }
        if (li == Cursor)
        {
            int j = ColToByte(s, CursorCol);
            var pen = new Pen(Theme.B(EditMode ? Theme.P.Error : Theme.P.ArrowHot), 1);
            dc.DrawRectangle(null, pen, new Rect(x0 + ByteCol(s, j) * CharW - 1, y, 2 * CharW + 2, LineH));
            dc.DrawRectangle(null, pen, new Rect(x0 + (AsciiCol(s) + j) * CharW, y, CharW, LineH));
        }
    }

    protected override void OnClicked(long line, int col) => _nib = 0;

    public void ToggleEdit()
    {
        EditMode = !EditMode;
        _nib = 0;
        EditModeChanged?.Invoke();
        Redraw();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (_s == null) { base.OnKeyDown(e); return; }
        if (e.Key == Key.F2)
        {
            EditMode = !EditMode;
            _nib = 0;
            EditModeChanged?.Invoke();
            Redraw();
            e.Handled = true;
            return;
        }
        if (e.Key is Key.Left or Key.Right)
        {
            ulong cur = CursorEa;
            ulong n = e.Key == Key.Left ? cur - 1 : cur + 1;
            if (_s.Db.IsMapped(n)) GotoEa(n, false);
            e.Handled = true;
            return;
        }
        if (EditMode)
        {
            if (e.Key == Key.Escape) { EditMode = false; EditModeChanged?.Invoke(); Redraw(); e.Handled = true; return; }
            int v = HexKey(e.Key);
            if (v >= 0)
            {
                ulong ea = CursorEa;
                if (_s.Db.TryByte(ea, out var b))
                {
                    byte nb = _nib == 0 ? (byte)((v << 4) | (b & 0x0F)) : (byte)((b & 0xF0) | v);
                    _s.Db.PatchByte(ea, nb);
                    ClearCache();
                    if (_nib == 0) _nib = 1;
                    else
                    {
                        _nib = 0;
                        BytePatched?.Invoke(ea);
                        if (_s.Db.IsMapped(ea + 1)) GotoEa(ea + 1, false);
                    }
                    Redraw();
                }
                e.Handled = true;
                return;
            }
        }
        base.OnKeyDown(e);
    }

    private static int HexKey(Key k)
    {
        if (k >= Key.D0 && k <= Key.D9) return k - Key.D0;
        if (k >= Key.NumPad0 && k <= Key.NumPad9) return k - Key.NumPad0;
        if (k >= Key.A && k <= Key.F) return 10 + (k - Key.A);
        return -1;
    }
}

// Pseudocode-A
public sealed class PseudoView : LineView
{
    private List<Line> _lines = new();

    public PseudoView() { Gutter = 6; }

    public void SetLines(List<Line> lines)
    {
        _lines = lines;
        SelAnchor = -1;
        ScrollTo(0);
        Refresh();
        SetCursor(0, 0);
    }

    protected override long LineCount => _lines.Count;
    public long LineCountPublic => _lines.Count;
    protected override Line BuildLine(long i) => i < _lines.Count ? _lines[(int)i] : new Line();
    public ulong CurrentEa => Cursor < _lines.Count ? _lines[(int)Cursor].Ea : 0;

    public void SelectEa(ulong ea)
    {
        for (int i = 0; i < _lines.Count; i++)
            if (_lines[i].Ea == ea && i > 2) { SetCursor(i, 0, false, true); return; }
    }
}
