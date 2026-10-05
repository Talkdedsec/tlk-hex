using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

// IDA navigation band: tum adres alani, oge turune gore renkli
public sealed class NavBand : FrameworkElement
{
    // 0 yok, 1 fonksiyon, 2 kutuphane/thunk, 3 fonksiyonsuz kod, 4 veri, 5 kesfedilmemis, 6 dis sembol
    private byte[] _cls = Array.Empty<byte>();
    private Session? _s;
    private ulong _total;
    private ulong _cur;
    private readonly ToolTip _tip = new();

    public event Action<ulong>? Navigate;

    public NavBand()
    {
        Height = 16;
        ClipToBounds = true;
        ToolTip = _tip;
        ToolTipService.SetInitialShowDelay(this, 200);
        Theme.Changed += InvalidateVisual;
        Cursor = Cursors.Hand;
    }

    public void SetSession(Session? s)
    {
        _s = s;
        Recompute();
    }

    public ulong Current
    {
        get => _cur;
        set
        {
            if (_cur == value) return;
            _cur = value;
            InvalidateVisual();
        }
    }

    public void Recompute()
    {
        if (_s == null) { _cls = Array.Empty<byte>(); _total = 0; InvalidateVisual(); return; }
        var db = _s.Db;
        _total = 0;
        foreach (var s in db.Segs) _total += (ulong)s.Size;
        int n = (int)Math.Min(4096UL, Math.Max(1UL, _total));
        _cls = new byte[n];
        var cnt = new int[7];
        for (int b = 0; b < n; b++)
        {
            ulong a0 = _total * (ulong)b / (ulong)n;
            ulong a1 = Math.Max(a0 + 1, _total * (ulong)(b + 1) / (ulong)n);
            Array.Clear(cnt);
            ulong span = a1 - a0;
            int samples = (int)Math.Min(span, 48UL);
            for (int k = 0; k < samples; k++)
            {
                ulong pos = a0 + span * (ulong)k / (ulong)samples;
                var ea = PosToEa(pos);
                if (ea is ulong e) cnt[Classify(e)]++;
            }
            byte best = 5;
            int bc = -1;
            for (byte c = 1; c < 7; c++)
                if (cnt[c] > bc) { bc = cnt[c]; best = c; }
            if (cnt[6] > 0) best = 6;
            _cls[b] = best;
        }
        InvalidateVisual();
    }

    private byte Classify(ulong ea)
    {
        var db = _s!.Db;
        var s = db.SegOf(ea);
        if (s == null) return 0;
        if (s.IsExtern) return 6;
        long o = (long)(ea - s.Start);
        var k = (ItemKind)(s.F[o] & FF.KindMask);
        switch (k)
        {
            case ItemKind.Code:
                var f = db.FuncAt(ea);
                if (f == null) return 3;
                return f.IsLibrary || f.IsThunk ? (byte)2 : (byte)1;
            case ItemKind.Extern: return 6;
            case ItemKind.Unknown: return 5;
            case ItemKind.Align: return s.X ? (byte)5 : (byte)4;
            default: return 4;
        }
    }

    private ulong? PosToEa(ulong pos)
    {
        foreach (var s in _s!.Db.Segs)
        {
            if (pos < (ulong)s.Size) return s.Start + pos;
            pos -= (ulong)s.Size;
        }
        return null;
    }

    private ulong? EaToPos(ulong ea)
    {
        ulong acc = 0;
        foreach (var s in _s!.Db.Segs)
        {
            if (s.Contains(ea)) return acc + (ea - s.Start);
            acc += (ulong)s.Size;
        }
        return null;
    }

    private Color ClsColor(byte c) => c switch
    {
        1 => Theme.P.NavFunc,
        2 => Theme.P.NavLib,
        3 => Theme.P.NavCode,
        4 => Theme.P.NavData,
        6 => Theme.P.NavExt,
        _ => Theme.P.NavUnk,
    };

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Theme.B(Theme.P.Window), null, new Rect(0, 0, w, h));
        if (_cls.Length == 0 || w <= 0) return;
        int n = _cls.Length;
        int px = (int)w;
        int runStart = 0;
        byte runCls = Cls(0, px, n);
        for (int x = 1; x <= px; x++)
        {
            byte c = x < px ? Cls(x, px, n) : (byte)255;
            if (c == runCls) continue;
            dc.DrawRectangle(Theme.B(ClsColor(runCls)), null, new Rect(runStart, 2, x - runStart, h - 4));
            runStart = x;
            runCls = c;
        }
        // segment sinirlari
        ulong acc = 0;
        var segPen = new Pen(Theme.B(Theme.P.Border), 1);
        foreach (var s in _s!.Db.Segs)
        {
            double sx = (double)acc / _total * w;
            if (acc > 0) dc.DrawLine(segPen, new Point(sx, 0), new Point(sx, h));
            acc += (ulong)s.Size;
        }
        // gosterge
        if (EaToPos(_cur) is ulong pos)
        {
            double cx = Math.Round((double)pos / _total * w);
            var ptr = Theme.B(Theme.P.NavPtr);
            dc.DrawRectangle(ptr, new Pen(Brushes.Black, 0.5), new Rect(cx - 1.5, 0, 3, h));
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                c.BeginFigure(new Point(cx - 5, 0), true, true);
                c.LineTo(new Point(cx + 5, 0), true, false);
                c.LineTo(new Point(cx, 6), true, false);
            }
            g.Freeze();
            dc.DrawGeometry(ptr, new Pen(Brushes.Black, 0.6), g);
        }
    }

    private byte Cls(int x, int px, int n)
    {
        int b = (int)((long)x * n / Math.Max(1, px));
        return _cls[Math.Clamp(b, 0, n - 1)];
    }

    private ulong? EaAt(double x)
    {
        if (_s == null || _total == 0 || ActualWidth <= 0) return null;
        ulong pos = (ulong)(Math.Clamp(x / ActualWidth, 0, 0.999999) * _total);
        return PosToEa(pos);
    }

    protected override void OnMouseDown(MouseButtonEventArgs e)
    {
        if (EaAt(e.GetPosition(this).X) is ulong ea) Navigate?.Invoke(_s!.Db.HeadOf(ea));
        CaptureMouse();
    }

    protected override void OnMouseUp(MouseButtonEventArgs e) => ReleaseMouseCapture();

    protected override void OnMouseMove(MouseEventArgs e)
    {
        var x = e.GetPosition(this).X;
        if (EaAt(x) is not ulong ea) return;
        if (e.LeftButton == MouseButtonState.Pressed) Navigate?.Invoke(_s!.Db.HeadOf(ea));
        var s = _s!.Db.SegOf(ea);
        string kind = Classify(ea) switch
        {
            1 => "Normal fonksiyon", 2 => "Kütüphane / thunk", 3 => "Komut (fonksiyon dışı)", 4 => "Veri",
            6 => "Dış sembol", _ => "Keşfedilmemiş",
        };
        _tip.Content = $"{s?.Name}:{_s.Db.AddrStr(ea)}  -  {kind}";
    }
}
