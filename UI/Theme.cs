using System.Windows;
using System.Windows.Media;
using tlk_hex.Core;

namespace tlk_hex.UI;

public sealed class Palette
{
    public Color Bg, Fg, CurLine, Highlight, Selection, Caret;
    public Color Prefix, PrefixNoFunc, PrefixData, PrefixUnk, PrefixExt, PrefixLib;
    public Color Mnem, Reg, Num, Kw, Punct, Name, DummyName, ImportName, LocalVar, Str, Cmt, AutoCmt, RepCmt,
        Directive, Bytes, Error, LabelDef;
    public Color ArrowUncond, ArrowCond, ArrowHot;
    public Color GraphBg, BlockBg, BlockBorder, BlockShadow, BlockSel, BlockHead, EdgeTrue, EdgeFalse, EdgeUncond;
    public Color NavFunc, NavLib, NavCode, NavData, NavUnk, NavExt, NavPtr;
    public Color Window, Surface, Panel, Border, Text, TextDim, Accent, UiSel, Hover, Header;
    public bool Dark;
}

public static class Theme
{
    private static Color C(string hex) => (Color)ColorConverter.ConvertFromString(hex);

    public static readonly Palette Light = new()
    {
        Bg = C("#FFFFFF"), Fg = C("#000080"), CurLine = C("#E3E9FA"), Highlight = C("#FFFF00"),
        Selection = C("#C2D4F2"), Caret = C("#000000"),
        Prefix = C("#000000"), PrefixNoFunc = C("#B33E22"), PrefixData = C("#808080"), PrefixUnk = C("#8A8A3C"),
        PrefixExt = C("#D000D0"), PrefixLib = C("#009090"),
        Mnem = C("#000080"), Reg = C("#000080"), Num = C("#008000"), Kw = C("#000080"), Punct = C("#000080"),
        Name = C("#0000FF"), DummyName = C("#2A3BC4"), ImportName = C("#FF00FF"), LocalVar = C("#00804A"),
        Str = C("#008080"), Cmt = C("#0000FF"), AutoCmt = C("#808080"), RepCmt = C("#6A6AA8"),
        Directive = C("#000080"), Bytes = C("#808080"), Error = C("#FF0000"), LabelDef = C("#0000FF"),
        ArrowUncond = C("#303030"), ArrowCond = C("#8A8A8A"), ArrowHot = C("#0050FF"),
        GraphBg = C("#F2F2F2"), BlockBg = C("#FFFFFF"), BlockBorder = C("#8C8C8C"), BlockShadow = C("#30000000"),
        BlockSel = C("#E3E9FA"), BlockHead = C("#EEF2FB"),
        EdgeTrue = C("#00A000"), EdgeFalse = C("#E00000"), EdgeUncond = C("#0000E0"),
        NavFunc = C("#3D7BD8"), NavLib = C("#6AE3E3"), NavCode = C("#A8442E"), NavData = C("#C4C4C4"),
        NavUnk = C("#A8A86A"), NavExt = C("#FF80FF"), NavPtr = C("#FFE000"),
        Window = C("#F0F0F0"), Surface = C("#F5F5F5"), Panel = C("#FFFFFF"), Border = C("#C9C9C9"),
        Text = C("#000000"), TextDim = C("#5E5E5E"), Accent = C("#2F7DE1"), UiSel = C("#CCE4F7"),
        Hover = C("#E5F1FB"), Header = C("#ECECEC"),
    };

    public static readonly Palette Dark = new()
    {
        Dark = true,
        Bg = C("#232323"), Fg = C("#D4D4D4"), CurLine = C("#33373F"), Highlight = C("#77701C"),
        Selection = C("#264F78"), Caret = C("#FFFFFF"),
        Prefix = C("#B4B4B4"), PrefixNoFunc = C("#E07A5F"), PrefixData = C("#8C8C8C"), PrefixUnk = C("#B0B070"),
        PrefixExt = C("#E68AE6"), PrefixLib = C("#5FC9C9"),
        Mnem = C("#7FB6FF"), Reg = C("#DCC487"), Num = C("#B5CEA8"), Kw = C("#6FA7E0"), Punct = C("#C8C8C8"),
        Name = C("#4FC1FF"), DummyName = C("#9CD3FE"), ImportName = C("#FF8BFF"), LocalVar = C("#C79BD9"),
        Str = C("#E0A47A"), Cmt = C("#7EC27E"), AutoCmt = C("#848C8E"), RepCmt = C("#9A9AD0"),
        Directive = C("#6FA7E0"), Bytes = C("#8A8A8A"), Error = C("#FF6060"), LabelDef = C("#4FC1FF"),
        ArrowUncond = C("#A0A0A0"), ArrowCond = C("#6E6E6E"), ArrowHot = C("#4FC1FF"),
        GraphBg = C("#1B1B1B"), BlockBg = C("#262626"), BlockBorder = C("#5C5C5C"), BlockShadow = C("#70000000"),
        BlockSel = C("#33373F"), BlockHead = C("#2C2F36"),
        EdgeTrue = C("#4ECB4E"), EdgeFalse = C("#F05A5A"), EdgeUncond = C("#5E9DFF"),
        NavFunc = C("#3A72C9"), NavLib = C("#4BB8B8"), NavCode = C("#A04A36"), NavData = C("#7C7C7C"),
        NavUnk = C("#8C8C55"), NavExt = C("#D070D0"), NavPtr = C("#FFE000"),
        Window = C("#2D2D30"), Surface = C("#2D2D30"), Panel = C("#252526"), Border = C("#434346"),
        Text = C("#E2E2E2"), TextDim = C("#9B9B9B"), Accent = C("#3B8EEA"), UiSel = C("#094771"),
        Hover = C("#3E3E42"), Header = C("#333337"),
    };

    // Arka plan gorseline uygun mor/siyah tema
    public static readonly Palette Purple = new()
    {
        Dark = true,
        Bg = C("#000000"), Fg = C("#E4E4EC"), CurLine = C("#3A8B5CF6"), Highlight = C("#906D3FC0"),
        Selection = C("#703B2F5E"), Caret = C("#FFFFFF"),
        Prefix = C("#B8B4C8"), PrefixNoFunc = C("#F08A6C"), PrefixData = C("#8A869A"), PrefixUnk = C("#B4AE70"),
        PrefixExt = C("#F07AD8"), PrefixLib = C("#6CD0D0"),
        Mnem = C("#B9A4FF"), Reg = C("#E6C58F"), Num = C("#A2E0A8"), Kw = C("#9D7CF0"), Punct = C("#CFCFDA"),
        Name = C("#C9A8FF"), DummyName = C("#A9B9FF"), ImportName = C("#FF7AD9"), LocalVar = C("#7FD8CB"),
        Str = C("#F2B07A"), Cmt = C("#8CD07E"), AutoCmt = C("#8A85A0"), RepCmt = C("#A69CD8"),
        Directive = C("#9D7CF0"), Bytes = C("#7E7A90"), Error = C("#FF6B6B"), LabelDef = C("#C9A8FF"),
        ArrowUncond = C("#B9A4FF"), ArrowCond = C("#6E6688"), ArrowHot = C("#FFD166"),
        GraphBg = C("#000000"), BlockBg = C("#E00E0C16"), BlockBorder = C("#5B4B8C"), BlockShadow = C("#808B5CF6"),
        BlockSel = C("#3A8B5CF6"), BlockHead = C("#1A1626"),
        EdgeTrue = C("#5BD66A"), EdgeFalse = C("#F25F6C"), EdgeUncond = C("#9D7CF0"),
        NavFunc = C("#7B55E0"), NavLib = C("#4BC0C0"), NavCode = C("#B0503C"), NavData = C("#6E6A80"),
        NavUnk = C("#8C8C55"), NavExt = C("#E070C8"), NavPtr = C("#FFE000"),
        Window = C("#121018"), Surface = C("#17151F"), Panel = C("#0E0C14"), Border = C("#2E2A3D"),
        Text = C("#E4E4EC"), TextDim = C("#8A8A9A"), Accent = C("#8B5CF6"), UiSel = C("#3B2F5E"),
        Hover = C("#241F33"), Header = C("#1A1724"),
    };

    public static Palette P { get; private set; } = Light;
    public static string Name { get; private set; } = "light";

    // ---- arka plan gorseli ----
    public static ImageSource? BgImage { get; private set; }
    public static double BgDim { get; private set; }

    public static void SetBackground(bool on, string? path, double dim)
    {
        BgDim = Math.Clamp(dim, 0, 0.95);
        BgImage = null;
        if (on)
        {
            try
            {
                var bmp = new System.Windows.Media.Imaging.BitmapImage();
                bmp.BeginInit();
                bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                bmp.UriSource = !string.IsNullOrEmpty(path) && System.IO.File.Exists(path)
                    ? new Uri(path)
                    : new Uri("pack://application:,,,/resources/bg-default.png");
                bmp.EndInit();
                bmp.Freeze();
                BgImage = bmp;
            }
            catch { BgImage = null; }
        }
        Changed?.Invoke();
    }

    // Gorunum zemini: renk + (varsa) gorsel, saga yasli UniformToFill, ustune karartma
    public static void DrawBackground(DrawingContext dc, Rect r, Color bg)
    {
        dc.DrawRectangle(B(bg), null, r);
        if (BgImage == null || r.Width <= 0 || r.Height <= 0) return;
        double iw = BgImage.Width, ih = BgImage.Height;
        double s = Math.Max(r.Width / iw, r.Height / ih);
        double w = iw * s, h = ih * s;
        dc.DrawImage(BgImage, new Rect(r.Right - w, r.Top + (r.Height - h) / 2, w, h));
        if (BgDim > 0) dc.DrawRectangle(B(Color.FromArgb((byte)(BgDim * 255), bg.R, bg.G, bg.B)), null, r);
    }
    public static event Action? Changed;

    private static readonly Dictionary<Color, SolidColorBrush> _cache = new();

    public static SolidColorBrush B(Color c)
    {
        if (_cache.TryGetValue(c, out var b)) return b;
        b = new SolidColorBrush(c);
        b.Freeze();
        _cache[c] = b;
        return b;
    }

    public static Color TokColor(Tk k) => k switch
    {
        Tk.Prefix => P.Prefix,
        Tk.PrefixNoFunc => P.PrefixNoFunc,
        Tk.PrefixData => P.PrefixData,
        Tk.PrefixUnk => P.PrefixUnk,
        Tk.PrefixExt => P.PrefixExt,
        Tk.PrefixLib => P.PrefixLib,
        Tk.Mnem => P.Mnem,
        Tk.Reg => P.Reg,
        Tk.Num => P.Num,
        Tk.Kw or Tk.Keyword2 => P.Kw,
        Tk.Punct => P.Punct,
        Tk.Name => P.Name,
        Tk.DummyName => P.DummyName,
        Tk.ImportName => P.ImportName,
        Tk.LocalVar => P.LocalVar,
        Tk.Str => P.Str,
        Tk.Cmt => P.Cmt,
        Tk.AutoCmt => P.AutoCmt,
        Tk.RepCmt => P.RepCmt,
        Tk.Directive or Tk.Macro => P.Directive,
        Tk.Bytes => P.Bytes,
        Tk.Error => P.Error,
        Tk.LabelDef => P.LabelDef,
        _ => P.Fg,
    };

    public static SolidColorBrush Tok(Tk k) => B(TokColor(k));

    public static void Apply(bool dark) => Apply(dark ? "dark" : "light");

    public static void Apply(string name)
    {
        Name = name;
        P = name switch { "dark" => Dark, "purple" => Purple, _ => Light };
        var r = Application.Current.Resources;
        void Set(string key, Color c) => r[key] = new SolidColorBrush(c);
        Set("BgBrush", P.Window);
        Set("SurfaceBrush", P.Surface);
        Set("PanelBrush", P.Panel);
        Set("BorderBrush", P.Border);
        Set("TextBrush", P.Text);
        Set("TextDimBrush", P.TextDim);
        Set("AccentBrush", P.Accent);
        Set("SelectionBrush", P.UiSel);
        Set("HoverBrush", P.Hover);
        Set("HeaderBrush", P.Header);
        Set("ViewBgBrush", P.Bg);
        Set("ViewFgBrush", P.Fg);
        Changed?.Invoke();
    }
}
