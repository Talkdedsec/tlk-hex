using System;
using System.Collections.Generic;
using System.IO;
using Xunit;
using tlk_hex.Core;

namespace tlk_hex.Tests;

public class HexFormatTests
{
    [Theory]
    [InlineData(0ul, "0")]
    [InlineData(9ul, "9")]
    [InlineData(10ul, "0Ah")]
    [InlineData(255ul, "0FFh")]
    [InlineData(0x1234ul, "1234h")]
    [InlineData(0x10ul, "10h")]
    public void HexNum_matches_ida_style(ulong v, string expected)
        => Assert.Equal(expected, Db.HexNum(v));

    [Theory]
    [InlineData(-8L, "-8")]
    [InlineData(-0x18L, "-18h")]
    [InlineData(4L, "4")]
    public void HexNumSigned_handles_sign(long v, string expected)
        => Assert.Equal(expected, Db.HexNumSigned(v));
}

public class ParseNumTests
{
    [Theory]
    [InlineData("0x10", 16ul)]
    [InlineData("10h", 16ul)]
    [InlineData("1Fh", 31ul)]
    [InlineData("#16", 16ul)]
    [InlineData("ff", 255ul)]          // no prefix => hex
    public void ParseNum_parses_common_forms(string s, ulong expected)
        => Assert.Equal(expected, Db.ParseNum(s));

    [Fact]
    public void ParseNum_rejects_garbage()
        => Assert.Null(Db.ParseNum("zzz"));
}

public class DemangleTests
{
    [Theory]
    [InlineData("main", "main")]
    [InlineData("_Func@8", "Func")]              // __stdcall decoration
    [InlineData("?Foo@@YAXXZ", "Foo")]           // simple C++ function
    public void Demangle_simplifies(string input, string expected)
        => Assert.Equal(expected, Pdb.Demangle(input));
}

public class SearchParsingTests
{
    [Theory]
    [InlineData("0x1F", 31ul)]
    [InlineData("1Fh", 31ul)]
    [InlineData("31", 31ul)]
    public void ParseValue_handles_hex_and_dec(string s, ulong expected)
        => Assert.Equal(expected, SearchEngine.ParseValue(s));

    [Fact]
    public void ParsePattern_supports_wildcards()
    {
        var p = SearchEngine.ParsePattern("48 8B ?? 05");
        Assert.NotNull(p);
        var (pat, mask) = p!.Value;
        Assert.Equal(4, pat.Length);
        Assert.True(mask[0]);
        Assert.True(mask[1]);
        Assert.False(mask[2]);          // ?? => any byte
        Assert.True(mask[3]);
        Assert.Equal(0x48, pat[0]);
        Assert.Equal(0x05, pat[3]);
    }

    [Fact]
    public void ParsePattern_rejects_invalid()
        => Assert.Null(SearchEngine.ParsePattern("not hex!"));
}

public class ApiHintsTests
{
    [Theory]
    [InlineData("CreateFileW", "lpFileName")]
    [InlineData("CreateFileA", "lpFileName")]
    [InlineData("VirtualAllocEx", "flProtect")]
    [InlineData("__imp_WriteProcessMemory", "lpBaseAddress")]
    [InlineData("j_strcmp", "str2")]
    public void TryGet_resolves_known_apis(string name, string mustContain)
    {
        // j_ ve __imp_ onekleri cagri tarafinda temizlenir; burada net isim veriyoruz
        string clean = name.StartsWith("j_") ? name[2..]
            : name.StartsWith("__imp_") ? name[6..] : name;
        Assert.True(ApiHints.TryGet(clean, out var proto));
        Assert.Contains(mustContain, proto);
    }

    [Fact]
    public void TryGet_rejects_unknown()
        => Assert.False(ApiHints.TryGet("SomeRandomFunc123", out _));

    [Fact]
    public void TryGet_formats_prototype()
    {
        Assert.True(ApiHints.TryGet("memcpy", out var p));
        Assert.Equal("memcpy(dest, src, count)", p);
    }
}

public class BinDiffTests
{
    private static FuncSig F(ulong ea, string name, int ic, ulong hash, bool dummy = false, params string[] calls)
        => new() { Ea = ea, Name = name, InsnCount = ic, Hash = hash, Dummy = dummy, Calls = calls };

    [Fact]
    public void Identical_lists_match_fully()
    {
        var a = new[] { F(1, "foo", 10, 0x111, false, "CreateFileW"), F(2, "bar", 5, 0x222) };
        var b = new[] { F(100, "foo", 10, 0x111, false, "CreateFileW"), F(200, "bar", 5, 0x222) };
        var s = BinDiff.Summarize(BinDiff.Compare(a, b));
        Assert.Equal(2, s.Identical);
        Assert.Equal(0, s.Changed);
        Assert.Equal(0, s.OnlyLeft + s.OnlyRight);
    }

    [Fact]
    public void Added_and_removed_are_classified()
    {
        var a = new[] { F(1, "foo", 10, 0x111), F(2, "gone", 7, 0x999) };
        var b = new[] { F(100, "foo", 10, 0x111), F(200, "brandnew", 8, 0xABC) };
        var s = BinDiff.Summarize(BinDiff.Compare(a, b));
        Assert.Equal(1, s.Identical);
        Assert.Equal(1, s.OnlyLeft);
        Assert.Equal(1, s.OnlyRight);
    }

    [Fact]
    public void Same_name_different_body_is_changed()
    {
        // ayni isim, farkli hash + yakin govde + ortak cagri -> degisti
        var a = new[] { F(1, "check", 20, 0x111, false, "strcmp", "printf") };
        var b = new[] { F(100, "check", 22, 0x222, false, "strcmp", "printf") };
        var pairs = BinDiff.Compare(a, b);
        var s = BinDiff.Summarize(pairs);
        Assert.Equal(1, s.Changed);
        Assert.True(pairs.Single(p => p.Kind == DiffKind.Changed).Similarity is > 0.5 and < 1.0);
    }

    [Fact]
    public void Fuzzy_matches_renamed_function_by_structure()
    {
        // isim degismis (biri dummy) ama govde + cagrilar ayni -> birebir (hash esit)
        var a = new[] { F(1, "sub_1000", 12, 0x55, true, "send", "recv") };
        var b = new[] { F(100, "sub_2000", 12, 0x55, true, "send", "recv") };
        var s = BinDiff.Summarize(BinDiff.Compare(a, b));
        Assert.Equal(1, s.Identical);
    }
}

public class FlirtTests
{
    private static Signature Sig(string name, byte[] pat, byte[] mask)
        => new() { Name = name, Pattern = pat, Mask = mask };

    [Fact]
    public void Matches_respects_wildcards()
    {
        var s = Sig("f", new byte[] { 0x55, 0x8B, 0xEC, 0x00 }, new byte[] { 0xFF, 0xFF, 0xFF, 0x00 });
        Assert.True(s.Matches(new byte[] { 0x55, 0x8B, 0xEC, 0x99 }));   // son bayt joker
        Assert.True(s.Matches(new byte[] { 0x55, 0x8B, 0xEC, 0x11, 0x22 })); // daha uzun pencere ok
        Assert.False(s.Matches(new byte[] { 0x55, 0x8B, 0xED, 0x00 }));  // sabit bayt uymuyor
        Assert.False(s.Matches(new byte[] { 0x55, 0x8B }));              // pencere kisa
    }

    [Fact]
    public void Save_load_roundtrip_preserves_signatures()
    {
        var sigs = new List<Signature>
        {
            Sig("alpha", new byte[] { 0x48, 0x89, 0x5C, 0x24 }, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }),
            Sig("beta",  new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0xFF, 0x00, 0x00, 0x00, 0x00 }),
        };
        string path = Path.Combine(Path.GetTempPath(), "tlkhex_test_" + Guid.NewGuid().ToString("N") + ".sig");
        try
        {
            Flirt.Save(path, sigs);
            var back = Flirt.Load(path);
            Assert.Equal(2, back.Count);
            Assert.Equal("alpha", back[0].Name);
            Assert.Equal(sigs[1].Pattern, back[1].Pattern);
            Assert.Equal(sigs[1].Mask, back[1].Mask);
            Assert.Equal(4, back[0].Fixed);   // alpha: 4 sabit bayt
            Assert.Equal(1, back[1].Fixed);   // beta: 1 sabit (E8), kalan joker
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }
}

public class LoaderDetectTests
{
    [Fact]
    public void Detect_identifies_pe()
    {
        var b = new byte[0x100];
        b[0] = (byte)'M'; b[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(b, 0x3C);
        b[0x80] = (byte)'P'; b[0x81] = (byte)'E'; b[0x82] = 0; b[0x83] = 0;
        Assert.Equal("pe", Loaders.Detect(b));
    }

    [Fact]
    public void Detect_identifies_elf()
    {
        var b = new byte[0x40];
        b[0] = 0x7F; b[1] = (byte)'E'; b[2] = (byte)'L'; b[3] = (byte)'F';
        Assert.Equal("elf", Loaders.Detect(b));
    }

    [Fact]
    public void Detect_falls_back_to_bin()
        => Assert.Equal("bin", Loaders.Detect(new byte[] { 1, 2, 3, 4, 5 }));
}
