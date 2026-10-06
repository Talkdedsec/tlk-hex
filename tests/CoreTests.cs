using System;
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
