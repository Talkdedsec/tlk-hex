namespace tlk_hex;

public class AnalysisResult
{
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public string Architecture { get; set; } = "";
    public string EntryPoint { get; set; } = "";
    public string ImageBase { get; set; } = "";
    public string Timestamp { get; set; } = "";
    public string FileType { get; set; } = "";
    public string Subsystem { get; set; } = "";
    public bool IsDotNet { get; set; }
    public bool IsSigned { get; set; }
    public double AnalysisSeconds { get; set; }
    public byte[] RawBytes { get; set; } = Array.Empty<byte>();
    public List<SectionInfo> Sections { get; set; } = new();
    public List<ImportEntry> Imports { get; set; } = new();
    public List<ExportEntry> Exports { get; set; } = new();
    public List<FunctionEntry> Functions { get; set; } = new();
    public List<StringEntry> Strings { get; set; } = new();
    public List<FindingEntry> Findings { get; set; } = new();
    public List<SummaryEntry> Summary { get; set; } = new();
}

public class SectionInfo
{
    public string Name { get; set; } = "";
    public string VirtualAddress { get; set; } = "";
    public string VirtualSize { get; set; } = "";
    public string RawSize { get; set; } = "";
    public string Entropy { get; set; } = "";
    public string Flags { get; set; } = "";
    public long FileOffset { get; set; } = -1;
}

public class ImportEntry
{
    public string Dll { get; set; } = "";
    public string Function { get; set; } = "";
    public string Address { get; set; } = "";
    public string Ordinal { get; set; } = "";
    public long FileOffset { get; set; } = -1;
}

public class ExportEntry
{
    public string Ordinal { get; set; } = "";
    public string Function { get; set; } = "";
    public string Address { get; set; } = "";
    public long FileOffset { get; set; } = -1;
}

public class FunctionEntry
{
    public string Address { get; set; } = "";
    public string Size { get; set; } = "";
    public string Source { get; set; } = "";
    public long FileOffset { get; set; } = -1;
}

public class StringEntry
{
    public string Offset { get; set; } = "";
    public string Value { get; set; } = "";
    public string Encoding { get; set; } = "";
    public int Length { get; set; }
    public long FileOffset { get; set; } = -1;
}

public class FindingEntry
{
    public string Severity { get; set; } = "";   // Yuksek / Orta / Bilgi
    public string Category { get; set; } = "";    // Gosterge / Yetenek / Imza / Ozet
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Rank { get; set; }                 // siralama icin (0 en yuksek)
}

public class SummaryEntry
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}
