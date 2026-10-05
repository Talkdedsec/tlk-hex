using System.IO;
using System.Text.Json;

namespace tlk_hex;

public static class RecentFiles
{
    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tlk-hex");
    private static readonly string FilePath = Path.Combine(Dir, "recent.json");
    private const int Max = 8;

    public static List<string> Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var list = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(FilePath));
                if (list != null)
                    return list.Where(File.Exists).Distinct().Take(Max).ToList();
            }
        }
        catch { }
        return new List<string>();
    }

    public static void Add(string path)
    {
        try
        {
            path = Path.GetFullPath(path);
            var list = Load().Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            list.RemoveAll(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
            list.Insert(0, path);
            if (list.Count > Max) list = list.Take(Max).ToList();
            Directory.CreateDirectory(Dir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(list));
        }
        catch { }
    }
}
