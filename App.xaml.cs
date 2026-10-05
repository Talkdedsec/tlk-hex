using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace tlk_hex;

public partial class App : Application
{
    public string? StartupFile { get; private set; }
    public bool Autonomous { get; private set; }   // -A: diyalogsuz yukle (IDA gibi)
    public string? ShotDir { get; private set; }    // --shots <klasor>: arayuz goruntuleri (test)

    private static readonly string CrashLog = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tlk-hex", "crash.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandled;
        for (int i = 0; i < e.Args.Length; i++)
        {
            var a = e.Args[i];
            if (a.Equals("-A", StringComparison.OrdinalIgnoreCase)) Autonomous = true;
            else if (a == "--shots" && i + 1 < e.Args.Length) { ShotDir = e.Args[++i]; Autonomous = true; }
            else if (File.Exists(a)) StartupFile = a;
        }
        base.OnStartup(e);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLog)!);
            File.WriteAllText(CrashLog, $"{DateTime.Now}\n{e.Exception}");
        }
        catch { }
        MessageBox.Show($"Beklenmeyen hata:\n\n{e.Exception.Message}", "tlk-hex",
            MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true; // uygulama cokmeden devam etsin
    }
}
