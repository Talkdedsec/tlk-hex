using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace tlk_hex;

// Test: ekran disinda arayuz goruntuleri al (--shots <klasor>)
public partial class MainWindow
{
    private async Task Pause(int ms = 400)
    {
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
        await Task.Delay(ms);
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private void Snap(string dir, string name, FrameworkElement? el = null)
    {
        el ??= (FrameworkElement)Content;
        int w = (int)Math.Max(1, el.ActualWidth), h = (int)Math.Max(1, el.ActualHeight);
        var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            dc.DrawRectangle(Background, null, new Rect(0, 0, w, h));
            dc.DrawRectangle(new VisualBrush(el), null, new Rect(0, 0, w, h));
        }
        rtb.Render(dv);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(Path.Combine(dir, name + ".png"));
        enc.Save(fs);
    }

    public async Task RunShots(string dir, string file)
    {
        Directory.CreateDirectory(dir);
        await Pause(600);
        Snap(dir, "00-welcome");
        OpenFile(file, false);
        await Pause(300);
        for (int i = 0; i < 100 && (_s == null || _busy); i++) await Task.Delay(200);
        await Pause(800);
        Snap(dir, "01-graph");
        SetGraph(false);
        await Pause();
        Snap(dir, "02-text");
        var hf = _s!.Db.Funcs.Values.OrderByDescending(f => _s.Db.XrefsTo(f.Start).Count).First();
        OnWordHover(_dv, _s.Db.FuncName(hf), new Point(300, 200));
        await Pause();
        if (_preview.Child is FrameworkElement pc0) Snap(dir, "02b-preview", pc0);
        HidePreview();
        _go.FocusBox();
        _go.SetText("Create");
        await Pause();
        Snap(dir, "02c-gobox", _go.SuggestionList);
        _go.SetText("");
        ShowSearch("Window", "all");
        await Pause(1500);
        Snap(dir, "02d-search");
        ShowSearch("48 89 5C 24", "bytes");
        await Pause(1500);
        Snap(dir, "02e-search-bytes", _sp);
        ShowAnch(_outAnch);
        Jump(_s!.DefaultEa() + 0x40, true);
        await Pause();
        ShowDoc("hexview", "Hex View-1", _hv);
        await Pause();
        Snap(dir, "03-hex");
        ShowPseudo(_s.Db.Entry);
        await Pause();
        Snap(dir, "04-pseudo");
        ShowStrings();
        await Pause();
        Snap(dir, "05-strings");
        ShowNames();
        await Pause();
        Snap(dir, "06-names");
        ShowSegments();
        await Pause();
        Snap(dir, "07-segments");
        ShowFindings();
        await Pause();
        Snap(dir, "08-findings");
        _fp.ToggleFolders();
        ShowAnch(_treeAnch);
        await Pause();
        Snap(dir, "09-tree");
        SetTheme("light");
        await Pause();
        Snap(dir, "10-light");
        SetTheme("dark");
        await Pause();
        Snap(dir, "11-dark");
        SetTheme("purple");
        var sw = new SettingsWindow(_cfg) { ShowActivated = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -6000, Top = 0 };
        sw.Show();
        await Pause();
        Snap(dir, "12-settings", (FrameworkElement)sw.Content);
        sw.Close();

        // menuler
        int mi = 0;
        foreach (var idx in new[] { 0, 1, 4 })
        {
            var m = (System.Windows.Controls.MenuItem)MainMenu.Items[idx];
            m.IsSubmenuOpen = true;
            await Pause();
            if (m.Template.FindName("PART_Popup", m) is System.Windows.Controls.Primitives.Popup pop && pop.Child is FrameworkElement pc)
                Snap(dir, $"13-menu{mi++}", pc);
            m.IsSubmenuOpen = false;
        }

        // diyaloglar
        int di = 0;
        UI.Dialogs.ShotHook = w =>
        {
            w.ShowActivated = false;
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = -6000;
            w.Top = 0;
            w.ContentRendered += async (_, _) =>
            {
                await Task.Delay(300);
                Snap(dir, $"14-dlg{di++}", (FrameworkElement)w.Content);
                w.Close();
            };
        };
        JumpDialog();
        var f0 = _s.Db.Funcs.Values.OrderByDescending(f => _s.Db.XrefsTo(f.Start).Count).First();
        ShowXrefs(f0.Start);
        UI.Dialogs.Load(this, _s.Db.FilePath, _s.Db.FileBytes, true, out _);
        UI.Dialogs.QuickStart(this, RecentFiles.Load());
        UI.Dialogs.SearchText(this, "", false);
        UI.Dialogs.Info(this, "Klavye kısayolları", UI.Dialogs.Shortcuts);
        ChooseFunction();
        UI.Dialogs.ShotHook = null;
        _s.Db.Dirty = false;
        Application.Current.Shutdown();
    }
}
