using System.IO;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Hafif kutuphane imzasi (FLIRT benzeri): uret / uygula
public partial class MainWindow
{
    private void GenerateSignatures()
    {
        if (_s == null) return;
        var sigs = Flirt.Generate(_s.Db, _s.Dis);
        if (sigs.Count == 0)
        {
            Dialogs.Info(this, "İmza üret", "Bu dosyada imza üretilebilecek adlandırılmış fonksiyon yok. "
                + "Önce sembolleri yükle (PDB) ya da fonksiyonları adlandır.");
            return;
        }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "İmza dosyasını kaydet",
            Filter = "tlk-hex imza (*.sig)|*.sig|Tüm dosyalar (*.*)|*.*",
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + ".sig",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            Flirt.Save(dlg.FileName, sigs);
            _out.Log($"İmza: {sigs.Count} adlandırılmış fonksiyondan imza üretildi → {Path.GetFileName(dlg.FileName)}");
            SetStatus($"{sigs.Count} imza kaydedildi.");
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", "İmza kaydedilemedi:\n" + ex.Message); }
    }

    private void ExportReport()
    {
        if (_s == null) return;
        _result ??= _s.ToResult();
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Analiz raporunu kaydet",
            Filter = "HTML rapor (*.html)|*.html|Tüm dosyalar (*.*)|*.*",
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + "-rapor.html",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            Report.Save(dlg.FileName, _result);
            _out.Log($"Rapor oluşturuldu → {Path.GetFileName(dlg.FileName)}");
            SetStatus("Rapor kaydedildi.");
            if (Dialogs.Confirm(this, "Rapor", "Rapor kaydedildi. Tarayıcıda açılsın mı?"))
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true }); }
                catch { }
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", "Rapor oluşturulamadı:\n" + ex.Message); }
    }

    private void ApplySignatures()
    {
        if (_s == null) return;
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Uygulanacak imza dosyasını seç",
            Filter = "tlk-hex imza (*.sig)|*.sig|Tüm dosyalar (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != true) return;
        List<Signature> sigs;
        try { sigs = Flirt.Load(dlg.FileName); }
        catch (Exception ex) { Dialogs.Info(this, "Hata", "İmza dosyası okunamadı:\n" + ex.Message); return; }
        if (sigs.Count == 0) { Dialogs.Info(this, "İmza uygula", "Dosyada geçerli imza yok."); return; }

        int n = Flirt.Apply(_s.Db, _s.Dis, sigs, (ea, name) =>
        {
            _s!.Db.LoaderNames[ea] = name;   // sembol benzeri (kullanici adi degil)
        });
        _out.Log($"İmza: {sigs.Count} imzadan {n} fonksiyon adlandırıldı ({Path.GetFileName(dlg.FileName)}).");
        if (n > 0) { AfterEdit(Here()); SetStatus($"{n} fonksiyon imzayla adlandırıldı."); }
        else SetStatus("Eşleşen imza bulunamadı.");
    }
}
