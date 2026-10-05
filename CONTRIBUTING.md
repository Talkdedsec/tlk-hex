# Contributing

Thanks for your interest in improving **tlk-hex**! Issues and pull requests are welcome.

## Building

Requirements: Windows 10/11 and the [.NET 10 SDK](https://dotnet.microsoft.com/).

```sh
dotnet build -c Release
```

The project is a WPF app (`net10.0-windows`). Core analysis lives in `Core/`, the UI in `UI/` and the
`MainWindow.*.cs` partial files; the website lives in `docs/`.

## Reporting bugs

Open an issue with:

- what you did and what you expected,
- the file type/architecture (PE/ELF, x86/x64) if relevant,
- steps to reproduce, and the tlk-hex version or commit.

Please **do not** attach copyrighted or malicious binaries. A minimal sample you have the rights to, or
a public file (e.g. a Windows system DLL), is ideal.

## Pull requests

- Keep changes focused; one topic per PR.
- Match the surrounding code style (the repo ships an `.editorconfig`).
- Make sure `dotnet build -c Release` succeeds (CI runs it on every PR).
- Describe what changed and why.

## Scope & ethics

tlk-hex is a static analysis / reverse-engineering tool for learning, security research, CTFs and
**authorized** analysis. Contributions that exist only to defeat licensing/DRM of third-party software,
or that target a specific product's protection, are out of scope.

---

<details>
<summary><b>Türkçe</b></summary>

<br>

Katkılar için teşekkürler! Derleme için Windows 10/11 ve [.NET 10 SDK](https://dotnet.microsoft.com/)
gerekir: `dotnet build -c Release`. Çekirdek analiz `Core/`, arayüz `UI/` ve `MainWindow.*.cs`
dosyalarında; site `docs/` altında.

**Hata bildirimi:** ne yaptığın, ne beklediğin, dosya türü/mimari, yeniden üretme adımları ve sürüm/commit.
Telifli ya da zararlı dosya ekleme; hakkına sahip olduğun küçük bir örnek veya genel bir dosya (ör. bir
Windows sistem DLL'i) ideal.

**PR:** odaklı tut, `.editorconfig`'e uy, `dotnet build -c Release` geçsin, neyi neden değiştirdiğini anlat.

**Kapsam:** araç; öğrenme, güvenlik araştırması, CTF ve izinli analiz içindir. Yalnızca üçüncü taraf
yazılımların lisans/DRM korumasını kırmaya yönelik katkılar kapsam dışıdır.

</details>
