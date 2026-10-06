# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-10-06

### Added
- Two-file comparison (BinDiff): match functions between the open file and a second binary by a normalized mnemonic fingerprint plus called-import set; classified as identical / changed / only-left / only-right with a similarity score. *File → Compare with another file…*
- Library signature recognition (FLIRT-lite): generate byte-pattern signatures (`.sig`) from a named binary and apply them to name matching functions in a stripped one; ambiguous matches are skipped. *File → Produce → Generate signatures* and *File → Apply signatures*.
- Self-contained HTML analysis report (findings, sections, imports grouped by DLL, URL indicators, longest strings). *File → Produce → Analysis report (HTML)*.

## [0.1.3] - 2026-10-06

### Added
- API parameter comments: calls to ~90 common Windows/CRT functions are annotated with their prototype (e.g. `CreateFileW(lpFileName, dwDesiredAccess, …)`).
- Triage findings: known packer section signatures (UPX, ASPack, VMProtect, Themida, …), an `imphash` import-table fingerprint, and a sparse-import heuristic.
- Module 09 "Packers & triage" tutorial (EN + TR): entropy, packer signatures, imphash and import-only triage.
- A one-page cheat sheet on the site (EN + TR), printable / save-as-PDF.
- Scoop and winget install manifests under `packaging/`; the release workflow keeps their version and checksums current.

## [0.1.2] - 2026-10-06

### Added
- Module 08 "Patching" tutorial (EN + TR), and crackmes 05 (patch target) and 06 (stack string) — six practice levels in total.

### Changed
- AI support is now provider-agnostic: a single OpenAI-compatible endpoint you configure (base URL, key, model). No vendor is hardcoded.

## [0.1.1] - 2026-10-06

### Added
- Module 07 "A full EXE, end to end" — a complete reverse-engineering walkthrough (English + Turkish).
- Original, self-generated background art (no third-party image); eye logo across the app, site and icon.
- Social preview banner and an animated demo GIF.
- Unit tests (xUnit) for core logic, run in CI via `dotnet test`.
- Release now ships a portable self-contained `.exe` (no .NET needed), a zip, and a smaller framework-dependent build.

### Changed
- License is now MIT with the Commons Clause: no selling, and attribution (author name + repository link) is required.

## [0.1.0] - 2026-10-06

### Added
- Own PE / ELF / raw-binary loader and x86/x64 disassembler engine (Iced-based).
- IDA-style text view: addresses, cross-references, stack variables, import calls, segments.
- Control-flow graph view with colored edges, zoom and an overview map.
- C-like pseudocode (`F5`), with optional AI-assisted output.
- Powerful search panel: names, strings, code lines, comments, byte patterns and immediates.
- Microsoft symbol (PDB) download and local caching; name demangling.
- Hex view with in-place byte patching; apply-to-file and DIF export.
- Renaming, comments, function folders, bookmarks — persisted in a per-file database.
- Navigation band, hover previews, go/search box, welcome screen and quick guide (`F1`).
- Light, dark and purple themes; customizable background image.
- Website with usage guide, learning course, shortcuts and FAQ (English + Turkish).

[Unreleased]: https://github.com/Talkdedsec/tlk-hex/commits/main

[0.1.0]: https://github.com/Talkdedsec/tlk-hex/releases/tag/v0.1.0
[0.1.1]: https://github.com/Talkdedsec/tlk-hex/releases/tag/v0.1.1
[0.1.2]: https://github.com/Talkdedsec/tlk-hex/releases/tag/v0.1.2
[0.1.3]: https://github.com/Talkdedsec/tlk-hex/releases/tag/v0.1.3
[0.1.4]: https://github.com/Talkdedsec/tlk-hex/releases/tag/v0.1.4
