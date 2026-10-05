# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
