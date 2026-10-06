# Packaging

Install manifests for tlk-hex. The release workflow fills the real version and
SHA-256 values on every tagged release, so these files always match the latest
published assets.

## Scoop

```powershell
scoop install https://raw.githubusercontent.com/Talkdedsec/tlk-hex/main/packaging/scoop/tlk-hex.json
```

This installs the portable build (no .NET required) and adds a `tlk-hex`
shortcut. `scoop update tlk-hex` picks up new releases automatically via the
manifest's `checkver` / `autoupdate` block.

## winget

The manifests under [`winget/`](winget/) target the community repository
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs). Once a
version is accepted there:

```powershell
winget install Talkdedsec.tlk-hex
```

To submit a new version, validate and open a PR against winget-pkgs:

```powershell
winget validate --manifest packaging/winget
# then copy into winget-pkgs/manifests/t/Talkdedsec/tlk-hex/<version>/ and open a PR
```

## Notes

- Placeholder hashes (`0000…`) in the committed files are replaced by the
  release workflow with the actual asset checksums.
- All builds are x64. The portable variant is self-contained; the
  framework-dependent variant needs the .NET 10 Desktop Runtime.
