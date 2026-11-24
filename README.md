# unigate

Removes the license checks from old Unity editors (5.3.x and 2017.x to 2018.2.x, Windows x64). A patched editor starts without activation and offers every build target whose support module is installed.

The original goal was PS Vita builds. These editors ship the Vita player, but Unity hides the build target unless the license includes console access.

## Usage

Requires [uv](https://docs.astral.sh/uv/). Close Unity first.

```powershell
uv run unigate.py --editor <dir>            # patch
uv run unigate.py --editor <dir> --check    # show patch state
uv run unigate.py --editor <dir> --restore  # undo
```

`<dir>` is the `Editor` folder containing `Unity.exe`. The first patch saves a backup next to it.

## How it works

Each supported era has its own profile. The 2017.x to 2018.2.x profile finds three license checks in `Unity.exe` by byte signature and makes each one return true:

- `HasLicense` gates individual build targets.
- `IsLicensed` gates startup and the sign-in window.
- `IsProLicensed` reports the Pro edition. Without it, Personal edition forces the "Made with Unity" splash back on at load/build time; it also gates the dark theme.

The 5.3.x profile patches two sites in LicenseManager. The call to ProcessLicense is removed, so no license file is read and the activation flow never starts. GetTokens returns a fixed entitlement word (Pro plus every gated platform, PS Vita included), which startup, the dark theme, the splash toggle and the platform checks all read. A patched editor ignores any license file until restored.

If a signature is missing, matches more than once, or its call target is not the expected function, the file is left alone. Tested on 2018.2.19f1, 2018.2.21f1 and 5.3.6p5.

