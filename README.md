# unigate

Removes the license checks from old Unity editors (2017.x to 2018.2.x, Windows x64). A patched editor starts without activation and offers every build target whose support module is installed.

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

It finds three license checks in `Unity.exe` by byte signature and makes each one return true:

- `HasLicense` gates individual build targets.
- `IsLicensed` gates startup and the sign-in window.
- `IsProLicensed` reports the Pro edition. Without it, Personal edition forces the "Made with Unity" splash back on at load/build time; it also gates the dark theme.

If a signature is missing or matches more than once, the file is left alone. Tested on 2018.2.19f1 and 2018.2.21f1.

