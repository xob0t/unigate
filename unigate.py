# /// script
# requires-python = ">=3.10"
# dependencies = ["pefile>=2023.2.7"]
# ///
"""unigate: remove license checks from legacy Unity editors (2017.x - 2018.2.x era, Windows x64).

Patches the editor binary (Unity.exe) so that:

  1. The PS Vita (PSP2) build target is selectable and buildable.
     Every per-platform entitlement check funnels through the native
     `HasLicense(feature)` function, which is a pure bitmask test on the
     loaded license's entitlement bits. Personal / no-license states never
     carry console entitlement bits, so PSP2 (target 13) is always denied.
     We make HasLicense always return true, which unlocks PSP2 and any
     other build target whose player module is actually installed.
  2. The editor considers itself licensed at startup, so the CEF sign-in /
     activation window and the batchmode "not activated" abort are skipped.

Instead of hardcoded addresses, each function is located by a masked byte
signature (internal call targets wildcarded). A site is patched only when
its signature matches EXACTLY ONCE in the binary, and only when all sites
resolve their shared GetLicense() call to the same address. Anything else
is reported as unsupported and left untouched. This makes the patcher safe
to run against any Unity version: same-era builds match, newer builds
(different licensing module) are refused.

Usage:
  uv run unigate.py --editor <dir>              # patch (backs up first)
  uv run unigate.py --editor <dir> --check      # report site states only
  uv run unigate.py --editor <dir> --restore    # restore newest backup
  uv run unigate.py --editor <dir> --pro-theme  # also force Pro license bit

<dir> is the Editor directory containing Unity.exe.

Requires PSP2 support module (Data/PlaybackEngines/PSP2Player) for the Vita
target itself; without it only the license checks are removed. Intended for
local PS Vita homebrew development with a locally installed, freely
downloadable editor. Run only on your own machine.
"""

import argparse
import re
import shutil
import sys
import time
from pathlib import Path

import pefile

PATCH = bytes.fromhex("B001C3")  # mov al,1 ; ret

# label, masked byte pattern ("??" = any byte), byte index of the E8 (call) opcode, description
SITE_DEFS = [
    (
        "HasLicense",
        "40 53 48 83 EC 20 8B D9 E8 ?? ?? ?? ?? 83 FB 40 7D ?? "
        "48 8B 80 68 01 00 00 8B CB 48 D3 E8 24 01 48 83 C4 20 5B C3",
        8,
        "per-feature license entitlement check (gates PSP2 build target)",
    ),
    (
        "IsLicensed",
        "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 B8 68 01 00 00 00 0F 95 C0 48 83 C4 28 C3",
        4,
        "startup license gate (sign-in window / batchmode abort)",
    ),
    (
        "IsProLicensed",
        "48 83 EC 28 E8 ?? ?? ?? ?? 0F B6 80 68 01 00 00 24 01 48 83 C4 28 C3",
        4,
        "Pro entitlement bit 0 (license type display / dark theme)",
    ),
]

BACKUP_SUFFIX = ".orig.bak"


def compile_masked(pattern: str) -> re.Pattern:
    return re.compile(
        b"".join(b"." if tok == "??" else re.escape(bytes.fromhex(tok)) for tok in pattern.split()),
        re.DOTALL,
    )


def build_sites(pro: bool):
    sites = []
    for label, pattern, call_at, desc in SITE_DEFS:
        tokens = pattern.split()
        sites.append(
            {
                "label": label,
                "orig": compile_masked(pattern),
                # after patching, the first 3 bytes are B0 01 C3 and the rest of the
                # pattern remains as dead code - use that as the already-patched mark
                "done": compile_masked("B0 01 C3 " + " ".join(tokens[3:])),
                "call_at": call_at,
                "desc": desc,
            }
        )
    if not pro:
        sites = [s for s in sites if s["label"] != "IsProLicensed"]
    return sites


def off_to_va(pe: pefile.PE, off: int) -> int:
    return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(off)


def call_target(pe: pefile.PE, data: bytes, match_off: int, call_at: int) -> int:
    rel = int.from_bytes(
        data[match_off + call_at + 1 : match_off + call_at + 5], "little", signed=True
    )
    return off_to_va(pe, match_off + call_at) + 5 + rel


def survey(pe: pefile.PE, data: bytes, sites) -> tuple[list[dict], int | None]:
    rows = []
    for site in sites:
        orig = [m.start() for m in site["orig"].finditer(data)]
        done = [m.start() for m in site["done"].finditer(data)]
        if len(orig) == 1 and not done:
            rows.append({"site": site, "state": "unpatched", "off": orig[0]})
        elif len(done) == 1 and not orig:
            rows.append({"site": site, "state": "patched", "off": done[0]})
        else:
            rows.append(
                {
                    "site": site,
                    "state": "no match" if not orig and not done else "ambiguous",
                    "off": None,
                }
            )
    targets = {
        call_target(pe, data, r["off"], r["site"]["call_at"]) for r in rows if r["off"] is not None
    }
    consistent = len(targets) == 1
    return rows, (targets.pop() if consistent and targets else None)


def psp2_module(editor: Path) -> bool:
    return (editor / "Data" / "PlaybackEngines" / "PSP2Player").is_dir()


def newest_backup(exe: Path) -> Path | None:
    pattern = exe.name + "*" + BACKUP_SUFFIX
    backups = sorted(exe.parent.glob(pattern), key=lambda p: p.stat().st_mtime)
    return backups[-1] if backups else None


def write_out(exe: Path, data: bytes, rows) -> None:
    tmp = exe.with_name(exe.name + ".patch-tmp")
    tmp.write_bytes(data)
    for attempt in range(6):
        try:
            tmp.replace(exe)
            break
        except PermissionError:
            if attempt == 5:
                # last resort: in-place write of the patched regions
                with exe.open("r+b") as fh:
                    for row in rows:
                        if row["state"] == "unpatched":
                            fh.seek(row["off"])
                            fh.write(PATCH)
                tmp.unlink(missing_ok=True)
                break
            time.sleep(2)


def cmd_check(editor: Path) -> int:
    exe = editor / "Unity.exe"
    pe = pefile.PE(str(exe), fast_load=True)
    rows, target = survey(pe, exe.read_bytes(), build_sites(pro=True))
    print(f"editor: {editor}")
    vita_note = "installed" if psp2_module(editor) else "NOT installed (Vita target stays hidden)"
    print(f"  PSP2 module: {vita_note}")
    rc = 0
    for row in rows:
        s = row["site"]
        off = f"off 0x{row['off']:08X}" if row["off"] is not None else "off n/a"
        print(f"  {s['label']:<14} {off}  {row['state']}")
        print(f"                 {s['desc']}")
        if row["state"] not in ("unpatched", "patched"):
            rc = 1
    matched = [r for r in rows if r["off"] is not None]
    if not matched:
        print("  no licensing signatures found - unsupported Unity version")
        rc = 1
    elif target is None:
        print("  GetLicense call targets are inconsistent across sites")
        rc = 1
    else:
        print(f"  GetLicense() @ 0x{target:X} - consistent across sites")
    return rc


def cmd_patch(editor: Path, pro: bool) -> int:
    exe = editor / "Unity.exe"
    try:
        with exe.open("r+b"):
            pass
    except PermissionError:
        print("ERROR: Unity.exe is locked - close the Unity Editor and retry.")
        return 1

    backup = newest_backup(exe)
    if backup is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = exe.with_name(exe.name + stamp + BACKUP_SUFFIX)
        shutil.copy2(exe, backup)
        print(f"backup created: {backup.name}")
    else:
        print(f"backup already exists: {backup.name}")

    pe = pefile.PE(str(exe), fast_load=True)
    data = bytearray(exe.read_bytes())
    rows, target = survey(pe, bytes(data), build_sites(pro=pro))

    matched = [r for r in rows if r["off"] is not None]
    if target is None and not matched:
        print("ERROR: no licensing signatures found - unsupported Unity version, nothing changed.")
        return 1
    if target is None:
        print("ERROR: sites inconsistent or ambiguous, aborting without changes.")
        return 1
    changed = 0
    for row in rows:
        label = row["site"]["label"]
        if row["state"] == "patched":
            print(f"  {label:<14} already patched, skipping")
            continue
        if row["state"] != "unpatched":
            print(f"  {label:<14} {row['state']} - unsupported binary, aborting without changes.")
            return 1
        data[row["off"] : row["off"] + len(PATCH)] = PATCH
        print(f"  {label:<14} patched (file offset 0x{row['off']:X})")
        changed += 1

    if changed:
        write_out(exe, bytes(data), rows)
        print(f"applied {changed} patch site(s).")
    else:
        print("nothing to do - all requested sites already patched.")

    if not psp2_module(editor):
        print("note: Data/PlaybackEngines/PSP2Player is missing - license checks are removed,")
        print("      but the Vita build target needs the PSP2 support module installed.")
    print("\nverification:")
    return cmd_check(editor)


def cmd_restore(editor: Path) -> int:
    exe = editor / "Unity.exe"
    backup = newest_backup(exe)
    if backup is None:
        print("no backup found - nothing to restore.")
        return 1
    shutil.copy2(backup, exe)
    print(f"restored {exe.name} from {backup.name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--editor", required=True, help="path to the Editor directory containing Unity.exe"
    )
    ap.add_argument("--check", action="store_true", help="report only")
    ap.add_argument("--restore", action="store_true", help="restore newest backup")
    ap.add_argument("--pro-theme", action="store_true", help="also patch IsProLicensed")
    args = ap.parse_args()

    editor = Path(args.editor)
    if not (editor / "Unity.exe").is_file():
        raise SystemExit(f"no Unity.exe in {editor} - pass the Editor directory that contains it")
    if args.restore:
        return cmd_restore(editor)
    if args.check:
        return cmd_check(editor)
    return cmd_patch(editor, args.pro_theme)


if __name__ == "__main__":
    sys.exit(main())
