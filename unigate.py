# /// script
# requires-python = ">=3.10"
# dependencies = ["pefile>=2023.2.7"]
# ///
"""unigate: remove license checks from legacy Unity editors (5.3.x, 2017.x - 2018.2.x; Windows x64).

Patches the editor binary (Unity.exe) so that:

  1. The PS Vita (PSP2) build target is selectable and buildable, along
     with any other build target whose player module is actually installed.
  2. The editor considers itself licensed at startup, so the CEF sign-in /
     activation window and the batchmode "not activated" abort are skipped.
  3. The editor reports the Pro edition, which unlocks the edition-gated
     features: disabling the "Made with Unity" splash screen and the dark
     theme.

How each era gets there differs, so each is its own profile:

  2017.x - 2018.2.x
     Every per-platform entitlement check funnels through the native
     `HasLicense(feature)` function, a pure bitmask test on the loaded
     license's entitlement bits. Personal / no-license states never carry
     console entitlement bits, so PSP2 (target 13) is always denied. Three
     predicates (HasLicense, IsLicensed, IsProLicensed) are made to return true.

  5.3.x
     The checks read a 64-bit token word that LicenseInfo copies out of
     LicenseManager, and the startup gate is `LicenseMessagePump` waiting
     while that word is zero. Two sites cover everything: the call to
     ProcessLicense() (file read, validation, activation flow) is removed
     from LicenseManager::Initialize(), and LicenseManager::GetTokens() is
     made to return a fixed word with Pro and the platform entitlements set.

Instead of hardcoded addresses, each site is located by a masked byte
signature (internal call targets wildcarded). A site is patched only when
its signature matches EXACTLY ONCE in the binary, and only when every site
of a profile is found and its call target checks out. Anything else is
reported as unsupported and left untouched. This makes the patcher safe
to run against any Unity version: known builds match, anything else
(different licensing code) is refused.

Usage:
  uv run unigate.py --editor <dir>              # patch (backs up first)
  uv run unigate.py --editor <dir> --check      # report site states only
  uv run unigate.py --editor <dir> --restore    # restore newest backup

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
SKIP_CALL = bytes.fromhex("31C0909090")  # xor eax,eax ; nop x3 (replaces a call)

# 5.3.x LicenseManager token word. Bit 0 is Pro. Every gated platform owns a
# bit, or a Personal/Pro pair of which only the Pro bit is wanted (4 iOS,
# 13 Android, 18 BlackBerry, 20 WinStore, 25 Samsung TV, 34 Tizen); the rest
# are consoles (5 Xbox 360, 6 PS3, 9 PS Vita, 21 PS4, 22 Xbox One, 23 Wii U,
# 36 PSM, 39 3DS). Team (2), Personal (62) and Edu (63) stay clear so the
# editor reads as plain Pro with every add-on.
TOKENS_53 = sum(1 << bit for bit in (0, 4, 5, 6, 9, 13, 18, 20, 21, 22, 23, 25, 34, 36, 39))
LOAD_TOKENS = b"\x48\xb8" + TOKENS_53.to_bytes(8, "little") + b"\xc3"  # mov rax, imm64 ; ret

# label, masked byte pattern ("??" = any byte), byte index of the E8 (call) opcode, description
SITES_2017 = [
    (
        "HasLicense",
        "40 53 48 83 EC 20 8B D9 E8 ?? ?? ?? ?? 83 FB 40 7D ?? "
        "48 8B 80 68 01 00 00 8B CB 48 D3 E8 24 01 48 83 C4 20 5B C3",
        8,
        "per-feature license entitlement check (gates PSP2 build target)",
        PATCH,
        0,
        None,
    ),
    (
        "IsLicensed",
        "48 83 EC 28 E8 ?? ?? ?? ?? 48 83 B8 68 01 00 00 00 0F 95 C0 48 83 C4 28 C3",
        4,
        "startup license gate (sign-in window / batchmode abort)",
        PATCH,
        0,
        None,
    ),
    (
        "IsProLicensed",
        "48 83 EC 28 E8 ?? ?? ?? ?? 0F B6 80 68 01 00 00 24 01 48 83 C4 28 C3",
        4,
        "Pro edition bit 0 (gates splash-screen disabling and dark theme)",
        PATCH,
        0,
        None,
    ),
]

BACKUP_SUFFIX = ".orig.bak"
# the site of each profile whose patch grants the Pro edition
PRO_SITES = ("IsProLicensed", "LicenseFlags")


def compile_masked(pattern: str) -> re.Pattern:
    return re.compile(
        b"".join(b"." if tok == "??" else re.escape(bytes.fromhex(tok)) for tok in pattern.split()),
        re.DOTALL,
    )


# Same tuple shape as SITES_2017, then: bytes to write, byte index where to write
# them, masked bytes the call target must start with (None = no check).
SITES_53 = [
    (
        "LicenseStatus",
        "4C 8D 44 24 38 48 8D 54 24 30 48 8B CB E8 ?? ?? ?? ?? "
        "48 8B 4C 24 30 48 8B 7C 24 48 89 83 A0 01 00 00",
        13,
        "call to ProcessLicense() (license file read, validation, activation flow)",
        SKIP_CALL,
        13,
        "40 55 53 56 57 41 54 48 8B EC 48 83 EC 70 48 C7 45 C0 FE FF FF FF",
    ),
    (
        "LicenseFlags",
        "48 8B 81 48 01 00 00 C3 CC CC CC",
        None,
        "LicenseManager::GetTokens() - entitlement word every license check reads",
        LOAD_TOKENS,
        0,
        None,
    ),
]

PROFILES = [
    # all three predicates test the entitlement mask at GetLicense()+0x168
    ("2017.x-2018.2.x", SITES_2017),
    # the status ProcessLicense() returns is the license state every later
    # check consults; status 0 means a valid license, so the file is never
    # read and the activation flow never starts.
    ("5.3.x", SITES_53),
]


def build_sites(defs):
    sites = []
    for label, pattern, call_at, desc, patch, patch_at, callee in defs:
        tokens = pattern.split()
        new = [f"{byte:02X}" for byte in patch]
        done = tokens[:patch_at] + new + tokens[patch_at + len(patch) :]
        sites.append(
            {
                "label": label,
                "orig": compile_masked(pattern),
                "done": compile_masked(" ".join(done)),
                "call_at": call_at,
                "desc": desc,
                "patch": patch,
                "patch_at": patch_at,
                "callee": callee,
            }
        )
    return sites


def off_to_va(pe: pefile.PE, off: int) -> int:
    return pe.OPTIONAL_HEADER.ImageBase + pe.get_rva_from_offset(off)


def call_target(pe: pefile.PE, data: bytes, match_off: int, call_at: int) -> int:
    rel = int.from_bytes(
        data[match_off + call_at + 1 : match_off + call_at + 5], "little", signed=True
    )
    return off_to_va(pe, match_off + call_at) + 5 + rel


def has_call(data: bytes, row) -> bool:
    """Is the site's E8 still there? (a patched site may have replaced it)"""
    site, off = row["site"], row["off"]
    return site["call_at"] is not None and data[off + site["call_at"]] == 0xE8


def callee_ok(pe: pefile.PE, data: bytes, row) -> bool:
    """The call inside a site must land on code starting with the expected bytes."""
    site, off = row["site"], row["off"]
    if site["callee"] is None or not has_call(data, row):
        return True
    start = call_target(pe, data, off, site["call_at"])
    start = pe.get_offset_from_rva(start - pe.OPTIONAL_HEADER.ImageBase)
    return compile_masked(site["callee"]).match(data, start) is not None


def survey(data: bytes, defs) -> list[dict]:
    rows = []
    for site in build_sites(defs):
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
    return rows


def survey_rows(pe: pefile.PE, data: bytes, rows) -> tuple[list[dict], bool, int | None]:
    """Judge located rows: all found, callee checks pass, remaining calls agree."""
    live = [r for r in rows if r["off"] is not None and has_call(data, r)]
    targets = {call_target(pe, data, r["off"], r["site"]["call_at"]) for r in live}
    found = all(r["off"] is not None for r in rows)
    ok = found and all(callee_ok(pe, data, r) for r in live) and len(targets) <= 1
    return rows, ok, (targets.pop() if len(targets) == 1 else None)


def examine(pe: pefile.PE, data: bytes) -> tuple[str, list[dict], bool, int | None]:
    """Pick the profile whose sites are all found, else the closest one to report on."""
    best = ("", [], False, None)
    for name, defs in PROFILES:
        rows, ok, target = survey_rows(pe, data, survey(data, defs))
        hits = sum(r["off"] is not None for r in rows)
        if hits == len(rows):
            return name, rows, ok, target
        if hits > sum(r["off"] is not None for r in best[1]):
            best = (name, rows, False, None)
    return best


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
                            fh.seek(row["off"] + row["site"]["patch_at"])
                            fh.write(row["site"]["patch"])
                tmp.unlink(missing_ok=True)
                break
            time.sleep(2)


def cmd_check(editor: Path) -> int:
    exe = editor / "Unity.exe"
    pe = pefile.PE(str(exe), fast_load=True)
    profile, rows, ok, target = examine(pe, exe.read_bytes())
    print(f"editor: {editor}")
    if profile:
        print(f"  profile: {profile}")
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
    elif not ok:
        print("  sites missing, inconsistent or unexpected call target - not a supported build")
        rc = 1
    elif target is not None:
        print(f"  shared callee @ 0x{target:X} - consistent across sites")
    pro_row = next((r for r in rows if r["site"]["label"] in PRO_SITES), None)
    if pro_row is not None and pro_row["state"] == "patched":
        print("  splash screen: disabling allowed (Pro edition forced)")
    return rc


def cmd_patch(editor: Path) -> int:
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
    profile, rows, ok, _target = examine(pe, bytes(data))
    if profile:
        print(f"profile: {profile}")

    matched = [r for r in rows if r["off"] is not None]
    if not matched:
        print("ERROR: no licensing signatures found - unsupported Unity version, nothing changed.")
        return 1
    if not ok:
        print("ERROR: sites missing, inconsistent or unexpected call target - nothing changed.")
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
        site = row["site"]
        start = row["off"] + site["patch_at"]
        data[start : start + len(site["patch"])] = site["patch"]
        print(f"  {label:<14} patched (file offset 0x{start:X})")
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
    args = ap.parse_args()

    editor = Path(args.editor)
    if not (editor / "Unity.exe").is_file():
        raise SystemExit(f"no Unity.exe in {editor} - pass the Editor directory that contains it")
    if args.restore:
        return cmd_restore(editor)
    if args.check:
        return cmd_check(editor)
    return cmd_patch(editor)


if __name__ == "__main__":
    sys.exit(main())
