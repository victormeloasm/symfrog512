#!/usr/bin/env python3
"""
symfrog_inspect.py (v2)

Offline inspector for SymFrog .syf files.
- Does NOT call the symfrog binary.
- Validates header structure, sizes, nonce/salt formatting, and basic invariants.
- Detects duplicate nonces across files (reported as WARNING groups).

Usage:
  python3 symfrog_inspect.py                 # scans current directory (recursive) for *.syf/*.sfy
  python3 symfrog_inspect.py symfrog_test_out
  python3 symfrog_inspect.py --no-recursive  .
  python3 symfrog_inspect.py --json report.json  symfrog_test_out

Exit code:
  0 if all files look structurally valid (warnings allowed)
  1 if any errors were found
  2 if no files were found
"""

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple

MAGIC = b"SYMFROG1"          # 8 bytes
VERSION = 0x00000001        # u32 LE
FLAG_KEY_DERIVED = 1 << 0

SALT_BYTES = 32
NONCE_BYTES = 32
TAG_BYTES = 32
HDR_RESERVED_BYTES = 32
HEADER_BYTES = 152          # 8+4+4+32+32+8+32+32

EXTS = (".syf", ".sfy")


def _hex_short(b: bytes, n: int = 10) -> str:
    if b is None:
        return "-"
    if len(b) <= n:
        return b.hex()
    return f"{b[:n].hex()}…"


def _all_zero(b: bytes) -> bool:
    return b == b"\x00" * len(b)


def parse_header(buf: bytes) -> Dict:
    if len(buf) < HEADER_BYTES:
        raise ValueError(f"header too short: {len(buf)} bytes (< {HEADER_BYTES})")

    magic = buf[0:8]
    version, flags = struct.unpack_from("<II", buf, 8)
    salt = buf[16:16 + SALT_BYTES]
    nonce = buf[48:48 + NONCE_BYTES]
    ct_len = struct.unpack_from("<Q", buf, 80)[0]
    reserved = buf[88:88 + HDR_RESERVED_BYTES]
    header_tag = buf[120:120 + TAG_BYTES]

    return {
        "magic": magic,
        "version": version,
        "flags": flags,
        "salt": salt,
        "nonce": nonce,
        "ct_len": ct_len,
        "reserved": reserved,
        "header_tag": header_tag,
    }


def inspect_file(path: Path) -> Tuple[Dict, List[str], List[str]]:
    """
    Returns (record, errors, warnings)
    record is JSON-serializable.
    """
    errors: List[str] = []
    warnings: List[str] = []

    st = path.stat()
    size = st.st_size

    record: Dict = {
        "path": str(path),
        "size": size,
        "ok": False,
        "errors": errors,
        "warnings": warnings,
    }

    with path.open("rb") as f:
        hdr = f.read(HEADER_BYTES)

    if len(hdr) < HEADER_BYTES:
        errors.append(f"file too small to contain header: {len(hdr)} bytes")
        return record, errors, warnings

    try:
        h = parse_header(hdr)
    except Exception as e:
        errors.append(f"header parse failed: {e}")
        return record, errors, warnings

    if h["magic"] != MAGIC:
        errors.append(f"bad magic: {h['magic']!r} (expected {MAGIC!r})")

    if h["version"] != VERSION:
        errors.append(f"bad version: 0x{h['version']:08x} (expected 0x{VERSION:08x})")

    unknown_flags = h["flags"] & ~FLAG_KEY_DERIVED
    if unknown_flags != 0:
        warnings.append(f"unknown flags set: 0x{unknown_flags:08x}")

    if _all_zero(h["nonce"]):
        warnings.append("nonce is all-zero (unusual; check RNG/override)")

    if (h["flags"] & FLAG_KEY_DERIVED) != 0:
        if _all_zero(h["salt"]):
            warnings.append("FLAG_KEY_DERIVED set but salt is all-zero (unexpected for Argon2id)")
    # else: raw-key mode may intentionally keep salt zero

    if not _all_zero(h["reserved"]):
        warnings.append("reserved bytes are not all-zero (format drift?)")

    if _all_zero(h["header_tag"]):
        warnings.append("header_tag is all-zero (unexpected; check header_tag computation)")

    min_needed = HEADER_BYTES + TAG_BYTES
    if size < min_needed:
        errors.append(f"ciphertext truncated: file_size={size}, need >= {min_needed} (header+tag)")
        return record, errors, warnings

    actual_ct = size - HEADER_BYTES - TAG_BYTES
    ct_len = h["ct_len"]
    if ct_len != actual_ct:
        errors.append(f"ct_len mismatch: header says {ct_len}, file implies {actual_ct}")

    with path.open("rb") as f:
        prefix = f.read(HEADER_BYTES)
        f.seek(max(0, size - TAG_BYTES), os.SEEK_SET)
        tail = f.read(TAG_BYTES)

    record.update({
        "magic": h["magic"].decode("ascii", "replace"),
        "version": f"0x{h['version']:08x}",
        "flags": f"0x{h['flags']:08x}",
        "flags_int": int(h["flags"]),
        "key_derived": bool(h["flags"] & FLAG_KEY_DERIVED),
        "ct_len": int(ct_len),
        "nonce_hex": h["nonce"].hex(),
        "salt_hex": h["salt"].hex(),
        "header_tag_hex": h["header_tag"].hex(),
        "reserved_all_zero": _all_zero(h["reserved"]),
        "header_sha256": hashlib.sha256(prefix).hexdigest(),
        "tag_sha256": hashlib.sha256(tail).hexdigest(),
    })

    record["ok"] = (len(errors) == 0)
    return record, errors, warnings


def iter_targets(root: Path, recursive: bool) -> List[Path]:
    files: List[Path] = []
    if root.is_file():
        return [root] if root.suffix.lower() in EXTS else []
    if recursive:
        for ext in EXTS:
            files.extend(root.rglob(f"*{ext}"))
    else:
        for ext in EXTS:
            files.extend(root.glob(f"*{ext}"))
    return sorted(set(files))


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline SymFrog .syf inspector (structure/header/nonce checks).")
    ap.add_argument("paths", nargs="*", default=["."], help="Paths (files or directories). Default: current directory.")
    ap.add_argument("--no-recursive", action="store_true", help="Do not scan directories recursively.")
    ap.add_argument("--json", default=None, help="Write a JSON report to this path.")
    ap.add_argument("--quiet", action="store_true", help="Less console output (still prints errors).")
    args = ap.parse_args()

    recursive = not args.no_recursive
    targets: List[Path] = []
    for p in args.paths:
        targets.extend(iter_targets(Path(p), recursive))

    if not targets:
        print("No .syf/.sfy files found.")
        return 2

    report: List[Dict] = []
    nonce_map: Dict[str, List[str]] = {}

    file_errors = 0
    file_warnings = 0

    if not args.quiet:
        print(f"[symfrog_inspect] found {len(targets)} file(s)")

    for path in targets:
        rec, errs, warns = inspect_file(path)
        report.append(rec)

        file_errors += len(errs)
        file_warnings += len(warns)

        nonce_hex = rec.get("nonce_hex", "")
        if nonce_hex:
            nonce_map.setdefault(nonce_hex, []).append(str(path))

        if args.quiet:
            if errs:
                print(f"ERROR {path}:")
                for e in errs:
                    print(f"  - {e}")
            continue

        status = "OK" if not errs else "ERROR"
        print(f"{status:5}  {path}  size={rec['size']}  ct_len={rec.get('ct_len','?')}  flags={rec.get('flags','?')}")
        print(f"       magic={rec.get('magic','?')} ver={rec.get('version','?')} key_derived={rec.get('key_derived','?')}")
        print(f"       nonce={_hex_short(bytes.fromhex(rec['nonce_hex']))}  salt={_hex_short(bytes.fromhex(rec['salt_hex']))}")
        print(f"       header_tag={_hex_short(bytes.fromhex(rec['header_tag_hex']))}  tag_sha256={rec.get('tag_sha256','-')[:16]}…")
        for w in warns:
            print(f"       WARN: {w}")
        for e in errs:
            print(f"       ERR : {e}")
        print("")

    dup_nonces = {n: ps for n, ps in nonce_map.items() if n and len(ps) > 1}
    dup_groups = len(dup_nonces)
    dup_instances = sum((len(ps) - 1) for ps in dup_nonces.values())

    if dup_nonces and not args.quiet:
        print("WARN: duplicate nonces detected across files (same nonce reused):")
        for n, ps in sorted(dup_nonces.items(), key=lambda kv: len(kv[1]), reverse=True):
            print(f"  nonce={n[:20]}… used in {len(ps)} file(s):")
            for p in ps[:10]:
                print(f"    - {p}")
            if len(ps) > 10:
                print(f"    ... (+{len(ps)-10} more)")
        print("")

    total_warnings = file_warnings + dup_groups

    if args.json:
        outp = Path(args.json)
        outp.write_text(json.dumps({
            "summary": {
                "files": len(targets),
                "errors": file_errors,
                "file_warnings": file_warnings,
                "dup_nonce_groups": dup_groups,
                "dup_nonce_extra_instances": dup_instances,
                "warnings_total": total_warnings,
                "duplicate_nonces": dup_nonces,
            },
            "files": report
        }, indent=2))
        if not args.quiet:
            print(f"[symfrog_inspect] wrote JSON report: {outp}")

    if file_errors == 0:
        if not args.quiet:
            print(f"[symfrog_inspect] ALL FILES STRUCTURALLY OK ✅  (file_warnings={file_warnings}, dup_nonce_groups={dup_groups})")
        return 0

    print(f"[symfrog_inspect] ERRORS FOUND ❌  (errors={file_errors}, file_warnings={file_warnings}, dup_nonce_groups={dup_groups})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
