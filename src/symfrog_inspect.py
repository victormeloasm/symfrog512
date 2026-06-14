#!/usr/bin/env python3
"""
symfrog_inspect.py (hardened v2)

Offline structural inspector for SymFrog .syf files.
- Does not decrypt and cannot verify authentication tags.
- Accepts legacy format v1 and hardened format v2.
- Validates flags, KDF metadata, lengths, reserved bytes, salt/nonce invariants.
- Reports nonce-reuse risk groups using the information visible in the header.

Exit codes:
  0: all files structurally valid (warnings may exist)
  1: at least one structural error
  2: no matching files
"""

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple

MAGIC = b"SYMFROG1"
VERSION_LEGACY = 0x00000001
VERSION_CURRENT = 0x00000002
SUPPORTED_VERSIONS = {VERSION_LEGACY, VERSION_CURRENT}

FLAG_KEY_DERIVED = 1 << 0
KNOWN_FLAGS = FLAG_KEY_DERIVED
KDF_MARKER = b"KDF2"
KDF_PROFILE_NAMES = {1: "MODERATE", 2: "SENSITIVE"}

SALT_BYTES = 32
NONCE_BYTES = 32
TAG_BYTES = 32
HDR_RESERVED_BYTES = 32
HEADER_BYTES = 152
EXTS = (".syf", ".sfy")


def _hex_short(value: bytes, n: int = 10) -> str:
    return value.hex() if len(value) <= n else f"{value[:n].hex()}…"


def _all_zero(value: bytes) -> bool:
    return value == b"\x00" * len(value)


def parse_header(buf: bytes) -> Dict:
    if len(buf) != HEADER_BYTES:
        raise ValueError(f"header length is {len(buf)} bytes, expected {HEADER_BYTES}")

    version, flags = struct.unpack_from("<II", buf, 8)
    return {
        "magic": buf[0:8],
        "version": version,
        "flags": flags,
        "salt": buf[16:48],
        "nonce": buf[48:80],
        "ct_len": struct.unpack_from("<Q", buf, 80)[0],
        "reserved": buf[88:120],
        "header_tag": buf[120:152],
    }


def validate_kdf_metadata(h: Dict, errors: List[str]) -> Tuple[int, str]:
    derived = bool(h["flags"] & FLAG_KEY_DERIVED)
    version = h["version"]
    reserved = h["reserved"]

    if version == VERSION_LEGACY:
        if not _all_zero(reserved):
            errors.append("legacy v1 reserved bytes must be all-zero")
        return 0, "legacy-external"

    if not derived:
        if not _all_zero(reserved):
            errors.append("v2 raw-key file has unexpected KDF metadata")
        return 0, "none"

    if reserved[0:4] != KDF_MARKER:
        errors.append(f"v2 password file has invalid KDF marker: {reserved[0:4]!r}")
        return 0, "invalid"

    profile = reserved[4]
    if profile not in KDF_PROFILE_NAMES:
        errors.append(f"unsupported v2 KDF profile: {profile}")
    if not _all_zero(reserved[5:]):
        errors.append("v2 KDF reserved tail is not all-zero")
    return profile, KDF_PROFILE_NAMES.get(profile, "invalid")


def inspect_file(path: Path) -> Tuple[Dict, List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    record: Dict = {
        "path": str(path),
        "ok": False,
        "errors": errors,
        "warnings": warnings,
    }

    if path.is_symlink():
        errors.append("symbolic links are not inspected")
        return record, errors, warnings

    try:
        st = path.stat()
    except OSError as exc:
        errors.append(f"stat failed: {exc}")
        return record, errors, warnings

    if not path.is_file():
        errors.append("not a regular file")
        return record, errors, warnings

    size = st.st_size
    record["size"] = size
    if size < HEADER_BYTES + TAG_BYTES:
        errors.append(f"file too small: {size} bytes, need at least {HEADER_BYTES + TAG_BYTES}")
        return record, errors, warnings

    try:
        with path.open("rb") as f:
            hdr = f.read(HEADER_BYTES)
            f.seek(size - TAG_BYTES, os.SEEK_SET)
            final_tag = f.read(TAG_BYTES)
    except OSError as exc:
        errors.append(f"read failed: {exc}")
        return record, errors, warnings

    try:
        h = parse_header(hdr)
    except ValueError as exc:
        errors.append(str(exc))
        return record, errors, warnings

    if h["magic"] != MAGIC:
        errors.append(f"bad magic: {h['magic']!r}")
    if h["version"] not in SUPPORTED_VERSIONS:
        errors.append(f"unsupported version: 0x{h['version']:08x}")

    unknown_flags = h["flags"] & ~KNOWN_FLAGS
    if unknown_flags:
        errors.append(f"unknown flags set: 0x{unknown_flags:08x}")

    derived = bool(h["flags"] & FLAG_KEY_DERIVED)
    if derived and _all_zero(h["salt"]):
        errors.append("password-derived file has an all-zero salt")
    if not derived and not _all_zero(h["salt"]):
        errors.append("raw-key file has a non-zero salt")

    if _all_zero(h["nonce"]):
        if h["version"] == VERSION_CURRENT:
            errors.append("v2 nonce is all-zero")
        else:
            warnings.append("legacy nonce is all-zero; verify that it was unique for the key")

    if _all_zero(h["header_tag"]):
        warnings.append("header authentication tag is all-zero")
    if len(final_tag) != TAG_BYTES or _all_zero(final_tag):
        warnings.append("final authentication tag is missing or all-zero")

    kdf_profile, kdf_profile_name = validate_kdf_metadata(h, errors)

    actual_ct_len = size - HEADER_BYTES - TAG_BYTES
    if h["ct_len"] != actual_ct_len:
        errors.append(f"ct_len mismatch: header={h['ct_len']}, file={actual_ct_len}")

    record.update({
        "magic": h["magic"].decode("ascii", "replace"),
        "version": h["version"],
        "version_hex": f"0x{h['version']:08x}",
        "format": "legacy-v1" if h["version"] == VERSION_LEGACY else "hardened-v2",
        "flags": h["flags"],
        "flags_hex": f"0x{h['flags']:08x}",
        "key_derived": derived,
        "kdf_profile": kdf_profile,
        "kdf_profile_name": kdf_profile_name,
        "ct_len": h["ct_len"],
        "actual_ct_len": actual_ct_len,
        "nonce_hex": h["nonce"].hex(),
        "salt_hex": h["salt"].hex(),
        "header_tag_hex": h["header_tag"].hex(),
        "final_tag_hex": final_tag.hex(),
        "reserved_hex": h["reserved"].hex(),
        "header_sha256": hashlib.sha256(hdr).hexdigest(),
        "tag_sha256": hashlib.sha256(final_tag).hexdigest(),
    })
    record["ok"] = not errors
    return record, errors, warnings


def iter_targets(root: Path, recursive: bool) -> List[Path]:
    if root.is_file() or root.is_symlink():
        return [root] if root.suffix.lower() in EXTS else []
    files: List[Path] = []
    iterator = root.rglob if recursive else root.glob
    for ext in EXTS:
        files.extend(iterator(f"*{ext}"))
    return sorted(set(files))


def nonce_risk_key(rec: Dict) -> str:
    nonce = rec.get("nonce_hex", "")
    if not nonce:
        return ""
    if rec.get("key_derived"):
        # Same password + same salt/profile yields the same derived key; this is the visible risky tuple.
        return f"pass:{rec.get('version')}:{rec.get('kdf_profile')}:{rec.get('salt_hex')}:{nonce}"
    # The raw key is not visible, so duplicate nonces are conservatively grouped together.
    return f"raw:{rec.get('version')}:{nonce}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline SymFrog v1/v2 structural inspector")
    ap.add_argument("paths", nargs="*", default=["."], help="Files or directories; default is current directory")
    ap.add_argument("--no-recursive", action="store_true", help="Do not recurse into directories")
    ap.add_argument("--json", help="Write a JSON report")
    ap.add_argument("--quiet", action="store_true", help="Print only errors and final status")
    args = ap.parse_args()

    targets: List[Path] = []
    for supplied in args.paths:
        targets.extend(iter_targets(Path(supplied), not args.no_recursive))
    targets = sorted(set(targets))

    if not targets:
        print("No .syf/.sfy files found.")
        return 2

    report: List[Dict] = []
    risk_map: Dict[str, List[str]] = {}
    file_errors = 0
    file_warnings = 0

    if not args.quiet:
        print(f"[symfrog_inspect] found {len(targets)} file(s)")

    for path in targets:
        rec, errors, warnings = inspect_file(path)
        report.append(rec)
        file_errors += len(errors)
        file_warnings += len(warnings)

        if rec.get("ok"):
            key = nonce_risk_key(rec)
            if key:
                risk_map.setdefault(key, []).append(str(path))

        if args.quiet:
            if errors:
                print(f"ERROR {path}:")
                for error in errors:
                    print(f"  - {error}")
            continue

        status = "OK" if not errors else "ERROR"
        print(f"{status:5}  {path}  size={rec.get('size', '?')}  ct_len={rec.get('ct_len', '?')}")
        print(
            f"       format={rec.get('format', '?')} flags={rec.get('flags_hex', '?')} "
            f"key_derived={rec.get('key_derived', '?')} kdf={rec.get('kdf_profile_name', '?')}"
        )
        if rec.get("nonce_hex"):
            print(
                f"       nonce={_hex_short(bytes.fromhex(rec['nonce_hex']))} "
                f"salt={_hex_short(bytes.fromhex(rec['salt_hex']))}"
            )
        for warning in warnings:
            print(f"       WARN: {warning}")
        for error in errors:
            print(f"       ERR : {error}")
        print()

    duplicate_risks = {key: paths for key, paths in risk_map.items() if len(paths) > 1}
    if duplicate_risks and not args.quiet:
        print("WARN: potential nonce reuse under the same visible key context:")
        for key, paths in sorted(duplicate_risks.items(), key=lambda item: len(item[1]), reverse=True):
            print(f"  {key[:96]}… ({len(paths)} files)")
            for item in paths[:10]:
                print(f"    - {item}")
        print()

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "summary": {
                        "files": len(targets),
                        "errors": file_errors,
                        "file_warnings": file_warnings,
                        "nonce_risk_groups": len(duplicate_risks),
                    },
                    "nonce_risk_groups": duplicate_risks,
                    "files": report,
                },
                indent=2,
            )
        )
        if not args.quiet:
            print(f"[symfrog_inspect] wrote JSON report: {args.json}")

    if file_errors:
        print(
            f"[symfrog_inspect] ERRORS FOUND ❌ "
            f"(errors={file_errors}, warnings={file_warnings}, nonce_risk_groups={len(duplicate_risks)})"
        )
        return 1

    if not args.quiet:
        print(
            f"[symfrog_inspect] ALL FILES STRUCTURALLY OK ✅ "
            f"(warnings={file_warnings}, nonce_risk_groups={len(duplicate_risks)})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
