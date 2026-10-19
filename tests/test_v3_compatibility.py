#!/usr/bin/env python3
"""Legacy v2 and v3 fixture compatibility regressions. No third-party Python deps."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "tests" / "fixtures" / "legacy_v2_rawkey.syf"
LEGACY_V3 = ROOT / "tests" / "fixtures" / "legacy_v3_rawkey.syf"
V3_SHA256 = "cd31ad7c2ee7be356b61dff7c831a157b6c8eaa0d5c8f43f1c5a6aa83c01bc36"
LEGACY_SHA256 = "ea3c60d413755e0e19a0edceae878e3c09ba90bdcff78bcff1174e973471b250"


def run(*args: str, succeeds: bool = True) -> None:
    p = subprocess.run([str(ROOT / "symfrog512"), *map(str, args)], capture_output=True, text=True)
    if (p.returncode == 0) != succeeds:
        raise AssertionError(f"unexpected result {p.returncode}: {p.stderr.strip()}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    assert sha256(LEGACY.read_bytes()) == LEGACY_SHA256, "legacy fixture changed"
    assert sha256(LEGACY_V3.read_bytes()) == V3_SHA256, "v3 fixture changed"
    with tempfile.TemporaryDirectory(prefix="symfrog-v3-check-") as td:
        path = Path(td)
        key = path / "key"
        key.write_bytes(bytes(range(128))) # test-only key, deliberately public
        os.chmod(key, 0o600)
        plain = path / "plain"
        plain.write_bytes(bytes(i % 256 for i in range(4097)))
        p_v2 = path / "p_v2"
        run("dec", str(LEGACY), str(p_v2), "--key-file", str(key), "--quiet")
        assert p_v2.read_bytes() == plain.read_bytes(), "v2 decryption incompatible"
        p_v3 = path / "p_v3"
        run("dec", str(LEGACY_V3), str(p_v3), "--key-file", str(key), "--ad", "0102030405", "--quiet")
        assert p_v3.read_bytes() == plain.read_bytes(), "v3 fixture decryption incompatible"
        bad_ad = path / "bad_ad"
        run("dec", str(LEGACY_V3), str(bad_ad), "--key-file", str(key), "--ad", "000000", "--quiet", succeeds=False)
        assert not bad_ad.exists()
        altered = bytearray(LEGACY_V3.read_bytes())
        altered[152 + 10] ^= 1
        tampered = path / "tampered.syf"
        tampered.write_bytes(altered)
        rejected_output = path / "rejected-output"
        run("dec", str(tampered), str(rejected_output), "--key-file", str(key), "--ad", "0102030405", "--quiet", succeeds=False)
        assert not rejected_output.exists()
    print("PASS: original v2 fixture, original v3 KAT fixture, wrong AAD, tamper rejection")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
