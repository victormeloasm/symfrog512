#!/usr/bin/env python3
"""Regression tests for accidental in-place replacement and atomic output handling."""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "symfrog512"


def run(*args: object, success: bool) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run([str(BIN), *(str(a) for a in args)], capture_output=True, text=True)
    if (cp.returncode == 0) != success:
        raise AssertionError(f"unexpected exit status {cp.returncode}: {cp.stderr}")
    return cp


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="symfrog-io-") as d:
        wd = Path(d)
        original = bytes(range(256)) * 3
        plain = wd / "input"
        plain.write_bytes(original)

        # A hash destination must never destroy the source, even with --force.
        run("hash", plain, "--out", plain, "--force", success=False)
        assert plain.read_bytes() == original, "in-place hash destroyed its input"

        digest = run("hash", plain, success=True).stdout.strip()
        assert len(digest) == 128 and all(c in "0123456789abcdef" for c in digest)
        digest_path = wd / "digest.txt"
        run("hash", plain, "--out", digest_path, success=True)
        assert digest_path.read_text() == digest + "\n"
        run("hash", plain, "--out", digest_path, success=False)
        assert digest_path.read_text() == digest + "\n"

        # Both enc and dec must reject equal input/output inode with --force.
        key = wd / "key.bin"
        key.write_bytes(bytes(range(128)))
        os.chmod(key, 0o600)
        run("enc", plain, plain, "--key-file", key, "--force", success=False)
        assert plain.read_bytes() == original, "in-place encryption destroyed its input"

        ciphertext = wd / "encrypted.syf"
        run("enc", plain, ciphertext, "--key-file", key, success=True)
        ct_data = ciphertext.read_bytes()
        run("dec", ciphertext, ciphertext, "--key-file", key, "--force", success=False)
        assert ciphertext.read_bytes() == ct_data, "in-place decryption destroyed its input"

        decoded = wd / "decoded"
        run("dec", ciphertext, decoded, "--key-file", key, success=True)
        assert decoded.read_bytes() == original

        # The --force destination must not destroy the only copy of a key/passphrase.
        # This bug was reproduced against the pre-battery audited binary.
        original_key = key.read_bytes()
        run("enc", plain, key, "--key-file", key, "--force", "--quiet", success=False)
        assert key.read_bytes() == original_key, "encryption destroyed its key file"
        run("dec", ciphertext, key, "--key-file", key, "--force", "--quiet", success=False)
        assert key.read_bytes() == original_key, "decryption destroyed its key file"
        key_link = wd / "key-hardlink"
        os.link(key, key_link)
        run("enc", plain, key_link, "--key-file", key, "--force", "--quiet", success=False)
        run("dec", ciphertext, key_link, "--key-file", key, "--force", "--quiet", success=False)
        assert key_link.read_bytes() == original_key, "hardlinked secret was destroyed"

        password_file = wd / "passphrase.txt"
        password_file.write_bytes(b"example testing passphrase\n")
        os.chmod(password_file, 0o600)
        original_passphrase = password_file.read_bytes()
        run("enc", plain, password_file, "--pass-file", password_file, "--force", "--quiet", success=False)
        run("dec", ciphertext, password_file, "--pass-file", password_file, "--force", "--quiet", success=False)
        assert password_file.read_bytes() == original_passphrase, "passphrase was destroyed"

        # With distinct outputs, --force still works as documented.
        digest_path.write_text("stale\n")
        run("hash", plain, "--out", digest_path, "--force", success=True)
        assert digest_path.read_text() == digest + "\n"

    print("PASS: input and secret-file overwrite protection; hash output handling; enc/dec roundtrip")


if __name__ == "__main__":
    try:
        main()
    except (OSError, AssertionError) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
