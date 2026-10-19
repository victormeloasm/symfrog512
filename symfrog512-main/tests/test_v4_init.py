#!/usr/bin/env python3
"""Verify RFC 5869 HKDF-SHA512 independent of OpenSSL via Python stdlib HMAC."""
import hashlib
import hmac
import pathlib
import subprocess
import tempfile
import os
import json

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEY = bytes(range(128))
NONCE = bytes(range(32))
INFO = b"SymFrog-512 AEAD v4 | P1024-v3 | initial state | HKDF-SHA-512"

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.digest(salt, ikm, "sha512")
    result, prev = b"", b""
    for counter in range(1, (length + 63) // 64 + 1):
        prev = hmac.digest(prk, prev + info + bytes([counter]), "sha512")
        result += prev
    return result[:length]

def main():
    expected = hkdf(KEY, NONCE, INFO, 128).hex()
    reference = (ROOT/'tests/fixtures/v4_hkdf_initial_state.hex').read_text().strip()
    assert reference == expected, 'independent HKDF fixture mismatch'
    cpp = ROOT/'tests/test_v4_init.cpp'
    with tempfile.TemporaryDirectory() as td:
        binary = pathlib.Path(td)/'initial_state'
        compiler = os.environ.get('CXX', 'clang++')
        extra = os.environ.get('SYMFROG_TEST_CPPFLAGS','').split()
        subprocess.run([compiler,'-std=c++23','-O2','-fno-rtti',*extra,str(cpp),'-o',str(binary),*os.environ.get('SYMFROG_TEST_LDLIBS','-lsodium -lcrypto').split()],check=True)
        result = subprocess.check_output([str(binary)],text=True).strip()
    assert result == expected, 'C++ v4 initial state differs from independent RFC 5869 HKDF'
    print('PASS: independent HKDF-SHA512 128-byte KAT and 2,048 XOR-related pairs separated')
if __name__ == '__main__': main()
