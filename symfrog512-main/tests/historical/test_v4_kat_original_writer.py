# Historical executable-only KAT: expects the *v4 writer*, not the v5 writer.
# For v4 ciphertext compatibility against the v5 reader, use tests/test_v5_siv.py.
#!/usr/bin/env python3
"""Deterministic v4 encryption, key/nonce separation, and authenticated integrity."""
import hashlib
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = pathlib.Path(os.environ.get('SYMFROG_V4_BIN', str(ROOT/'symfrog512')))
V4_SHA256 = '2f1ea307215670667eda1c23989d089afb5b112fc223aeef3beaa2289a7ba00a'

def execute(*args, ok=True):
    p = subprocess.run([str(BIN),*map(str,args)],capture_output=True,text=True)
    assert (p.returncode == 0) == ok, (args,p.stderr)

def main():
    with tempfile.TemporaryDirectory() as t:
        w=pathlib.Path(t)
        key=bytes(range(128))
        nonce=bytes(range(32))
        mask=bytes((i*11+1)%256 for i in range(32))
        alt=key[:96]+bytes(x^y for x,y in zip(key[96:],mask))
        adjusted=bytes(x^y for x,y in zip(nonce,mask))
        (w/'k').write_bytes(key);(w/'k2').write_bytes(alt)
        (w/'k').chmod(0o600);(w/'k2').chmod(0o600)
        pt=bytes(i%256 for i in range(4097));(w/'pt').write_bytes(pt)
        p=w/'ct'; p2=w/'ct2'
        opt=['--allow-unsafe-nonce','--ad','0102030405','--quiet']
        execute('enc',w/'pt',p,'--key-file',w/'k','--nonce-hex',nonce.hex(),*opt)
        d=p.read_bytes()
        assert d[8:12]==(4).to_bytes(4,'little')
        digest=hashlib.sha256(d).hexdigest()
        assert digest == V4_SHA256, 'v4 KAT changed'
        execute('enc',w/'pt',p2,'--key-file',w/'k2','--nonce-hex',adjusted.hex(),*opt)
        d2=p2.read_bytes()
        assert d[152:]!=d2[152:], 'legacy key/nonce XOR equivalence survived in v4'
        out=w/'decoded'
        execute('dec',p,out,'--key-file',w/'k','--ad','0102030405','--quiet')
        assert out.read_bytes()==pt
        target=w/'reject';target.write_bytes(b'untouched')
        execute('dec',p,target,'--key-file',w/'k2','--ad','0102030405','--force','--quiet',ok=False)
        assert target.read_bytes()==b'untouched'
        execute('dec',p,target,'--key-file',w/'k','--ad','9999','--force','--quiet',ok=False)
        assert target.read_bytes()==b'untouched'
        t=bytearray(d);t[152+10]^=1;(w/'tamper').write_bytes(t)
        execute('dec',w/'tamper',target,'--key-file',w/'k','--ad','0102030405','--force','--quiet',ok=False)
        assert target.read_bytes()==b'untouched'
        print('PASS: v4 deterministic KAT, related key/nonce separation, decrypt, integrity rejections')
if __name__ == '__main__': main()
