#!/usr/bin/env python3
"""AEAD v5 regression: nonce reuse, synthetic IV, authentication, and legacy v4."""
from pathlib import Path
import subprocess
import hashlib
import hmac
import os
import tempfile

ROOT=Path(__file__).resolve().parent.parent
BIN=Path(os.environ.get('SYMFROG_TEST_BIN',str(ROOT/'symfrog512')))
FIX=ROOT/'tests/fixtures'
PUBNONCE='12'*32

def call(*args, accept=True):
    r=subprocess.run([str(BIN),*map(str,args)],capture_output=True,text=True)
    assert (r.returncode==0)==accept, (args,r.returncode,r.stderr)

def main():
  with tempfile.TemporaryDirectory(prefix='symfrog-v5-') as folder:
    d=Path(folder); key=d/'key';key.write_bytes(bytes(range(128)));key.chmod(0o600)
    ad='01020304'
    reference=[]
    for size in (0,1,7,31,63,64,65,127,128,129,4097, 1048641):
      inp=d/f'in-{size}';ct=d/f'ct-{size}';out=d/f'out-{size}'
      payload=bytes((i*29+size)%256 for i in range(size));inp.write_bytes(payload)
      call('enc',inp,ct,'--key-file',key,'--nonce-hex',PUBNONCE,'--allow-unsafe-nonce','--ad',ad,'--quiet')
      data=ct.read_bytes()
      assert data[8:12]==(5).to_bytes(4,'little'),'not v5'
      if size==4097:
        kat=(FIX/'v5_kat_sha256.txt').read_text().strip()
        assert hashlib.sha256(data).hexdigest()==kat,'v5 deterministic ciphertext KAT changed'
      assert data[16:48]==bytes.fromhex(PUBNONCE),'nonce not stored in salt'
      assert data[48:80]!=bytes.fromhex(PUBNONCE),'synthetic nonce equals public nonce'
      # Independent RFC 5869 + Python HMAC-SHA512 transcript implementation.
      public_salt=data[16:48]
      prk=hmac.digest(public_salt,bytes(range(128)), 'sha512')
      info=b'SymFrog-512 AEAD v5 | synthetic IV MAC key | HKDF-SHA-512'
      mac_key=hmac.digest(prk,info+b'\x01','sha512')
      canonical=data[:48]+bytes(32)+data[80:120]+bytes(32)
      domain=b'SymFrog-512 AEAD v5 | SIV transcript | header, AAD, plaintext'
      transcript=domain+canonical+len(bytes.fromhex(ad)).to_bytes(8,'little')+bytes.fromhex(ad)+payload
      assert data[48:80]==hmac.digest(mac_key,transcript,'sha512')[:32], 'C++ SIV differs from independent Python HMAC' 
      call('dec',ct,out,'--key-file',key,'--ad',ad,'--quiet')
      assert out.read_bytes()==payload
      reference.append((size,data))
    # Reusing the SAME public nonce under the SAME key and AAD with distinct plaintext
    # must NOT repeat the initial stream bytes. Specifically, C1^C2 != P1^P2.
    n=4096
    a=d/'a';b=d/'b';c=d/'c';a.write_bytes(b'\x00'*n);b.write_bytes(b'\xff'*n);c.write_bytes(b'\x00'*n)
    def enc(inp,out, aad=ad):
      call('enc',inp,out,'--key-file',key,'--nonce-hex',PUBNONCE,'--allow-unsafe-nonce','--ad',aad,'--quiet')
    enc(a,d/'ca');enc(b,d/'cb');enc(c,d/'cc')
    ca=(d/'ca').read_bytes();cb=(d/'cb').read_bytes();cc=(d/'cc').read_bytes()
    assert ca==cc, 'same input/nonce/key/AAD not deterministic'
    assert ca[48:80]!=cb[48:80], 'different plaintext same synthetic nonce'
    assert bytes(x^y for x,y in zip(ca[152:216],cb[152:216]))!=b'\xff'*64, 'reused keystream under nonce reuse'
    enc(a,d/'cad','01020305')
    assert ca[48:80]!=(d/'cad').read_bytes()[48:80], 'AAD not bound to SIV'
    # Any modified header, SIV, ciphertext or authentication tag must fail without
    # destroying an existing output; check also wrong key, wrong AD.
    target=d/'existing';target.write_bytes(b'PRESERVE ME')
    for pos in (8,16,48,80,119,151,152,152+n//2,152+n,152+n+31):
      tam=bytearray(ca);tam[pos]^=1;bad=d/f'tamper-{pos}';bad.write_bytes(tam)
      call('dec',bad,target,'--key-file',key,'--ad',ad,'--force','--quiet',accept=False)
      assert target.read_bytes()==b'PRESERVE ME', f'output destroyed on tamper {pos}'
    call('dec',d/'ca',target,'--key-file',key,'--ad','0a0b','--force','--quiet',accept=False)
    assert target.read_bytes()==b'PRESERVE ME'
    wrong=d/'wrong';wrong.write_bytes(bytes(reversed(range(128))));wrong.chmod(0o600)
    call('dec',d/'ca',target,'--key-file',wrong,'--ad',ad,'--force','--quiet',accept=False)
    assert target.read_bytes()==b'PRESERVE ME'
    # Frozen v4 ciphertext from the original audited binary remains decryptable.
    call('dec',FIX/'legacy_v4_rawkey.syf',d/'old','--key-file',key,'--ad','a1b2c3','--quiet')
    assert (d/'old').read_bytes()==(FIX/'legacy_v4_reference_plain.bin').read_bytes()
    print('PASS: v5-SIV lengths, nonce-reuse XOR property, deterministic replay, AAD/key/tamper, legacy v4')
if __name__=='__main__':main()
