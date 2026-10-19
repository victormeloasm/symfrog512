#!/usr/bin/env python3
"""Additional independent black-box robustness and property tests for SymFrog AEAD format v5.
Does not modify the cryptographic construction. Python stdlib only.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import tempfile
import time

BIN = Path(__file__).resolve().parent.parent / 'symfrog512'
ROOT = BIN.parent
RNG = random.Random(0x5F06_2026)
counts: dict[str,int] = {}
notes: list[str] = []

def run(args, success=True, timeout=20):
    p = subprocess.run([str(BIN), *[str(a) for a in args]], capture_output=True, timeout=timeout)
    if (p.returncode == 0) != success:
        raise AssertionError(f'Unexpected return {p.returncode} args={args[:3]} stderr={p.stderr[:260]!r}')
    counts['processes'] = counts.get('processes', 0) + 1
    return p

def mark(name, n=1):
    counts[name] = counts.get(name,0) + n

def randbytes(n):
    return RNG.randbytes(n)

def vary_sizes():
    bases=[0,1,2,3,4,7,8,15,16,31,32,33,47,48,49,63,64,65,66,95,96,97,127,128,129,130,191,192,193,255,256,257,511,512,513,1023,1024,1025,4095,4096,4097,8191,8192,8193,65535,65536,65537,1<<20,(1<<20)-1,(1<<20)+1]
    extras=[RNG.randrange(0,65536) for _ in range(165)]
    return sorted(set(bases+extras))

def main():
    started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='symfrog-stress-') as t:
        work=Path(t)
        key1=randbytes(128)
        assert key1 != bytes(128)
        key2=randbytes(128)
        (work/'key1').write_bytes(key1); (work/'key2').write_bytes(key2)
        os.chmod(work/'key1',0o600); os.chmod(work/'key2',0o600)
        source=work/'plaintext'; cipher=work/'cipher.syf'; recovered=work/'recovered'
        aads=[b'',b'\x00',bytes(31), bytes(32),bytes(63),bytes(64),bytes(65),bytes(127), bytes(128),bytes(129), b'ABC',randbytes(1024)]
        sizes=vary_sizes()
        for i,n in enumerate(sizes):
            if i%7 == 0: data=bytes(n)
            elif i%7 == 1: data=b'\xff'*n
            elif i%7 == 2: data=(bytes(range(256))*((n+255)//256))[:n]
            elif i%7 == 3: data=b'\x80'*n
            else: data=randbytes(n)
            source.write_bytes(data)
            ad=aads[i%len(aads)].hex()
            opts=['--key-file',work/'key1','--quiet']
            if ad: opts.extend(['--ad',ad])
            run(['enc',source,cipher,*opts, '--force'])
            assert len(cipher.read_bytes()) == 184+n, 'wrong ciphertext file size'
            assert cipher.read_bytes()[8:12] == b'\x05\x00\x00\x00', 'incorrect v5 format marker'
            run(['dec',cipher,recovered,*opts,'--force'])
            assert recovered.read_bytes()==data, f'roundtrip failure at {n}'
            mark('roundtrip_sizes')
            # Hash consistency, deterministic on same input, and differs with size/content
            a=run(['hash',source]).stdout.strip()
            b=run(['hash',source]).stdout.strip()
            assert a==b and len(a)==128
            mark('hash_determinism')
        # Chosen-nonce deterministic ciphertext + seed perturbation, key/AAD semantics.
        source.write_bytes(randbytes(321))
        nonce1=bytes(range(1,33));nonce2=bytes(range(2,34))
        n1=nonce1.hex();n2=nonce2.hex()
        det1=work/'det1';det2=work/'det2';det3=work/'det3'
        base=['--key-file',work/'key1','--quiet','--allow-unsafe-nonce']
        run(['enc',source,det1,*base,'--nonce-hex',n1])
        run(['enc',source,det2,*base,'--nonce-hex',n1])
        run(['enc',source,det3,*base,'--nonce-hex',n2])
        assert det1.read_bytes()==det2.read_bytes()
        assert det1.read_bytes()!=det3.read_bytes()
        run(['enc',source,cipher,'--key-file',work/'key1','--nonce-hex',n1,'--quiet'], False)
        run(['enc',source,cipher,'--key-file',work/'key1','--allow-unsafe-nonce','--nonce-hex','00'*32,'--quiet'],False)
        run(['dec',det1,recovered,'--key-file',work/'key2','--quiet','--force'],False)
        mark('nonce_and_key_controls',6)
        # The legacy v3 XOR-compensation identity must NOT carry to v4.
        delta=randbytes(32)
        relatedkey=key1[:96]+bytes(x^y for x,y in zip(key1[96:],delta))
        related_nonce=bytes(x^y for x,y in zip(nonce1,delta))
        assert nonce1!=related_nonce and key1!=relatedkey
        (work/'related.key').write_bytes(relatedkey)
        os.chmod(work/'related.key',0o600)
        related=work/'related.syf'
        run(['enc',source,related,'--key-file',work/'related.key','--quiet',
             '--allow-unsafe-nonce','--nonce-hex',related_nonce.hex()])
        related_raw=related.read_bytes();det_raw=det1.read_bytes()
        assert related_raw[152:]!=det_raw[152:], 'v5 retains the v3 related-key/nonce equivalence'
        assert related_raw[:152]!=det_raw[:152], 'authenticated file headers should differ'
        notes.append('V5_RELATED_KEY_NONCE: XOR-compensated key/nonce pair has distinct ciphertext and tag; former v3 identity not observed.')
        mark('v5_related_key_nonce_rejection')
        # File mutation: every header byte, every tag byte and 100% of ciphertext in 257-byte sample.
        source.write_bytes(randbytes(257))
        run(['enc',source,cipher,'--key-file',work/'key1','--quiet','--force','--ad','012345'])
        good=cipher.read_bytes()
        assert len(good)==441
        tampered=work/'corrupt.syf'; target=work/'should-stay-unchanged'
        sentinel=b'PROTECTED DATA SHOULD NEVER BE REPLACED\n'
        for j in range(len(good)):
            corrupt=bytearray(good)
            corrupt[j]^=1<<(j%8)
            tampered.write_bytes(corrupt)
            target.write_bytes(sentinel)
            run(['dec',tampered,target,'--key-file',work/'key1','--ad','012345','--force','--quiet'],False)
            assert target.read_bytes()==sentinel, f'tamper commit at offset {j}'
            mark('all_byte_tamper_rejections')
        # Wrong AD, absent AD, incorrect keys and truncated files.
        target.write_bytes(sentinel)
        run(['dec',cipher,target,'--key-file',work/'key1','--force','--quiet'],False)
        run(['dec',cipher,target,'--key-file',work/'key2','--ad','012345','--force','--quiet'],False)
        run(['dec',cipher,target,'--key-file',work/'key1','--ad','012346','--force','--quiet'],False)
        assert target.read_bytes()==sentinel
        for j in [0,1,8,12,15,16,32,80,120,151,152,183,184,185,len(good)-33,len(good)-1]:
            tampered.write_bytes(good[:j])
            run(['dec',tampered,target,'--key-file',work/'key1','--ad','012345','--force','--quiet'],False)
            assert target.read_bytes()==sentinel
            mark('truncation_rejections')
        # Mutation fuzz: random edits and malformed headers, including oversized length declarations.
        for i in range(1200):
            if i%4==0:
                raw=bytearray(randbytes(RNG.choice([0,1,7,8,11,12,16,32,152,183,184,185,256,512,1024])))
            else:
                raw=bytearray(good)
                for _ in range(RNG.randint(1,8)):
                    off=RNG.randrange(len(raw));raw[off]^=RNG.randint(1,255)
                if i%7==0:
                    raw[80:88]=randbytes(8)
                elif i%7==1:
                    raw+=randbytes(RNG.randint(1,10))
            tampered.write_bytes(raw)
            run(['dec',tampered,target,'--key-file',work/'key1','--ad','012345','--quiet','--force'],False)
            assert target.read_bytes()==sentinel
            mark('mutational_fuzz_rejections')
        # File system hardlinks, input symlinks and output overwrite protection.
        source.write_bytes(b'inode test'*8)
        link=work/'hardlink'; os.link(source,link)
        run(['hash',source,'--out',link,'--force'],False)
        run(['enc',source,link,'--key-file',work/'key1','--force','--quiet'],False)
        assert source.read_bytes()==link.read_bytes()
        symlink=work/'symlink'; symlink.symlink_to(source)
        run(['hash',symlink],False)
        run(['enc',symlink,cipher,'--key-file',work/'key1','--force','--quiet'],False)
        mark('filesystem_rejections',4)
        # Key format rejections
        invalid_cases=[bytes(127),bytes(129),bytes(128),b'0123',bytes(256)]
        for i,bs in enumerate(invalid_cases):
            bad=work/('badkey'+str(i));bad.write_bytes(bs);os.chmod(bad,0o600)
            if i==2:
                bad.chmod(0o644)
            run(['enc',source,cipher,'--key-file',bad,'--quiet','--force'],False)
            mark('malformed_key_rejections')
        # One-bit avalanche in hash output; analyze independent random input trials.
        hds=[]; hash_prefixes=set()
        for i in range(256):
            data=randbytes(64)
            j=RNG.randrange(512)
            perturbed=bytearray(data);perturbed[j>>3]^=1<<(j%8)
            source.write_bytes(data)
            ha=bytes.fromhex(run(['hash',source]).stdout.strip().decode())
            source.write_bytes(perturbed)
            hb=bytes.fromhex(run(['hash',source]).stdout.strip().decode())
            hd=sum((x^y).bit_count() for x,y in zip(ha,hb))
            hds.append(hd)
            assert ha!=hb, 'observed hash collision for one-bit difference'
            hash_prefixes.add(ha[:16]);hash_prefixes.add(hb[:16])
            mark('hash_avalanche_pairs')
        assert len(hash_prefixes)==512
        mean_hd=statistics.mean(hds)
        assert 245 <=mean_hd <=267, f'hash avalanche gross bias: mean={mean_hd}'
        notes.append(f'HASH_AVALANCHE_256_PAIRS: mean HD={mean_hd:.3f}/512, min={min(hds)}, max={max(hds)}, sample_sd={statistics.stdev(hds):.3f}. Exploratory only.')
    out={'status':'PASS','counts':counts,'notes':notes,'wall_seconds':round(time.monotonic()-started,2),'source_sha256':hashlib.sha256((ROOT/'src/symfrog512.cpp').read_bytes()).hexdigest()}
    output=ROOT/'battery_test_results'/'stress_battery_results.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out,indent=2))

if __name__=='__main__':
    main()
