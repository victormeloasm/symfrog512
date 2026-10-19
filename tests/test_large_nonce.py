#!/usr/bin/env python3
"""Large-file consistency, multi-megabyte streaming, and randomized nonce uniqueness smoke tests."""
import json,hashlib,os,subprocess,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
BIN=ROOT/'symfrog512'
def run(*argv):
    p=subprocess.run([str(BIN),*[str(v) for v in argv]],capture_output=True,timeout=180)
    assert p.returncode==0, f'rc={p.returncode} {p.stderr[:300]!r}'
    return p

def main():
    results={}
    with tempfile.TemporaryDirectory(prefix='symfrog-large-') as td:
        p=Path(td);inp=p/'in';ct=p/'ct';out=p/'out';key=p/'key'
        key.write_bytes(os.urandom(128));key.chmod(0o600)
        data=os.urandom(32*1024*1024+65)
        inp.write_bytes(data)
        st=time.monotonic()
        run('enc',inp,ct,'--key-file',key,'--quiet')
        run('dec',ct,out,'--key-file',key,'--quiet')
        assert hashlib.sha256(inp.read_bytes()).digest()==hashlib.sha256(out.read_bytes()).digest()
        assert len(ct.read_bytes())==len(data)+184
        results['large_file_bytes']=len(data)
        results['roundtrip_seconds']=round(time.monotonic()-st,3)
        # independent random-nonce smoke: each key/pt pair should produce a distinct header nonce
        inp.write_bytes(b'single-key repeated-message random nonce regression')
        nonces=set(); crypt=set()
        for i in range(1000):
            run('enc',inp,ct,'--key-file',key,'--quiet','--force')
            v=ct.read_bytes();nonce=v[16:48] # v5 public nonce, not the synthetic IV
            assert len(nonce)==32 and nonce!=bytes(32)
            assert nonce not in nonces, f'nonce repetition at trial {i}'
            nonces.add(nonce)
            assert v[152:] not in crypt, f'ciphertext+tag repetition at trial {i}'
            crypt.add(v[152:])
        results['distinct_nonce_trials']=1000
        results['unique_nonces']=len(nonces)
        results['unique_ciphertexts_and_tags']=len(crypt)
    results['status']='PASS'
    print(json.dumps(results,indent=2))
    (ROOT/'battery_test_results').mkdir(parents=True, exist_ok=True)
    (ROOT/'battery_test_results'/'large_nonce_results.json').write_text(json.dumps(results,indent=2)+'\n')
if __name__=='__main__':main()
