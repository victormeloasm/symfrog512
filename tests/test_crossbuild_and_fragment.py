#!/usr/bin/env python3
"""Cross compiler, optimization, sanitizer, and read fragmentation regression tests."""
import hashlib, json, os, random, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
rng=random.Random(845301)
counts={'build_equivalence_cases':0,'fragmentation_cases':0,'sanitizer_cases':0,'password_cases':0}

def run(bin,args,env=None,expected=True,timeout=90):
    p=subprocess.run([str(bin), *[str(s) for s in args]],capture_output=True, env=env,timeout=timeout)
    assert (p.returncode==0)==expected, f'failed rc={p.returncode} args={args[:3]} stderr={p.stderr[:400]!r}'
    return p

def main():
    orig=ROOT/'symfrog512';clang3=ROOT/'build_clang_o3';clang0=ROOT/'build_clang_o0';gcc3=ROOT/'build_gcc_o3';san=ROOT/'build_clang_san'
    preloader=ROOT/'read_fragmentation.so'
    with tempfile.TemporaryDirectory(prefix='symfrog-build-frag-') as t:
        w=Path(t); inp=w/'in';out=w/'out';key=w/'key';password=w/'password'
        key.write_bytes(bytes(range(128))); key.chmod(0o600)
        password.write_bytes(b'correct horse battery staple 2026\n');password.chmod(0o600)
        rand_sizes=[rng.randint(0,8000) for _ in range(20)]
        sizes=[0,1,2,7,8,15,16,31,32,33,63,64,65,66,127,128,129,255,256,257,511,512,513,1023,1024,1025,4095,4096,4097,8191,8192,8193,65535,65536,65537,1048575,1048576,1048577]+rand_sizes
        sizes=sorted(set(sizes))
        quick = os.getenv('SYMFROG_BATTERY_QUICK') == '1'
        if quick:
            sizes=[0,1,31,63,64,65,128,129,4095,4096,4097,65537]
        for n in sizes:
            data=rng.randbytes(n);inp.write_bytes(data)
            ad=rng.randbytes(n%70).hex()
            nonce=bytes((1+(i+n)%255) for i in range(32)).hex()
            outputs=[]
            for b in [orig,clang3,clang0,gcc3]:
                ct=w/('ct_'+b.name)
                run(b,['enc',inp,ct,'--key-file',key,'--ad',ad,'--nonce-hex',nonce,'--allow-unsafe-nonce','--quiet','--force'])
                outputs.append(ct.read_bytes())
                p=run(b,['hash',inp]);outputs.append(bytes.fromhex(p.stdout.strip().decode()))
            assert len(set(outputs[::2]))==1, f'cipher discrepancy at length {n}'
            assert len(set(outputs[1::2]))==1, f'hash discrepancy at length {n}'
            counts['build_equivalence_cases']+=1
            # Compare actual decrypted content in a different build.
            run(gcc3,['dec',w/'ct_build_clang_o0',out,'--key-file',key,'--ad',ad,'--force','--quiet'])
            assert out.read_bytes()==data
        sizes_frag=[0,1,7,15,31,32,63,64,65,66,127,128,129,192,255,256,257,511,512,513,4095,4096,4097,65535,65536,65537,1048576,1048577]
        if quick:
            sizes_frag=[0,1,31,63,64,65,128,129,4097]
        for size in sizes_frag:
            data=rng.randbytes(size);inp.write_bytes(data)
            ref=run(orig,['hash',inp]).stdout
            ct=w/'fragref'
            run(orig,['enc',inp,ct,'--key-file',key,'--quiet','--force','--nonce-hex','01'*32,'--allow-unsafe-nonce'])
            expected_ct=ct.read_bytes()
            for block in [1,7,31,63,64,65,127]:
                env=os.environ.copy();env.update({'LD_PRELOAD':str(preloader),'SYMFROG_READ_CHUNK':str(block)})
                ctfrag=w/'frag.syf'
                run(orig,['enc',inp,ctfrag,'--key-file',key,'--quiet','--force','--nonce-hex','01'*32,'--allow-unsafe-nonce'],env=env)
                assert expected_ct==ctfrag.read_bytes(), f'encrypt read fragmentation bug len={size} chunk={block}'
                run(orig,['dec',ctfrag,out,'--key-file',key,'--quiet','--force'],env=env)
                assert data==out.read_bytes(), f'decrypt read fragmentation bug len={size} chunk={block}'
                out_hash=run(orig,['hash',inp],env=env).stdout
                assert ref==out_hash, f'hash read fragmentation bug len={size} chunk={block}'
                counts['fragmentation_cases']+=1
        for n in [0,1,31,32,63,64,65,127,128,129,4095,4096,65537]:
            data=rng.randbytes(n);inp.write_bytes(data)
            ct=w/'ct_san';
            env=os.environ.copy();env.update({'ASAN_OPTIONS':'detect_leaks=1:abort_on_error=1','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'})
            run(san,['enc',inp,ct,'--key-file',key,'--force','--quiet'],env)
            run(san,['dec',ct,out,'--key-file',key,'--force','--quiet'],env)
            assert out.read_bytes()==data
            run(san,['hash',inp],env=env)
            counts['sanitizer_cases']+=1
        # Check password-derived key, wrong pass, header format and roundtrip.
        inp.write_bytes(rng.randbytes(97));pwct=w/'pwct'
        run(orig,['enc',inp,pwct,'--pass-file',password,'--quiet'])
        assert pwct.read_bytes()[12:16]==(1).to_bytes(4,'little')
        assert pwct.read_bytes()[88:92]==b'KDF2'
        run(orig,['dec',pwct,out,'--pass-file',password,'--force','--quiet'])
        assert inp.read_bytes()==out.read_bytes()
        counts['password_cases']+=1
        wrong=w/'wrong';wrong.write_text('bad secret\n');wrong.chmod(0o600)
        run(orig,['dec',pwct,out,'--pass-file',wrong,'--force','--quiet'],expected=False)
        assert out.read_bytes()==inp.read_bytes(), 'wrong password overwrote an existing output'
        counts['password_cases']+=1
    print(json.dumps({'status':'PASS','counts':counts},indent=2))
    (ROOT/'battery_test_results').mkdir(parents=True, exist_ok=True)
    (ROOT/'battery_test_results'/'crossbuild_fragment_results.json').write_text(json.dumps({'status':'PASS','counts':counts},indent=2)+'\n')
if __name__=='__main__': main()
