import sys, os, json, time, threading, argparse, re, subprocess
sys.setrecursionlimit(1000000)
for _sz in (64*1024*1024, 32*1024*1024, 16*1024*1024):
    try:
        threading.stack_size(_sz)
        break
    except BaseException:
        pass
from lemit import B
from luai import make_interp, Scope, LuaTable
from payload import lz
import payload as pv
from stages import front, payload_of
import detect
import vmdecode
import shutil
import innerdump
from vmdecode import decode_proto, validate, disasm
from vmhandlers import dump_all
from layout import extract_layout
from classifier import build_classifier
from lift import lift, STATS
from structure import fix

def topy(v):
    if isinstance(v, LuaTable):
        return {('B', k[1] == 1) if isinstance(k, tuple) else k: topy(x) for k, x in v.h.items()}
    return v

def jsonable(v):
    if isinstance(v, dict):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, bytes):
        return v.hex()
    return v

def needs_lz(ast, b64):
    text = B([ast[-1]])
    alias = detect.find_interpreter_alias(ast)
    m = re.search(r"([A-Za-z_]\w*)\(" + re.escape(b64) + r"\('", text)
    if not m:
        return False
    return m.group(1) != alias

def build_proto(ast, raw, use_lz, des):
    it = make_interp()
    sc = Scope()
    skipped = []
    for i, st in enumerate(ast):
        if st[0] not in ('local', 'localfunc', 'assign'):
            continue
        try:
            it.stat(st, sc)
        except BaseException:
            skipped.append(i)
    data = lz(raw) if use_lz else raw
    proto = it.call(sc.v[des], [data])[0]
    return topy(proto), data, skipped

def find_luau(arg):
    if arg:
        return arg
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if sys.platform.startswith('win'):
        names = ('windows/luau.exe', 'luau.exe')
    else:
        names = ('ubuntu/luau', 'luau')
    for n in names:
        bundled = os.path.join(root, 'bin', *n.split('/'))
        if os.path.isfile(bundled):
            if not os.access(bundled, os.X_OK):
                try:
                    os.chmod(bundled, 0o755)
                except OSError:
                    pass
            if os.access(bundled, os.X_OK):
                return bundled
    return shutil.which('luau')

def pipeline(src, out, luau=None):
    os.makedirs(out, exist_ok=True)
    for fname in ('final.lua', 'lifted.lua', 'disasm.txt', 'handlers.txt', 'proto.json', 'proto_inner.json', 'payload.bin', 'stage_strings.lua'):
        fpath = os.path.join(out, fname)
        if os.path.isfile(fpath):
            try: os.remove(fpath)
            except BaseException: pass
    def save(name, text, enc='latin-1'):
        with open(os.path.join(out, name), 'w', encoding=enc) as f: f.write(text)
    from lparse import parse
    initial_ast = parse(src)
    b64_detected = detect.find_b64(initial_ast)
    if not b64_detected:
        from ast_deobf import deobfuscate_ast
        return deobfuscate_ast(src, out)
    ast, sd, b64 = front(src)
    save('stage_strings.lua', B(ast))
    des = detect.find_deserializer(ast)
    if not des:
        raise Exception('payload deserializer not found')
    raw = payload_of(ast, b64)
    use_lz = needs_lz(ast, b64)
    print('string decoder: %s, base64 decoder: %s, deserializer: %s' % (sd, b64, des))
    print('payload: %d bytes, compression layer: %s' % (len(raw), 'yes' if use_lz else 'no'))
    t = time.time()
    proto, data, skipped = build_proto(ast, raw, use_lz, des)
    with open(os.path.join(out, 'payload.bin'), 'wb') as f: f.write(data)
    print('payload deserialized in %.1fs' % (time.time() - t))
    pj = jsonable(proto)
    with open(os.path.join(out, 'proto.json'), 'w') as f: json.dump(pj, f)
    target = pj
    luau = find_luau(luau)
    if luau:
        dumps, err = innerdump.run(src, os.path.join(out, 'inner'), luau)
        print('deserializer calls observed: %s' % [x[1] for x in dumps])
        if len(dumps) > 1:
            last = dumps[-1][0]
            data = open(os.path.join(out, 'inner', 'inner_%d.bin' % last), 'rb').read()
            proto2, _, _ = build_proto(ast, data, False, des)
            target = jsonable(proto2)
            with open(os.path.join(out, 'proto_inner.json'), 'w') as f: json.dump(target, f)
            print('inner layer deserialized: %d bytes' % len(data))
    h_path = os.path.join(out, 'handlers.txt')
    try:
        n = dump_all(ast, h_path)
        print('handler groups: %d' % n)
    except BaseException as e:
        print('handler dump unavailable: %s' % e)
    if not os.path.isfile(h_path):
        print('handlers file not found; decoding skipped')
        return None
    h_text = open(h_path, encoding='latin-1').read()
    fld, proto_keys = extract_layout(ast, target, h_text)
    profile = build_classifier(h_path, fld, proto_keys)
    root = decode_proto(target, fld, proto_keys, profile)
    bad, unk = validate(root)
    print('bad jump targets: %d' % len(bad))
    print('unknown instructions: %d' % len(unk))
    save('disasm.txt', '\n'.join(disasm(root)) + '\n')
    lifted = lift(root)
    save('lifted.lua', lifted, 'utf-8')
    final, left = fix(lifted)
    save('final.lua', final, 'utf-8')
    print('functions: %d, instructions: %d' % (STATS['functions'], STATS['instructions']))
    print('goto/label left: %d' % left)
    print('lines: %d' % final.count('\n'))
    return final

KNOWN_ENTRY = ('a.q,a.m,a.t,a.v,a.y = a:q(),a:m(),a:t(),a:v(),a:y()', 'a.F = a:F()', 'return a:k()(...)')

RUN_KNOWN = '''T.q, T.m, T.t, T.v, T.y = T:q(), T:m(), T:t(), T:v(), T:y()
T.F = T:F()
T.v = wrap("DECRYPT", T.v)
T.y = wrap("HASH", T.y)
local fn = T:k()
local ok, err = pcall(fn)
print("RESULT", tostring(ok), tostring(err))'''

RUN_PLAIN = '''local ok, err = pcall(T.@@ENTRY@@, T)
print("RESULT", tostring(ok), tostring(err))'''

def write(path, data, mode='w'):
    if mode == 'w':
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(data)
    else:
        with open(path, 'wb') as f:
            f.write(data)


def unpack_stage(text, out):
    method, items, names, entry = pv.container(text)
    mul, add = pv.mapping_constants(items)
    mem = pv.members(items, names, mul, add)
    os.makedirs(os.path.join(out, 'members'), exist_ok=True)
    for name, code in mem.items():
        write(os.path.join(out, 'members', name + '.lua'), code)
    write(os.path.join(out, 'names.json'), json.dumps({'method': method, 'entry': entry, 'multiplier': mul, 'addend': add, 'names': names}, indent=2))
    payload, alphabet = pv.find_payload(text)
    info = {'entry': entry, 'members': len(mem), 'multiplier': mul, 'addend': add}
    if alphabet:
        raw = pv.b85_decode(payload, alphabet)
        data = pv.lz_decompress(raw)
        write(os.path.join(out, 'payload_b85.bin'), raw, 'b')
        write(os.path.join(out, 'payload_lz.bin'), data, 'b')
        info['payload_chars'] = len(payload)
        info['payload_b85_bytes'] = len(raw)
        info['payload_lz_bytes'] = len(data)
    return method, mem, entry, mul, add, info


def runtime_stage(text, out, method, mem, entry, mul, add, luau, timeout):
    table, names = pv.table_and_names(text, method, entry)
    entry_code = mem.get(entry, '')
    known = all(part in entry_code for part in KNOWN_ENTRY)
    run = RUN_KNOWN if known else RUN_PLAIN.replace('@@ENTRY@@', entry)
    tpl = innerdump.V2_SANDBOX
    driver = tpl.replace('@@TABLE@@', table).replace('@@NAMES@@', names).replace('@@MUL@@', str(mul)).replace('@@ADD@@', str(add)).replace('@@RUN@@', run)
    path = os.path.join(out, 'sandbox_run.lua')
    with open(path, 'w', encoding='latin-1', newline='\n') as f:
        f.write(driver)
    proc = subprocess.run([os.path.abspath(luau), 'sandbox_run.lua'], cwd=out, capture_output=True, timeout=timeout)
    stdout = proc.stdout.decode('latin-1', errors='replace')
    trace, decrypts, hashes, printed, result = [], [], [], [], None
    for line in stdout.split('\n'):
        parts = line.rstrip('\r').split('\t')
        if parts[0] == 'TRACE':
            trace.append('\t'.join(parts[1:]))
        elif parts[0] == 'DECRYPT' and len(parts) >= 5:
            decrypts.append({'ciphertext': parts[1], 'nonce': parts[2], 'key': parts[3], 'plaintext': parts[4]})
        elif parts[0] == 'HASH' and len(parts) >= 3:
            hashes.append({'input': parts[1], 'output': parts[2]})
        elif parts[0] == 'RESULT':
            result = {'ok': parts[1] == 'true', 'value': parts[2] if len(parts) > 2 else ''}
        elif line.strip():
            printed.append(line.rstrip('\r'))
    write(os.path.join(out, 'trace.txt'), '\n'.join(trace) + '\n')
    write(os.path.join(out, 'decrypts.json'), json.dumps(decrypts, indent=2))
    write(os.path.join(out, 'hashes.json'), json.dumps(hashes, indent=2))
    write(os.path.join(out, 'output.txt'), '\n'.join(printed) + '\n')
    os.makedirs(os.path.join(out, 'stages'), exist_ok=True)
    for i, d in enumerate(decrypts, 1):
        pt = bytes.fromhex(d['plaintext'])
        write(os.path.join(out, 'stages', 'stage_%d.bin' % i), pt, 'b')
        if len(pt) > 16:
            write(os.path.join(out, 'stages', 'stage_%d_lz.bin' % i), pv.lz_decompress(pt), 'b')
    return {'known_entry': known, 'trace_lines': len(trace), 'decrypt_calls': len(decrypts), 'hash_calls': len(hashes), 'decrypted_bytes': sum(len(d['plaintext']) // 2 for d in decrypts), 'printed_lines': len(printed), 'result': result, 'stderr': proc.stderr.decode('latin-1', errors='replace')[:500]}

def pipeline_v2(text, out, luau, timeout, no_run):
    os.makedirs(out, exist_ok=True)
    method, mem, entry, mul, add, info = unpack_stage(text, out)
    summary = {'unpack': info}
    print('members: %d, entry: %s' % (info['members'], entry))
    if 'payload_lz_bytes' in info:
        print('payload: %d chars -> %d bytes -> %d bytes after LZ' % (info['payload_chars'], info['payload_b85_bytes'], info['payload_lz_bytes']))
    if not no_run:
        luau = find_luau(luau)
        if not luau:
            print('luau binary not found, skipping runtime stage')
        else:
            rt = runtime_stage(text, out, method, mem, entry, mul, add, luau, timeout)
            summary['runtime'] = rt
            print('runtime: %d trace lines, %d decrypt calls, result=%s' % (rt['trace_lines'], rt['decrypt_calls'], rt['result']))
            if rt['decrypted_bytes'] * 4 < info.get('payload_lz_bytes', 0):
                print('note: only %d of %d payload bytes were decrypted, the script probably took an anti-tamper fallback path' % (rt['decrypted_bytes'], info['payload_lz_bytes']))
            if rt['printed_lines']:
                print('script output saved to output.txt (%d lines)' % rt['printed_lines'])
    write(os.path.join(out, 'summary.json'), json.dumps(summary, indent=2))
    return summary

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('-o', '--output', default='out')
    ap.add_argument('--luau', default=None)
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--no-run', action='store_true')
    a = ap.parse_args()
    src = open(a.input, encoding='latin-1').read()
    err = []
    def work():
        try:
            if pv.is_v2(src):
                print('detected: MoonVeil v2')
                pipeline_v2(src, a.output, a.luau, a.timeout, a.no_run)
            else:
                print('detected: MoonVeil v1')
                pipeline(src, a.output, a.luau)
        except BaseException:
            import traceback; err.append(traceback.format_exc())
    th = threading.Thread(target=work)
    th.start(); th.join()
    if err:
        print(err[0]); sys.exit(1)

if __name__ == '__main__':
    main()
