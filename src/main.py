import sys, os, json, time, threading, argparse, re
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
        bundled = os.path.join(root, 'bin', 'windows', 'luau.exe')
    else:
        bundled = os.path.join(root, 'bin', 'ubuntu', 'luau')
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('-o', '--output', default='out')
    ap.add_argument('--luau', default=None)
    a = ap.parse_args()
    src = open(a.input, encoding='latin-1').read()
    err = []
    def work():
        try: pipeline(src, a.output, a.luau)
        except BaseException:
            import traceback; err.append(traceback.format_exc())
    th = threading.Thread(target=work)
    th.start(); th.join()
    if err:
        print(err[0]); sys.exit(1)

if __name__ == '__main__':
    main()
