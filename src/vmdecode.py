import json, sys, os

PREFIX = bytes([220, 166, 237, 73, 32, 150, 88])
FLD = {'op': '37378', 'A': '14498', 'B': '54125', 'C': '54162', 'sD': '23764', 'D': '42346', 'sE': '56293', 'aux': '59799', 'k1': '31081', 'k2': '7867', 'k3': '53849', 'f1': '60329', 'kind': '62742'}
PROTO = {'code': '41691', 'children': '41625', 'nparams': '43677', 'nslots': '31905', 'nups': '4665', 'name': '62275'}
STUBS = {
    51: {105: (73, 249, 32), 235: (208, 125, 20), 238: (28, 194, 220), 254: (184, 203, 70)},
    73: {14: (48, 80, 148), 27: (51, 243, 218), 41: (98, 240, 73)},
    98: {52: (246, 24, 180), 110: (210, 170, 163), 250: (57, 165, 39)},
}

def xor_decrypt(data, key, prefix=PREFIX):
    k = prefix + key
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

def hexbytes(v):
    if isinstance(v, str):
        return bytes.fromhex(v)
    return None

def s16(v):
    if v is None:
        return 0
    v &= 0xFFFF
    return v if v < 32768 else v - 65536

def get(q, name, fld=FLD):
    v = q.get(fld[name], 0)
    return 0 if v is None else v

def raw_list(proto, proto_keys=PROTO):
    items = proto[proto_keys['code']]
    out = []
    for k in sorted(items, key=int):
        q = items[k]
        if q:
            d = dict(q)
            d['pc'] = int(k)
            out.append(d)
    return out

def child_keys(proto, proto_keys=PROTO):
    return sorted(proto[proto_keys['children']], key=int)

def decrypt_pass(raw, fld=FLD, profile=None):
    prefix = profile.get('prefix', PREFIX) if profile else PREFIX
    p_single = profile.get('pre_decrypt_single', {211}) if profile else {211}
    p_multi = profile.get('pre_decrypt_multi', {118}) if profile else {118}
    k1_fld = fld['k1']
    k2_fld = fld.get('k2')
    k3_fld = fld.get('k3')
    kind_fld = fld.get('kind')
    
    for i, q in enumerate(raw):
        op = get(q, 'op', fld)
        if op in p_single and i + 1 < len(raw):
            t = raw[i + 1]
            a = hexbytes(t.get(k1_fld))
            k = hexbytes(q.get(k1_fld))
            if a is not None and k is not None:
                t[k1_fld] = xor_decrypt(a, k, prefix).decode('latin-1')
                t['dec'] = True
            q['nop'] = True
        elif op in p_multi and i + 1 < len(raw):
            t = raw[i + 1]
            n = get(q, 'kind', fld) if kind_fld else 0
            slots = [k1_fld]
            if n >= 2 and k2_fld: slots.append(k2_fld)
            if n >= 3 and k3_fld: slots.append(k3_fld)
            for s in slots:
                a = hexbytes(t.get(s))
                k = hexbytes(q.get(s))
                if a is not None and k is not None:
                    t[s] = xor_decrypt(a, k, prefix).decode('latin-1')
            q['nop'] = True

def capture_pass(raw, proto, fld=FLD, proto_keys=PROTO, profile=None):
    closure_rules = profile.get('closure_rules', {}) if profile else {}
    if not closure_rules:
        closure_rules = {160: {'type': 'D', 'd_xor': 53671, 'a_xor': 56}, 209: {'type': 'K', 'a_xor': 0}}
    skip = set()
    children = proto.get(proto_keys['children'], {})
    nups_k = proto_keys['nups']
    
    for i, q in enumerate(raw):
        op = get(q, 'op', fld)
        if op in closure_rules:
            rule = closure_rules[op]
            if rule['type'] == 'D':
                idx = s16(get(q, 'D', fld) ^ rule.get('d_xor', 0))
            else:
                idx = get(q, 'k1', fld)
            ck = str(idx + 1)
            child = children.get(ck)
            n = child[nups_k] if child and nups_k in child else 0
            caps = []
            for j in range(1, n + 1):
                if i + j < len(raw):
                    c = raw[i + j]
                    caps.append((get(c, 'A', fld), get(c, 'B', fld)))
                    skip.add(i + j)
            q['caps'] = caps
            q['child_key'] = ck
    return skip

def expand(q, fld=FLD, profile=None):
    op = get(q, 'op', fld)
    c = get(q, 'C', fld)
    stubs = profile.get('stubs', STUBS) if profile else STUBS
    t = stubs.get(op, {}).get(c)
    if t:
        nop, xa, xb = t
        n = dict(q)
        n[fld['op']] = nop
        n[fld['A']] = get(q, 'A', fld) ^ xa
        n[fld['B']] = get(q, 'B', fld) ^ xb
        n[fld['C']] = 0
        return n
    return q

def target(q, off):
    return q['pc'] + 1 + off

def norm(q, proto, fld=FLD, proto_keys=PROTO, profile=None):
    op = get(q, 'op', fld)
    pc = q['pc']
    r = {'pc': pc}
    
    if profile and profile.get('op_map') and op in profile['op_map']:
        info = profile['op_map'][op]
        kind = info[0]
        if kind == 'MOVE':
            r.update(op='MOVE', a=q.get(info[1], 0), b=q.get(info[2], 0))
        elif kind == 'LOADNIL':
            r.update(op='LOADNIL', a=q.get(info[1], 0))
        elif kind == 'LOADB':
            r.update(op='LOADB', a=q.get(info[1], 0), value=(q.get(info[2], 0) == 1), target=target(q, s16(q.get(info[3], 0))))
        elif kind == 'LOADN':
            d_xor, a_xor = profile.get('loadn_rules', {}).get(op, (0, 0))
            r.update(op='LOADN', a=get(q, 'A', fld) ^ a_xor, value=s16(get(q, 'D', fld) ^ d_xor))
        elif kind == 'LOADK':
            r.update(op='LOADK', a=q.get(info[1], 0), k=q.get(fld['k1']))
        elif kind == 'GETUPVAL':
            r.update(op='GETUPVAL', a=q.get(info[1], 0), u=q.get(info[2], 0))
        elif kind == 'SETUPVAL':
            r.update(op='SETUPVAL', a=q.get(info[1], 0), u=q.get(info[2], 0))
        elif kind == 'GETIMPORT':
            path = [q.get(fld['k1'])]
            n = get(q, 'kind', fld)
            if n >= 2: path.append(q.get(fld['k2']))
            if n >= 3: path.append(q.get(fld['k3']))
            r.update(op='GETIMPORT', a=q.get(info[1], 0), path=path)
        elif kind == 'SETGLOBAL':
            r.update(op='SETGLOBAL', k=q.get(fld['k1']), v=q.get(info[2], 0))
        elif kind == 'GETTABLE':
            r.update(op='GETTABLE', a=q.get(info[1], 0), t=q.get(info[2], 0), k=q.get(info[3], 0))
        elif kind == 'SETTABLE':
            r.update(op='SETTABLE', t=q.get(info[1], 0), k=q.get(info[2], 0), v=q.get(info[3], 0))
        elif kind == 'GETFIELD':
            r.update(op='GETFIELD', a=q.get(info[1], 0), t=q.get(info[2], 0), k=q.get(fld['k1']))
        elif kind == 'SETFIELD':
            r.update(op='SETFIELD', t=q.get(info[1], 0), k=q.get(fld['k1']), v=q.get(info[2], 0))
        elif kind == 'GETTABLEN':
            r.update(op='GETTABLEN', a=q.get(info[1], 0), t=q.get(info[2], 0), n=q.get(info[3], 0) + 1)
        elif kind == 'SETTABLEN':
            r.update(op='SETTABLEN', t=q.get(info[1], 0), n=q.get(info[2], 0) + 1, v=q.get(info[3], 0))
        elif kind == 'NAMECALL':
            r.update(op='NAMECALL', a=q.get(info[1], 0), o=q.get(info[2], 0), k=q.get(fld['k1']))
        elif kind == 'CALL':
            c_rule = profile.get('call_rules', {}).get(op, [])
            if len(c_rule) >= 3:
                a = q.get(str(c_rule[0][0]), 0) ^ c_rule[0][1]
                nargs = (q.get(str(c_rule[1][0]), 0) ^ c_rule[1][1]) - 1
                nres = (q.get(str(c_rule[2][0]), 0) ^ c_rule[2][1]) - 1
            else:
                a = get(q, 'A', fld)
                nargs = get(q, 'B', fld) - 1
                nres = get(q, 'C', fld) - 1
            r.update(op='CALL', a=a, nargs=nargs, nres=nres)
        elif kind == 'RETURN':
            r.update(op='RETURN', a=q.get(info[1], 0), n=q.get(info[2], 0) - 1)
        elif kind == 'GETVARARGS':
            r.update(op='GETVARARGS', a=q.get(info[1], 0), n=q.get(info[2], 0) - 1)
        elif kind == 'NEWTABLE':
            r.update(op='NEWTABLE', a=q.get(info[1], 0), size=q.get(fld['aux'], 0))
        elif kind == 'SETLIST':
            r.update(op='SETLIST', t=q.get(info[1], 0), src=q.get(info[2], 0), n=q.get(info[3], 0) - 1, start=q.get(fld['aux'], 0))
        elif kind == 'CONCAT':
            r.update(op='CONCAT', a=q.get(info[1], 0), first=q.get(info[2], 0), last=q.get(info[3], 0))
        elif kind in ('ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW'):
            r.update(op=kind, a=q.get(info[1], 0), b=q.get(info[2], 0), c=q.get(info[3], 0))
        elif kind in ('ADDK', 'SUBK', 'MULK', 'DIVK', 'MODK', 'POWK'):
            r.update(op=kind, a=q.get(info[1], 0), b=q.get(info[2], 0), k=q.get(fld['k1']))
        elif kind == 'SUBRK':
            r.update(op='SUBRK', a=q.get(info[1], 0), b=q.get(info[2], 0), k=q.get(fld['k1']))
        elif kind == 'NOT':
            r.update(op='NOT', a=q.get(info[1], 0), b=q.get(info[2], 0))
        elif kind == 'LEN':
            r.update(op='LEN', a=q.get(info[1], 0), b=q.get(info[2], 0))
        elif kind == 'ORK':
            r.update(op='ORK', a=q.get(info[1], 0), b=q.get(info[2], 0), k=q.get(fld['k1']))
        elif kind == 'JUMP':
            r.update(op='JUMP', target=target(q, get(q, 'sD', fld)))
        elif kind == 'FORGPREP':
            r.update(op='FORGPREP', a=q.get(info[1], 0), target=target(q, get(q, 'sD', fld)))
        elif kind == 'FORGLOOP':
            r.update(op='FORGLOOP', a=q.get(info[1], 0), nvars=q.get(info[2], 0), target=target(q, get(q, 'sD', fld)))
        elif kind == 'FORNPREP':
            r.update(op='FORNPREP', a=q.get(info[1], 0), target=target(q, get(q, 'sD', fld)))
        elif kind == 'FORNLOOP':
            r.update(op='FORNLOOP', a=q.get(info[1], 0), target=target(q, get(q, 'sD', fld)))
        elif kind == 'JUMPIF':
            r.update(op='JUMPIF', a=q.get(info[1], 0), target=target(q, get(q, 'sD', fld)))
        elif kind == 'JUMPIFNOT':
            r.update(op='JUMPIFNOT', a=q.get(info[1], 0), target=target(q, get(q, 'sD', fld)))
        elif kind in ('JUMPIFEQ', 'JUMPIFNOTEQ', 'JUMPIFLT', 'JUMPIFNOTLT', 'JUMPIFLE', 'JUMPIFNOTLE'):
            r.update(op=kind, a=q.get(info[1], 0), b=q.get(fld['aux'], 0), target=target(q, get(q, 'sD', fld)))
        elif kind in ('JUMPEQK', 'JUMPEQB'):
            r.update(op=kind, a=q.get(info[1], 0), k=q.get(fld['k1']), neg=bool(q.get(fld['f1'], 0)), target=target(q, get(q, 'sD', fld)))
        elif kind == 'JUMPNIL':
            r.update(op='JUMPNIL', a=q.get(info[1], 0), neg=bool(q.get(fld['f1'], 0)), target=target(q, get(q, 'sD', fld)))
        elif kind.startswith('CLOSURE'):
            rule = profile.get('closure_rules', {}).get(op, {})
            a_xor = rule.get('a_xor', 0)
            r.update(op='CLOSURE', a=get(q, 'A', fld) ^ a_xor, child=q.get('child_key'), caps=q.get('caps', []))
        elif kind == 'CLOSEUPVALS':
            r.update(op='CLOSEUPVALS', a=q.get(info[1], 0))
        elif kind == 'NOP':
            r.update(op='NOP')
        else:
            r.update(op='UNKNOWN', raw=op)
        return r
        
    A = get(q, 'A', fld); B = get(q, 'B', fld); C = get(q, 'C', fld); sD = get(q, 'sD', fld); k1 = q.get(fld['k1'], None)
    if op == 48: r.update(op='MOVE', a=A, b=B)
    elif op == 98: r.update(op='LOADNIL', a=A)
    elif op == 235: r.update(op='LOADB', a=B, value=(C == 1), target=target(q, A))
    elif op == 166: r.update(op='LOADN', a=A ^ 58, value=s16(get(q, 'D', fld) ^ 4134))
    elif op == 200: r.update(op='LOADK', a=A, k=k1)
    elif op == 28: r.update(op='GETUPVAL', a=A, u=B)
    elif op == 208: r.update(op='SETUPVAL', a=A, u=B)
    elif op == 80:
        path = [k1]
        n = get(q, 'kind', fld)
        if n >= 2: path.append(q.get(fld['k2']))
        if n >= 3: path.append(q.get(fld['k3']))
        r.update(op='GETIMPORT', a=A, path=path)
    elif op == 18: r.update(op='GETTABLE', a=C, t=B, k=A)
    elif op in (247, 246): r.update(op='GETFIELD', a=B, t=A, k=k1)
    elif op == 41: r.update(op='GETTABLEN', a=A, t=C, n=B + 1)
    elif op == 230: r.update(op='SETFIELD', t=C, k=k1, v=B)
    elif op == 70: r.update(op='NAMECALL', a=B, o=A, k=k1)
    elif op == 60: r.update(op='CALL', a=C ^ 93, nargs=(A ^ 206) - 1, nres=(B ^ 53) - 1)
    elif op == 51: r.update(op='RETURN', a=A, n=B - 1)
    elif op == 73: r.update(op='GETVARARGS', a=A, n=B - 1)
    elif op == 54: r.update(op='NEWTABLE', a=A, size=q.get(fld['aux'], 0))
    elif op == 124: r.update(op='SETLIST', t=C, src=A, n=B - 1, start=q.get(fld['aux'], 0))
    elif op == 1: r.update(op='CONCAT', a=C, first=A, last=B)
    elif op == 149: r.update(op='ADD', a=B, b=C, c=A)
    elif op == 127: r.update(op='SUB', a=C, b=A, c=B)
    elif op == 36: r.update(op='MUL', a=A, b=C, c=B)
    elif op == 66: r.update(op='DIV', a=C, b=A, c=B)
    elif op == 145: r.update(op='ADDK', a=B, b=A, k=k1)
    elif op == 213: r.update(op='SUBK', a=B, b=A, k=k1)
    elif op == 147: r.update(op='MULK', a=B, b=C, k=k1)
    elif op == 102: r.update(op='SUBRK', a=B, k=k1, b=A)
    elif op == 210: r.update(op='NOT', a=A, b=B)
    elif op == 57: r.update(op='LEN', a=A, b=B)
    elif op == 156: r.update(op='ORK', a=C, b=A, k=k1)
    elif op == 100: r.update(op='JUMP', target=target(q, sD))
    elif op == 32: r.update(op='FORGPREP', a=A, target=target(q, sD))
    elif op == 86: r.update(op='JUMPIF', a=A, target=target(q, sD))
    elif op == 250: r.update(op='JUMPIFNOT', a=A, target=target(q, sD))
    elif op == 46: r.update(op='JUMPIFEQ', a=A, b=q.get(fld['aux'], 0), target=target(q, sD))
    elif op == 83: r.update(op='JUMPIFNOTEQ', a=A, b=q.get(fld['aux'], 0), target=target(q, sD))
    elif op == 84: r.update(op='JUMPIFNOTLT', a=A, b=q.get(fld['aux'], 0), target=target(q, sD))
    elif op == 238: r.update(op='JUMPIFNOTLE', a=A, b=q.get(fld['aux'], 0), target=target(q, sD))
    elif op == 56: r.update(op='JUMPEQK', a=A, k=k1, neg=bool(q.get(fld['f1'], 0)), target=target(q, sD))
    elif op == 126: r.update(op='JUMPNIL', a=A, neg=bool(q.get(fld['f1'], 0)), target=target(q, sD))
    elif op == 169: r.update(op='JUMPEQB', a=A, k=k1, neg=bool(q.get(fld['f1'], 0)), target=target(q, sD))
    elif op == 50: r.update(op='FORNPREP', a=A, target=target(q, sD))
    elif op == 179: r.update(op='FORNLOOP', a=A, target=target(q, sD))
    elif op == 25: r.update(op='FORGLOOP', a=A, nvars=k1, target=target(q, sD))
    elif op == 160: r.update(op='CLOSURE', a=A ^ 56, child=q['child_key'], caps=q['caps'])
    elif op == 209: r.update(op='CLOSURE', a=A, child=q['child_key'], caps=q['caps'])
    elif op in (180, 181, 182, 183, 184): r.update(op='CLOSEUPVALS', a=A)
    elif op in (2, 78, 188): r.update(op='NOP')
    else: r.update(op='UNKNOWN', raw=op, A=A, B=B, C=C, sD=sD)
    return r

def remap_targets(code):
    pcs = sorted(c['pc'] for c in code)
    import bisect
    last = pcs[-1] + 1 if pcs else 0
    for c in code:
        t = c.get('target')
        if t is None:
            continue
        i = bisect.bisect_left(pcs, t)
        c['target'] = pcs[i] if i < len(pcs) else last

def decode_proto(proto, fld=None, proto_keys=None, profile=None):
    if fld is None:
        fld = FLD
    if proto_keys is None:
        proto_keys = PROTO
    raw = raw_list(proto, proto_keys)
    decrypt_pass(raw, fld, profile)
    skip = capture_pass(raw, proto, fld, proto_keys, profile)
    code = []
    for i, q in enumerate(raw):
        if i in skip:
            continue
        if q.get('nop'):
            continue
        q = expand(q, fld, profile)
        n = norm(q, proto, fld, proto_keys, profile)
        if n['op'] == 'NOP':
            continue
        code.append(n)
    remap_targets(code)
    children = {k: decode_proto(proto[proto_keys['children']][k], fld, proto_keys, profile) for k in child_keys(proto, proto_keys)}
    return {
        'name': proto.get(proto_keys['name'], ''),
        'nparams': proto[proto_keys['nparams']],
        'nslots': proto[proto_keys['nslots']],
        'nups': proto[proto_keys['nups']],
        'code': code,
        'children': children
    }

def validate(p, path='0'):
    pcs = {c['pc'] for c in p['code']}
    bad = []
    for c in p['code']:
        t = c.get('target')
        if t is not None and t not in pcs and t <= max(pcs) + 1:
            bad.append((path, c['pc'], c['op'], t))
    unk = [(path, c['pc'], c['raw']) for c in p['code'] if c['op'] == 'UNKNOWN']
    for k, ch in p['children'].items():
        b, u = validate(ch, path + '.' + k)
        bad += b
        unk += u
    return bad, unk

def fmtk(v):
    if isinstance(v, str):
        return repr(v)
    return str(v)

def fmt_instr(c):
    parts = [c['op']]
    for k, v in c.items():
        if k in ('pc', 'op'):
            continue
        if k == 'caps':
            v = ','.join('%d:%d' % x for x in v)
        elif k in ('k', 'path'):
            v = fmtk(v) if k == 'k' else '.'.join(fmtk(x) for x in v)
        parts.append('%s=%s' % (k, v))
    return '%04d  %s' % (c['pc'], ' '.join(parts))

def disasm(p, path='0', depth=0, out=None):
    out = [] if out is None else out
    pad = '  ' * depth
    out.append('%sproto %s: params=%d slots=%d ups=%d instrs=%d children=%d' % (pad, path, p['nparams'], p['nslots'], p['nups'], len(p['code']), len(p['children'])))
    for c in p['code']:
        out.append(pad + '  ' + fmt_instr(c))
    for k, ch in p['children'].items():
        disasm(ch, path + '.' + k, depth + 1, out)
    return out

def load(path):
    with open(path) as f:
        return json.load(f)

def run(proto_path, out_dir):
    root = decode_proto(load(proto_path))
    bad, unk = validate(root)
    with open(os.path.join(out_dir, 'disasm.txt'), 'w', encoding='latin-1') as f:
        f.write('\n'.join(disasm(root)) + '\n')
    return root, bad, unk

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'out/proto.json'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'out'
    root, bad, unk = run(src, dst)
    print('bad jump targets: %d' % len(bad))
    print('unknown instructions: %d' % len(unk))
    for x in bad[:10]: print('bad', x)
    for x in unk[:10]: print('unk', x)
