import re
from vm2sym import Sym, show, subst, truthy, analyze
MEMBER_RE = re.compile(r'return function\(\w+,\w+\)\s*return function\(\w+,\w+\)')

def find_vm_member(mem):
    best = None
    for name, code in mem.items():
        if MEMBER_RE.match(code.lstrip()) and 'repeat' in code:
            if best is None or len(code) > len(mem[best]):
                best = name
    return best

def parse_fields(line):
    out = {}
    for part in line.split(';'):
        if not part:
            continue
        k, v = part.split('=', 1)
        t, val = v.split(':', 1)
        if t == 'n':
            f = float(val)
            out[int(k)] = int(f) if f.is_integer() else f
        elif t == 's':
            out[int(k)] = bytes.fromhex(val).decode('latin-1')
        elif t == 'b':
            out[int(k)] = val == '1'
    return out

def lit(v):
    if isinstance(v, str):
        if v and all(32 <= ord(c) < 127 for c in v):
            return '"%s"' % v.replace('\\', '\\\\').replace('"', '\\"')
        return 'x"%s"' % v.encode('latin-1').hex()
    return show(v)

class Pretty:
    def __init__(self, vm):
        self.regs = vm.regs
        self.k = vm.kname
        self.names = {'h': 'pack', 'i': 'unpack', 'g': 'iter', 'v': 'decrypt', 'y': 'hash', 't': 'lz'}

    def sh(self, v):
        if isinstance(v, str):
            return lit(v)
        if not isinstance(v, Sym):
            return show(v)
        o, a = v.op, v.a
        if o == 'idx':
            b, k = a
            if isinstance(b, Sym) and b.op == 'var' and b.a[0] == self.regs:
                return 'R[%s]' % self.sh(k)
            if isinstance(b, Sym) and b.op == 'var' and b.a[0] == self.k and isinstance(k, str):
                return self.names.get(k, 'K.' + k)
            return '%s[%s]' % (self.sh(b), self.sh(k))
        if o == 'var':
            if a[0] == self.regs:
                return 'R'
            return '$' + a[0]
        if o == 'bin':
            return '(%s %s %s)' % (self.sh(a[1]), a[0], self.sh(a[2]))
        if o == 'un':
            return '(%s%s)' % (a[0], self.sh(a[1]))
        if o == 'and':
            return '(%s and %s)' % (self.sh(a[0]), self.sh(a[1]))
        if o == 'or':
            return '(%s or %s)' % (self.sh(a[0]), self.sh(a[1]))
        if o == 'tab':
            return '{%s}' % ', '.join(self.sh(x) for x in a[0])
        return show(v)

    def ev(self, e):
        k = e[0]
        if k == 'set':
            if isinstance(e[1], Sym) and e[1].op == 'tab':
                return 'T[%s] = %s' % (self.sh(e[2]), self.sh(e[3]))
            return '%s[%s] = %s' % (self.sh(e[1]), self.sh(e[2]), self.sh(e[3]))
        if k == 'call':
            f = e[2]
            fn = self.sh(f) if e[4] is None else '%s:%s' % (self.sh(f), e[4])
            return 'r%d = %s(%s)' % (e[1], fn, ', '.join(self.sh(x) for x in e[3]))
        if k == 'pc':
            return 'goto %s' % self.sh(e[1])
        if k == 'return':
            return 'return %s' % ', '.join(self.sh(x) for x in e[1])
        return repr(e)

def select(vm, fields, pc):
    best = None
    for var in vm.table.get(fields.get(vm.opkey, -1), []):
        resid = []
        ok = True
        for pol, c in var['path']:
            r = subst(c, fields, pc)
            if isinstance(r, Sym):
                resid.append((pol, r))
            elif truthy(r) != pol:
                ok = False
                break
        if not ok:
            continue
        if best is None or len(resid) < len(best[1]):
            best = (var, resid)
    return best

def disasm(vm, code_lines, decrypts=None):
    pr = Pretty(vm)
    known = {}
    for d in decrypts or []:
        known[d['ciphertext']] = d['plaintext']
    out = []
    for i, line in enumerate(code_lines, 1):
        fields = parse_fields(line)
        op = fields.get(vm.opkey, -1)
        sel = select(vm, fields, i)
        used = {k: v for k, v in fields.items() if k != vm.opkey and v not in (0, '')}
        head = '%04d  op%-3d %s' % (i, op, ' '.join('%s=%s' % (k, lit(v)) for k, v in sorted(used.items())))
        out.append(head)
        for k, v in fields.items():
            if isinstance(v, str) and v.encode('latin-1').hex() in known:
                pt = bytes.fromhex(known[v.encode('latin-1').hex()])
                out.append('        decrypts to %s' % lit(pt.decode('latin-1')))
        if sel is None:
            out.append('        unresolved')
            continue
        var, resid = sel
        pre = ''
        if resid:
            pre = 'if %s then ' % ' and '.join(('' if p else 'not ') + pr.sh(c) for p, c in resid)
        for e in var['events']:
            e2 = substevent(e, fields, i)
            out.append('        %s%s' % (pre, pr.ev(e2)))
    return out

def substevent(e, fields, pc):
    k = e[0]
    if k == 'set':
        return ('set', subst(e[1], fields, pc), subst(e[2], fields, pc), subst(e[3], fields, pc))
    if k == 'call':
        return ('call', e[1], subst(e[2], fields, pc), [subst(a, fields, pc) for a in e[3]], e[4])
    if k == 'pc':
        return ('pc', subst(e[1], fields, pc))
    if k == 'return':
        return ('return', [subst(x, fields, pc) for x in e[1]])
    return e
