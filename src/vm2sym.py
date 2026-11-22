import sys
sys.setrecursionlimit(1000000)
from lparse import parse


class Sym:
    __slots__ = ('op', 'a')

    def __init__(s, op, *a):
        s.op = op
        s.a = a

    def __repr__(s):
        return show(s)


def show(v):
    if isinstance(v, Sym):
        o, a = v.op, v.a
        if o == 'in':
            return a[0]
        if o == 'var':
            return '$' + a[0]
        if o == 'up':
            return 'UP%d' % a[0]
        if o == 'idx':
            return '%s[%s]' % (show(a[0]), show(a[1]))
        if o == 'bin':
            return '(%s %s %s)' % (show(a[1]), a[0], show(a[2]))
        if o == 'un':
            return '(%s%s)' % (a[0], show(a[1]))
        if o == 'ret':
            return 'r%d.%d' % (a[0], a[1])
        if o == 'tab':
            return '{%s}' % ','.join(show(x) for x in a[0])
        if o == 'vararg':
            return '...'
        if o == 'fn':
            return '<fn>'
        return '%s(%s)' % (o, ','.join(show(x) for x in a))
    if v is None:
        return 'nil'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return repr(v) if isinstance(v, str) else str(v)


def truthy(v):
    return not (v is None or v is False)


def num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def norm(x):
    if isinstance(x, float) and x.is_integer() and abs(x) < 1e15:
        return int(x)
    return x


def unesc(s):
    s = s[1:-1]
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\':
            i += 1
            c = s[i]
            if c.isdigit():
                j = i
                while j < len(s) and j < i + 3 and s[j].isdigit():
                    j += 1
                out.append(chr(int(s[i:j])))
                i = j
                continue
            out.append({'n': '\n', 't': '\t', 'r': '\r'}.get(c, c))
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def parse_num(s):
    if isinstance(s, (int, float)):
        return s
    t = s.lower()
    if t.startswith('0x'):
        return int(t, 16)
    if t.startswith('0b'):
        return int(t, 2)
    f = float(s)
    return int(f) if f.is_integer() and 'e' not in t and '.' not in t else f


class Ctx:
    def __init__(self, opcode, opkey, fetch_show, pcname):
        self.opcode = opcode
        self.opkey = opkey
        self.fetch_show = fetch_show
        self.pcname = pcname
        self.calls = 0


def is_up(e):
    if e[0] != 'index':
        return None
    a, b = e[1], e[2]
    if a[0] == 'index' and a[1][0] == 'index' and a[1][1] == ('name', 'hb') and a[2] == ('num', '3') and a[1][2][0] == 'num':
        n = a[1][2][1]
        if b == ('index', ('index', ('name', 'hb'), ('num', n)), ('num', '2')):
            return int(n)
    return None


def arith(op, x, y):
    if op == '+':
        return norm(x + y)
    if op == '-':
        return norm(x - y)
    if op == '*':
        return norm(x * y)
    if op == '/':
        return norm(x / y) if y != 0 else Sym('bin', op, x, y)
    if op == '%':
        return norm(x % y) if y != 0 else Sym('bin', op, x, y)
    if op == '//':
        return norm(x // y) if y != 0 else Sym('bin', op, x, y)
    if op == '^':
        return norm(x ** y)
    if op == '<':
        return x < y
    if op == '>':
        return x > y
    if op == '<=':
        return x <= y
    if op == '>=':
        return x >= y
    if op == '==':
        return x == y
    if op == '~=':
        return x != y
    raise Exception('arith ' + op)


def ev(e, env, st, ctx):
    t = e[0]
    if t == 'num':
        return parse_num(e[1])
    if t == 'str':
        return unesc(e[1])
    if t == 'nil':
        return None
    if t == 'true':
        return True
    if t == 'false':
        return False
    if t == 'vararg':
        return Sym('vararg')
    if t == 'paren':
        return ev(e[1], env, st, ctx)
    if t == 'name':
        n = e[1]
        if n in env:
            return env[n]
        return Sym('var', n)
    if t == 'index':
        u = is_up(e)
        if u is not None:
            return Sym('up', u)
        b = ev(e[1], env, st, ctx)
        k = ev(e[2], env, st, ctx)
        if isinstance(b, Sym) and num(k) and (b.op == 'in' or (b.op == 'idx' and show(b) == ctx.fetch_show)):
            if k == ctx.opkey:
                return ctx.opcode
            return Sym('in', 'o.%s' % k)
        if isinstance(b, dict):
            return b.get(k)
        return Sym('idx', b, k)
    if t == 'bin':
        op = e[1]
        if op == 'and':
            l = ev(e[2], env, st, ctx)
            if not isinstance(l, Sym):
                return ev(e[3], env, st, ctx) if truthy(l) else l
            return Sym('and', l, ev(e[3], env, st, ctx))
        if op == 'or':
            l = ev(e[2], env, st, ctx)
            if not isinstance(l, Sym):
                return l if truthy(l) else ev(e[3], env, st, ctx)
            return Sym('or', l, ev(e[3], env, st, ctx))
        l = ev(e[2], env, st, ctx)
        r = ev(e[3], env, st, ctx)
        if op == '..':
            if isinstance(l, (str, int, float)) and isinstance(r, (str, int, float)):
                return str(l) + str(r)
            return Sym('bin', op, l, r)
        if num(l) and num(r):
            return arith(op, l, r)
        if op == '==' and not isinstance(l, Sym) and not isinstance(r, Sym):
            return l == r
        if op == '~=' and not isinstance(l, Sym) and not isinstance(r, Sym):
            return l != r
        return Sym('bin', op, l, r)
    if t == 'un':
        x = ev(e[2], env, st, ctx)
        op = e[1]
        if op == 'not':
            if isinstance(x, Sym):
                return Sym('un', 'not ', x)
            return not truthy(x)
        if op == '-':
            if num(x):
                return norm(-x)
            return Sym('un', '-', x)
        if op == '#':
            if isinstance(x, str):
                return len(x)
            return Sym('un', '#', x)
        return Sym('un', op, x)
    if t == 'table':
        items = []
        for it in e[1]:
            if it[0] == 'v':
                items.append(ev(it[1], env, st, ctx))
            else:
                items.append(Sym('kv', ev(it[1], env, st, ctx), ev(it[2], env, st, ctx)))
        return Sym('tab', items)
    if t == 'function':
        return Sym('fn')
    if t in ('call', 'mcall'):
        return call(e, env, st, ctx, 1)[0]
    raise Exception('ev ' + t)


def call(e, env, st, ctx, want):
    if e[0] == 'call':
        f = ev(e[1], env, st, ctx)
        args = [ev(a, env, st, ctx) for a in e[2]]
        name = show(f)
    else:
        f = ev(e[1], env, st, ctx)
        args = [ev(a, env, st, ctx) for a in e[3]]
        name = '%s:%s' % (show(f), e[2])
    ctx.calls += 1
    cid = ctx.calls
    st['events'].append(('call', cid, f, args, e[2] if e[0] == 'mcall' else None))
    return [Sym('ret', cid, i) for i in range(max(want, 1))]


def evlist(exprs, env, st, ctx, nt):
    out = []
    for i, e in enumerate(exprs):
        last = i == len(exprs) - 1
        if last and e[0] in ('call', 'mcall') and nt > len(out) + 1:
            out.extend(call(e, env, st, ctx, nt - len(out)))
        else:
            out.append(ev(e, env, st, ctx))
    while len(out) < nt:
        out.append(None)
    return out


def assign_target(t, v, env, st, ctx):
    if t[0] == 'name':
        env[t[1]] = v
        if t[1] == ctx.pcname:
            st['events'].append(('pc', v))
    elif t[0] == 'index':
        b = ev(t[1], env, st, ctx)
        k = ev(t[2], env, st, ctx)
        st['events'].append(('set', b, k, v))
    else:
        raise Exception('target ' + t[0])


def clone(st):
    return {'env': dict(st['env']), 'events': list(st['events']), 'path': list(st['path']), 'end': st['end']}


def run_stmt(s, sts, ctx):
    out = []
    for st in sts:
        if st['end']:
            out.append(st)
            continue
        env = st['env']
        t = s[0]
        if t == 'local':
            vals = evlist(s[2], env, st, ctx, len(s[1])) if s[2] else [None] * len(s[1])
            for n, v in zip(s[1], vals):
                env[n] = v
            out.append(st)
        elif t == 'assign':
            vals = evlist(s[2], env, st, ctx, len(s[1]))
            for tg, v in zip(s[1], vals):
                assign_target(tg, v, env, st, ctx)
            out.append(st)
        elif t == 'callstat':
            call(s[1], env, st, ctx, 1)
            out.append(st)
        elif t == 'if':
            rest = s[2]
            taken = False
            pending = [st]
            for cond, body in s[1]:
                nxt = []
                for p in pending:
                    c = ev(cond, p['env'], p, ctx)
                    if isinstance(c, Sym):
                        a = clone(p)
                        a['path'].append((True, c))
                        out.extend(run_block(body, [a], ctx))
                        b = p
                        b['path'].append((False, c))
                        nxt.append(b)
                    elif truthy(c):
                        out.extend(run_block(body, [p], ctx))
                    else:
                        nxt.append(p)
                pending = nxt
            if rest is not None:
                out.extend(run_block(rest, pending, ctx))
            else:
                out.extend(pending)
        elif t == 'return':
            vals = [ev(x, env, st, ctx) for x in s[1]]
            st['events'].append(('return', vals))
            st['end'] = 'return'
            out.append(st)
        elif t == 'nop':
            out.append(st)
        else:
            st['events'].append('UNSUPPORTED ' + t)
            st['end'] = 'unsupported'
            out.append(st)
    return out


def run_block(stmts, sts, ctx):
    for s in stmts:
        sts = run_stmt(s, sts, ctx)
    return sts


def descend(stmts, env, st, ctx):
    while True:
        if len(stmts) == 1 and stmts[0][0] == 'if':
            node = stmts[0]
            chosen = None
            ok = True
            for cond, body in node[1]:
                c = ev(cond, env, st, ctx)
                if isinstance(c, Sym):
                    ok = False
                    break
                if truthy(c):
                    chosen = body
                    break
            if not ok:
                return stmts
            if chosen is None:
                if node[2] is None:
                    return []
                chosen = node[2]
            stmts = chosen
        else:
            return stmts




def has(node, pat):
    if node == pat:
        return True
    if isinstance(node, (list, tuple)):
        return any(has(x, pat) for x in node)
    return False


def leaves(stmts, out):
    if len(stmts) == 1 and stmts[0][0] == 'if':
        for cond, b in stmts[0][1]:
            leaves(b, out)
        if stmts[0][2] is not None:
            leaves(stmts[0][2], out)
    else:
        out.append(stmts)


def find_vm(text):
    ast = parse(text)
    fn1 = ast[0][1][0]
    inner = fn1[3][0][1][0]
    body = inner[3]
    loop = [s for s in body if s[0] == 'repeat'][0]
    tree = loop[1]
    node = tree[0]
    cond = node[1][0][0]
    lname = cond[2][1]
    allleaves = []
    leaves(tree, allleaves)
    counts = {}

    def count(node):
        if isinstance(node, tuple):
            if len(node) == 3 and node[0] == 'index' and node[1][0] == 'name' and node[2][0] == 'num':
                counts[node[1][1]] = counts.get(node[1][1], 0) + 1
            for x in node:
                count(x)
        elif isinstance(node, list):
            for x in node:
                count(x)

    count(tree)
    best = None
    for lf in allleaves:
        for si, s in enumerate(lf):
            if s[0] != 'assign':
                continue
            for tg, ex in zip(s[1], s[2]):
                if not (tg[0] == 'name' and ex[0] == 'index' and ex[1][0] == 'name' and ex[2][0] == 'name'):
                    continue
                ins, gbn, han = tg[1], ex[1][1], ex[2][1]
                incr = False
                for s3 in lf:
                    if s3[0] != 'assign':
                        continue
                    for t3, e3 in zip(s3[1], s3[2]):
                        if t3[0] == 'name' and t3[1] == han and e3[0] == 'bin' and e3[1] == '+' and e3[2] == ('name', han):
                            incr = True
                if not incr:
                    continue
                key = None
                for s2 in lf[si + 1:]:
                    if s2[0] != 'assign':
                        continue
                    for e2 in s2[2]:
                        if key is None and e2[0] == 'index' and e2[1] == ('name', ins) and e2[2][0] == 'num':
                            key = parse_num(e2[2][1])
                if key is None:
                    continue
                score = counts.get(ins, 0)
                if best is None or score > best[0]:
                    best = (score, lf, (ins, gbn, han, key))
    fetch = best[1]
    info = best[2]
    return tree, lname, fetch, info, inner


def start_state(tree, lname, fetch, ctxfactory):
    probe = Ctx(0, -1, '', '')
    cands = []
    for v in range(0, 40000):
        env = {lname: v}
        if descend(tree, env, {'events': [], 'path': []}, probe) is fetch:
            cands.append(v)
    best = None
    for v in cands:
        ok = True
        for opc in range(256):
            ctx = ctxfactory(opc)
            env = {lname: v, 'gb': None}
            st = {'env': dict(env), 'events': [], 'path': [], 'end': None}
            try:
                outs = run_block(fetch, [st], ctx)
            except Exception:
                ok = False
                break
            for o in outs:
                Lv = o['env'].get(lname)
                if isinstance(Lv, Sym):
                    continue
                if not isinstance(Lv, int):
                    ok = False
        if ok:
            best = v
            break
    return best if best is not None else (cands[-1] if cands else None)


class VM:
    pass


def analyze(text):
    tree, lname, fetch, info, inner = find_vm(text)
    ins, gbn, han, opkey = info
    vm = VM()
    vm.opkey = opkey
    vm.regs = inner[1][0]
    vm.kname = ast_outer_name(text)
    vm.lname = lname
    vm.gb = gbn
    vm.ha = han
    fetch_show = '$%s[$%s]' % (gbn, han)

    def mk(opc):
        return Ctx(opc, opkey, fetch_show, han)

    L0 = start_state(tree, lname, fetch, mk)
    vm.L0 = L0
    table = {}
    for opc in range(256):
        table[opc] = explore(opc, tree, fetch, lname, gbn, han, ins, L0, mk)
    vm.table = table
    return vm


def explore(opc, tree, fetch, lname, gbn, han, ins, L0, mk, maxsteps=400, maxpaths=48, budget=4000):
    ctx = mk(opc)
    start = {'env': {lname: L0, gbn: Sym('var', gbn), han: Sym('var', han), ins: Sym('in', 'o')}, 'events': [], 'path': [], 'end': None}
    work = [(start, 0, False)]
    res = []
    used = 0
    while work:
        st, steps, seen = work.pop()
        visits = {}
        while True:
            used += 1
            if used > budget:
                st['end'] = 'budget'
                res.append(st)
                work = []
                break
            key = show(st['env'][lname])
            visits[key] = visits.get(key, 0) + 1
            if visits[key] > 4:
                st['end'] = 'loop'
                res.append(st)
                break
            if steps > maxsteps:
                st['end'] = 'steplimit'
                res.append(st)
                break
            leaf = descend(tree, st['env'], st, ctx)
            if leaf is fetch and seen:
                st['end'] = 'next'
                res.append(st)
                break
            if not leaf:
                st['end'] = 'noleaf'
                res.append(st)
                break
            outs = run_block(leaf, [st], ctx)
            steps += 1
            seen = True
            cont = []
            for o in outs:
                if o['end']:
                    res.append(o)
                    continue
                Lv = o['env'][lname]
                if isinstance(Lv, Sym) and Lv.op == 'or' and isinstance(Lv.a[0], Sym) and Lv.a[0].op == 'and':
                    c, X = Lv.a[0].a
                    Y = Lv.a[1]
                    if isinstance(X, Sym) or isinstance(Y, Sym):
                        o['end'] = 'symL'
                        res.append(o)
                        continue
                    a = clone(o)
                    a['env'][lname] = X
                    a['path'].append((True, c))
                    b = o
                    b['env'][lname] = Y
                    b['path'].append((False, c))
                    cont += [a, b]
                elif isinstance(Lv, Sym):
                    o['end'] = 'symL'
                    res.append(o)
                else:
                    cont.append(o)
            if not cont:
                break
            st = cont[0]
            for c in cont[1:]:
                work.append((c, steps, seen))
        if len(res) > maxpaths:
            break
    out = []
    seen_sig = set()
    for x in res:
        ev = [e for e in x['events'] if not (e[0] == 'pc' and show(e[1]) in ('($%s + 1)' % han, '($%s[$%s] + 1)' % (gbn, han)))]
        sig = repr([(c, show(p)) for c, p in x['path']]) + repr([show_event(e) for e in ev])
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        out.append({'path': x['path'], 'events': ev, 'end': x['end']})
    return out


def show_event(e):
    k = e[0]
    if k == 'set':
        return 'SET %s[%s] = %s' % (show(e[1]), show(e[2]), show(e[3]))
    if k == 'call':
        return 'CALL r%d = %s(%s)' % (e[1], show(e[2]) if e[4] is None else '%s:%s' % (show(e[2]), e[4]), ', '.join(show(a) for a in e[3]))
    if k == 'pc':
        return 'PC = %s' % show(e[1])
    if k == 'return':
        return 'RETURN ' + ', '.join(show(v) for v in e[1])
    return repr(e)


def subst(v, fields, pc):
    if not isinstance(v, Sym):
        return v
    o, a = v.op, v.a
    if o == 'in':
        parts = a[0].split('.')
        if len(parts) == 2:
            return fields.get(int(parts[1]), 0)
        return v
    if o == 'var':
        if a[0] == 'ha':
            return pc
        return v
    if o == 'bin':
        l = subst(a[1], fields, pc)
        r = subst(a[2], fields, pc)
        if num(l) and num(r):
            try:
                return arith(a[0], l, r)
            except Exception:
                pass
        if a[0] == '..' and isinstance(l, (str, int, float)) and isinstance(r, (str, int, float)):
            return str(l) + str(r)
        return Sym('bin', a[0], l, r)
    if o == 'un':
        x = subst(a[1], fields, pc)
        if num(x) and a[0] == '-':
            return norm(-x)
        if not isinstance(x, Sym) and a[0] == 'not ':
            return not truthy(x)
        return Sym('un', a[0], x)
    if o == 'and':
        l = subst(a[0], fields, pc)
        if not isinstance(l, Sym):
            return subst(a[1], fields, pc) if truthy(l) else l
        return Sym('and', l, subst(a[1], fields, pc))
    if o == 'or':
        l = subst(a[0], fields, pc)
        if not isinstance(l, Sym):
            return l if truthy(l) else subst(a[1], fields, pc)
        return Sym('or', l, subst(a[1], fields, pc))
    if o == 'idx':
        return Sym('idx', subst(a[0], fields, pc), subst(a[1], fields, pc))
    if o == 'tab':
        return Sym('tab', [subst(x, fields, pc) for x in a[0]])
    return Sym(o, *[subst(x, fields, pc) if isinstance(x, Sym) else x for x in a])


def ast_outer_name(text):
    ast = parse(text)
    return ast[0][1][0][1][0]
