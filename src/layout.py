import re
import detect, lemit

def extract_fld(ast):
    des = detect.find_deserializer(ast)
    tbl15 = None
    def find_tbls(node):
        nonlocal tbl15
        if not isinstance(node, (list, tuple)) or not node:
            return
        if node[0] == 'table' and len(node[1]) == 15:
            tbl15 = node
            return
        for c in node:
            find_tbls(c)
    for st in ast:
        if st[0] == 'local' and st[1] == [des]:
            find_tbls(st[2][0])
            break
    t15_keys = {lemit.E(kv[1]): lemit.E(kv[2]) for kv in tbl15[1]}
    var_expr = {}
    fld_assign = {}
    var_from_30 = None
    kind_key = None
    def visit(node):
        nonlocal var_from_30, kind_key
        if not isinstance(node, (list, tuple)) or not node:
            return
        if node[0] == 'assign':
            for target, val in zip(node[1], node[2]):
                vs = lemit.E(val)
                if target[0] == 'name':
                    var_expr[target[1]] = vs
                    if ',30)' in vs or '[2]' in vs:
                        var_from_30 = target[1]
                    if '65535' in vs:
                        var_expr[target[1]] = 'D_VAL'
                    elif '32768' in vs or '65536' in vs:
                        var_expr[target[1]] = 'sD_VAL'
                    elif '8388608' in vs or '16777216' in vs:
                        var_expr[target[1]] = 'sE_VAL'
                elif target[0] == 'index' and target[2][0] == 'num':
                    fld_key = str(target[2][1])
                    if fld_key in t15_keys:
                        if var_from_30 and vs == var_from_30:
                            kind_key = fld_key
                        fld_assign.setdefault(fld_key, []).append((vs, var_expr.get(vs)))
        for c in node:
            visit(c)
    for st in ast:
        if st[0] == 'local' and st[1] == [des]:
            visit(st[2][0])
            break
    FLD = {}
    if kind_key:
        FLD['kind'] = kind_key
    for k, vlist in fld_assign.items():
        vstrs = [s for s, _ in vlist]
        for s, tag in vlist:
            if ',8),255)' in s or ',8), 255)' in s or ', 8), 255)' in s:
                FLD['A'] = k
            elif ',16),255)' in s or ',16), 255)' in s:
                FLD['B'] = k
            elif ',24),255)' in s or ',24), 255)' in s:
                FLD['C'] = k
            elif '31,1)' in s or '31, 1)' in s:
                FLD['f1'] = k
                m = re.search(r'\[(\d+)\]', s)
                if m:
                    FLD['aux'] = m.group(1)
            elif tag == 'D_VAL':
                FLD['D'] = k
            elif tag == 'sD_VAL':
                FLD['sD'] = k
            elif tag == 'sE_VAL':
                FLD['sE'] = k
        if len(vstrs) >= 5:
            FLD['k1'] = k
        elif len(vstrs) == 2 and any('[' in s and '+ 1]' in s for s in vstrs):
            FLD['k2'] = k
        elif len(vstrs) == 1 and any('[' in s and '+ 1]' in s for s in vstrs) and k not in FLD.values():
            FLD['k3'] = k
    op_key = None
    try:
        import vmhandlers
        m = vmhandlers.Machine(ast)
        fetch1 = m.fetch[1]
        for val in fetch1[2]:
            if val[0] == 'index' and val[1][0] == 'name' and val[1][1] == m.qvar:
                if val[2][0] == 'num':
                    op_key = str(val[2][1])
    except Exception:
        pass
    if op_key:
        FLD['op'] = op_key
    for k, v in t15_keys.items():
        if v not in ('0', 'nil') and k not in FLD.values():
            if k == kind_key:
                FLD['kind'] = k
            elif 'op' not in FLD:
                FLD['op'] = k
    if 'kind' not in FLD and kind_key:
        FLD['kind'] = kind_key
    return FLD

def extract_proto(ast, target, h_text):
    des = detect.find_deserializer(ast)
    tbl6 = None
    def find_tbls(node):
        nonlocal tbl6
        if not isinstance(node, (list, tuple)) or not node:
            return
        if node[0] == 'table' and len(node[1]) == 6:
            tbl6 = node
            return
        for c in node:
            find_tbls(c)
    for st in ast:
        if st[0] == 'local' and st[1] == [des]:
            find_tbls(st[2][0])
            break
    t6_keys = [lemit.E(kv[1]) for kv in tbl6[1]]
    PROTO = {}
    int_keys = []
    for k in t6_keys:
        val = target.get(k)
        if isinstance(val, dict):
            first_v = next(iter(val.values())) if val else None
            if isinstance(first_v, dict) and any(isinstance(x, dict) for x in first_v.values()):
                PROTO['children'] = k
            else:
                PROTO['code'] = k
        elif isinstance(val, str):
            PROTO['name'] = k
        elif isinstance(val, int):
            int_keys.append(k)
    int_keys.sort(key=lambda k: target.get(k, 0))
    PROTO['nslots'] = int_keys[-1]
    m = re.search(r'(\w+)\s*=\s*\w+\[\w+\s*\+\s*1\].*?\n.*?(\w+)\s*=\s*\1\[(\d+)\]', h_text, re.DOTALL)
    if m and m.group(3) in int_keys:
        PROTO['nups'] = m.group(3)
        int_keys.remove(m.group(3))
    else:
        PROTO['nups'] = int_keys[0]
        int_keys.remove(int_keys[0])
    for k in int_keys:
        if k != PROTO['nslots']:
            PROTO['nparams'] = k
            break
    return PROTO

def extract_layout(ast, target, h_text):
    return extract_fld(ast), extract_proto(ast, target, h_text)
