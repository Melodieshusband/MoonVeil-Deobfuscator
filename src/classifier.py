import re
from strdec import unlua

def build_classifier(h_path, fld, proto):
    text = open(h_path, encoding='latin-1').read()
    blocks = text.split('=== opcodes ')
    
    A, B, C = fld['A'], fld['B'], fld['C']
    k1, k2, k3 = fld['k1'], fld.get('k2', ''), fld.get('k3', '')
    sD, D, sE, aux, f1, kind = fld['sD'], fld['D'], fld['sE'], fld['aux'], fld['f1'], fld['kind']
    nups = proto['nups']
    
    prefix = bytes([220,166,237,73,32,150,88])
    m_pfx = re.search(r'(\'[^\']+\')\s*\.\.\s*\w+', text)
    if m_pfx:
        prefix = unlua(m_pfx.group(1))
        
    stubs = {}
    pre_decrypt_single = set()
    pre_decrypt_multi = set()
    closure_ops = set()
    closure_rules = {}
    loadn_rules = {}
    call_rules = {}
    op_map = {}
    
    for b in blocks[1:]:
        header, *rest = b.split('\n', 1)
        if not rest:
            continue
        ops = [int(x) for x in header.split(',') if x.strip().isdigit()]
        if not ops:
            continue
        body = rest[0].strip()
        
        for tbl_m in re.finditer(r'\w+\[\s*\w+\s*\]\s*=\s*\{([^}]+)\}', body):
            tbl = tbl_m.group(1)
            c_zero_m = re.search(r'\[\s*' + C + r'\s*\]\s*=\s*0\b', tbl)
            if not c_zero_m:
                continue
            preceding = body[:tbl_m.start()]
            cond_m = list(re.finditer(r'\w+\[\s*' + C + r'\s*\]\s*==\s*(\d+)', preceding))
            if not cond_m:
                continue
            c_val = int(cond_m[-1].group(1))
            nop = None
            for f_m in re.finditer(r'\[\s*(\d+)\s*\]\s*=\s*(\d+)', tbl):
                k, v = f_m.group(1), int(f_m.group(2))
                if k != C:
                    nop = v
                    break
            if nop is None:
                continue
            xa_m = re.search(r'\[\s*' + A + r'\s*\]\s*=\s*\w+\(\w+\[\s*' + A + r'\s*\]\s*,\s*(\d+)\s*\)', tbl)
            xa = int(xa_m.group(1)) if xa_m else 0
            xb_m = re.search(r'\[\s*' + B + r'\s*\]\s*=\s*\w+\(\w+\[\s*' + B + r'\s*\]\s*,\s*(\d+)\s*\)', tbl)
            xb = int(xb_m.group(1)) if xb_m else 0
            for op in ops:
                stubs.setdefault(op, {})[c_val] = (nop, xa, xb)
                
        if '..' in body and re.search(r'%\s*#', body):
            if kind in body:
                pre_decrypt_multi.update(ops)
                info = ('DECRYPT_MULTI',)
            else:
                pre_decrypt_single.update(ops)
                info = ('DECRYPT_SINGLE',)
        elif nups in body:
            closure_ops.update(ops)
            if D in body:
                m_dx = re.search(r'\w+\(\w+\[\s*' + D + r'\s*\]\s*,\s*(\d+)\s*\)', body)
                m_ax = re.search(r'\w+\[\s*\w+\(\w+\[\s*' + A + r'\s*\]\s*,\s*(\d+)\s*\)\s*\]\s*=', body)
                d_xor = int(m_dx.group(1)) if m_dx else 0
                a_xor = int(m_ax.group(1)) if m_ax else 0
                for op in ops:
                    closure_rules[op] = {'type': 'D', 'd_xor': d_xor, 'a_xor': a_xor}
                info = ('CLOSURE_D', d_xor, a_xor)
            else:
                m_ax = re.search(r'\w+\[\s*\w+\(\w+\[\s*' + A + r'\s*\]\s*,\s*(\d+)\s*\)\s*\]\s*=', body)
                a_xor = int(m_ax.group(1)) if m_ax else 0
                for op in ops:
                    closure_rules[op] = {'type': 'K', 'a_xor': a_xor}
                info = ('CLOSURE_K', a_xor)
        elif re.search(r'\(\w+\(\w+\s*,\s*\w+\s*\+\s*1', body):
            m_call = re.findall(r'\w+\(\w+\[\s*(\d+)\s*\]\s*,\s*(\d+)\s*\)', body)
            c_rule = [(int(f), int(x)) for f, x in m_call[:3]] if len(m_call) >= 3 else []
            for op in ops:
                call_rules[op] = c_rule
            info = ('CALL', c_rule)
        elif 'return ' in body or 'return\n' in body or 'return\t' in body:
            info = ('RETURN', A, B)
        elif re.search(r'\(\w+\[\d+\],\s*1\s*,', body):
            info = ('GETVARARGS', A, B)
        elif '__iter' in body or ('goto state' in body and ('hb[' in body or 'I[3]' in body)):
            info = ('CLOSEUPVALS', A)
        elif '32768' in body and nups not in body:
            m_dx = re.search(r'\w+\(\w+\[\s*' + D + r'\s*\]\s*,\s*(\d+)\s*\)', body)
            m_ax = re.search(r'\w+\[\s*\w+\(\w+\[\s*' + A + r'\s*\]\s*,\s*(\d+)\s*\)\s*\]\s*=', body)
            d_xor = int(m_dx.group(1)) if m_dx else 0
            a_xor = int(m_ax.group(1)) if m_ax else 0
            for op in ops:
                loadn_rules[op] = (d_xor, a_xor)
            info = ('LOADN', d_xor, a_xor)
        elif re.search(r'\(\w+\[\w+\s*\+\s*1\],\s*\w+\[\w+\s*\+\s*2\]\)', body):
            info = ('FORGLOOP', A, k1)
        elif "'number'" in body and ('+ 2' in body or '+2' in body) and sD in body:
            info = ('FORNPREP', A)
        elif '> 0' in body and ('+ 2' in body or '+2' in body) and sD in body:
            info = ('FORNLOOP', A)
        elif "'function'" in body and 'not' in body and sD in body:
            info = ('FORGPREP', A)
        elif re.search(r'==\s*1\b', body) and ('+' + sD in body.replace(' ', '') or '+' + A in body.replace(' ', '') or '+' + B in body.replace(' ', '') or '+' + C in body.replace(' ', '')):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[(\d+)\]\s*==\s*1', body)
            m_off = re.search(r'\w+\s*=\s*\w+\s*\+\s*\w+\[(\d+)\]', body)
            a_fld = m_a.group(1) if m_a else B
            val_fld = m_a.group(2) if m_a else C
            off_fld = m_off.group(1) if m_off else A
            info = ('LOADB', a_fld, val_fld, off_fld)
        elif sD in body and 'if' not in body:
            info = ('JUMP',)
        elif sD in body and (re.search(r'==\s*nil\b|nil\s*==', body)):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]', body)
            a_fld = m_a.group(1) if m_a else A
            info = ('JUMPNIL', a_fld)
        elif sD in body and f1 in body and ('==' in body or '~=' in body):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]', body)
            a_fld = m_a.group(1) if m_a else A
            if 'boolean' in body or 'boolean' in body.lower():
                info = ('JUMPEQB', a_fld)
            else:
                info = ('JUMPEQK', a_fld)
        elif sD in body and 'if' in body:
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]', body)
            a_fld = m_a.group(1) if m_a else A
            parts = body.split('else', 1)
            then_part = parts[0]
            else_part = parts[1] if len(parts) > 1 else ''
            inverted = (sD in else_part and sD not in then_part)
            if '<=' in then_part and aux in body:
                info = ('JUMPIFNOTLE' if inverted else 'JUMPIFLE', a_fld)
            elif '<' in then_part and aux in body:
                info = ('JUMPIFNOTLT' if inverted else 'JUMPIFLT', a_fld)
            elif '==' in then_part and aux in body:
                info = ('JUMPIFNOTEQ' if inverted else 'JUMPIFEQ', a_fld)
            elif 'not' in then_part:
                info = ('JUMPIF' if inverted else 'JUMPIFNOT', a_fld)
            else:
                info = ('JUMPIFNOT' if inverted else 'JUMPIF', a_fld)
        elif re.search(r'\w+\[\w+\[(?:' + A + r'|' + B + r'|' + C + r')\]\]\s*=\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\s*' + k1 + r'\s*\]', body)
            a_fld = m_a.group(1) if m_a else A
            info = ('LOADK', a_fld)
        elif '#' in body:
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*#\s*\w+\[\w+\[(\d+)\]\]', body)
            a_fld = m.group(1) if m else A
            b_fld = m.group(2) if m else B
            info = ('LEN', a_fld, b_fld)
        elif 'not ' in body and not ('==' in body or '<' in body):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*not\s*\w+\[\w+\[(\d+)\]\]', body)
            a_fld = m_a.group(1) if m_a else A
            b_fld = m_a.group(2) if m_a else B
            info = ('NOT', a_fld, b_fld)
        elif 'table.create' in body or re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\(\w+\[\s*' + aux + r'\s*\]\)', body) or any(x in body for x in ('zc(', 'mb(', 'eb(')):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=', body)
            a_fld = m_a.group(1) if m_a else A
            info = ('NEWTABLE', a_fld)
        elif '- 1' in body and '== -1' in body:
            info = ('SETLIST', C, A, B)
        elif re.search(r'\[2\]\[\w+\[3\]\]', body) or (re.search(r'\w+\[\w+\[\d+\]\s*\+\s*1\]', body) and any(x in body for x in ('ta[', '_c[', 'Ff[', 'Ad['))):
            m_u = re.search(r'\w+\[\w+\[(\d+)\]\s*\+\s*1\]', body)
            u_fld = m_u.group(1) if m_u else B
            eq_idx = body.find('=')
            up_match = re.search(r'\[2\]\[\w+\[3\]\]', body)
            if up_match and eq_idx != -1 and up_match.start() < eq_idx:
                m_a = re.search(r'=\s*\w+\[\w+\[(\d+)\]\]', body)
                a_fld = m_a.group(1) if m_a else A
                info = ('SETUPVAL', a_fld, u_fld)
            else:
                m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=', body)
                a_fld = m_a.group(1) if m_a else A
                info = ('GETUPVAL', a_fld, u_fld)
        elif re.search(r'(?:b_|dc|Dd)\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body):
            m = re.search(r'(?:b_|dc|Dd)\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('SETGLOBAL', m.group(1), m.group(2))
        elif (k2 and k3 and k2 in body and k3 in body) or any(x in body for x in ('b_[', 'dc[', 'Dd[', 'La[', 'fc[', 'Fd[')):
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*(?:b_|dc|Dd)\[|\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\b.*?(?:b_|dc|Dd)\[', body)
            if not m_a:
                m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=', body)
            a_fld = (m_a.group(1) if m_a else A)
            info = ('GETIMPORT', a_fld)
        elif re.search(r'\[\w+\s*\+\s*1\]\s*=\s*(\w+).*?\[\w+\]\s*=\s*\1\[', body, re.DOTALL):
            info = ('NAMECALL', B, A)
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[(\d+)\]\s*\+\s*1\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[(\d+)\]\s*\+\s*1\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('SETTABLEN', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[(\d+)\]\s*\+\s*1\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[(\d+)\]\s*\+\s*1\]', body)
            info = ('GETTABLEN', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[\s*' + k1 + r'\s*\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body) or re.search(r'\w+\[\w+\[(\d+)\]\]\[[a-zA-Z_]\w*\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[\s*' + k1 + r'\s*\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            if not m:
                m = re.search(r'\w+\[\w+\[(\d+)\]\]\[[a-zA-Z_]\w*\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('SETFIELD', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[\s*' + k1 + r'\s*\]\]', body) or re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[[a-zA-Z_]\w*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[\s*' + k1 + r'\s*\]\]', body)
            if not m:
                m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[[a-zA-Z_]\w*\]', body)
            info = ('GETFIELD', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[\w+\[(\d+)\]\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\[\w+\[\w+\[(\d+)\]\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('SETTABLE', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[\w+\[(\d+)\]\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\[\w+\[\w+\[(\d+)\]\]\]', body)
            info = ('GETTABLE', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\(?\s*if\s+\w+\s+then\s+\w+\s+else\s+\w+\[\s*' + k1, body) or 'or false' in body or 'or nil' in body:
            m_a = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=', body)
            a_fld = m_a.group(1) if m_a else C
            b_fld = A
            m_src = re.search(r'\w+\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            if m_src:
                b_fld = m_src.group(1)
            info = ('ORK', a_fld, b_fld)
        elif '.. ' in body or ' ..' in body or ",''" in body or ",'\"'" in body:
            info = ('CONCAT', C, A, B)
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*-\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*-\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('SUBK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\s*' + k1 + r'\s*\]\s*-\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\s*' + k1 + r'\s*\]\s*-\s*\w+\[\w+\[\d+\]\]', body)
            info = ('SUBRK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\+\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\+\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('ADDK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\*\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\*\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('MULK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*/\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*/\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('DIVK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*%\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*%\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('MODK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\^\s*\w+\[\s*' + k1 + r'\s*\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\^\s*\w+\[\s*' + k1 + r'\s*\]', body)
            info = ('POWK', m.group(1), m.group(2))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\+\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\+\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('ADD', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*-\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*-\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('SUB', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\*\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\*\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('MUL', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*/\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*/\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('DIV', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*%\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*%\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('MOD', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]\s*\^\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]\s*\^\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('POW', m.group(1), m.group(2), m.group(3))
        elif re.search(r'\w+\[\w+\[\d+\]\]\s*=\s*\w+\[\w+\[\d+\]\]', body):
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*\w+\[\w+\[(\d+)\]\]', body)
            info = ('MOVE', m.group(1), m.group(2))
        elif ']=nil' in body.replace(' ', '') or ']= nil' in body:
            m = re.search(r'\w+\[\w+\[(\d+)\]\]\s*=\s*nil', body)
            info = ('LOADNIL', m.group(1) if m else A)
        else:
            info = ('NOP',)
            
        for op in ops:
            op_map[op] = info
            
    return {
        'prefix': prefix,
        'stubs': stubs,
        'pre_decrypt_single': pre_decrypt_single,
        'pre_decrypt_multi': pre_decrypt_multi,
        'closure_ops': closure_ops,
        'closure_rules': closure_rules,
        'loadn_rules': loadn_rules,
        'call_rules': call_rules,
        'op_map': op_map
    }
