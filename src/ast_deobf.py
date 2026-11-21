import os
from lparse import parse
from lemit import B
from passes import walk, fold
import strdec

def decrypt_strings(n):
    if isinstance(n, tuple):
        if n and n[0] == 'call':
            fn = n[1]
            while fn[0] == 'paren':
                fn = fn[1]
            if fn[0] == 'function' and len(n[2]) == 2 and n[2][0][0] == 'str' and n[2][1][0] == 'str':
                s1 = strdec.unlua(n[2][0][1])
                s2 = strdec.unlua(n[2][1][1])
                if s1 is not None and s2 is not None:
                    return ('str', strdec.lua(strdec.xdec(s1, s2)))
        return tuple(decrypt_strings(x) for x in n)
    elif isinstance(n, list):
        return [decrypt_strings(x) for x in n]
    return n

def clean_nops(block):
    res = []
    for s in block:
        if s[0] == 'nop':
            continue
        if s[0] in ('if', 'while', 'repeat', 'fornum', 'forin', 'do'):
            cleaned = []
            for item in s[1:]:
                if isinstance(item, list):
                    cleaned.append(clean_nops(item))
                elif isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], list):
                    cleaned.append((item[0], clean_nops(item[1])))
                else:
                    cleaned.append(item)
            res.append((s[0], *cleaned))
        else:
            res.append(s)
    return res

def deobfuscate_ast(src, out):
    os.makedirs(out, exist_ok=True)
    ast = parse(src)
    ast = decrypt_strings(ast)
    ast = walk(ast, fold)
    ast = clean_nops(ast)
    final_text = B(ast)
    with open(os.path.join(out, 'stage_strings.lua'), 'w', encoding='latin-1') as f:
        f.write(final_text)
    with open(os.path.join(out, 'final.lua'), 'w', encoding='utf-8') as f:
        f.write(final_text)
    print('decompiled final script: %d lines' % final_text.count('\n'))
    return final_text
