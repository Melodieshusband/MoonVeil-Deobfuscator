def unparen(e):
    while isinstance(e,tuple) and e and e[0]=='paren':e=e[1]
    return e
def is_bxor(e):
    e=unparen(e)
    return e[0]=='index' and unparen(e[1])==('name','bit32') and e[2][0]=='str' and e[2][1].strip('\'"')=='bxor'
def bindings(ast):
    for i,s in enumerate(ast):
        if s[0]=='local' and s[2]:
            for n,v in zip(s[1],s[2]):
                yield i,n,v
        elif s[0]=='assign':
            for t,v in zip(s[1],s[2]):
                if t[0]=='name':
                    yield i,t[1],v
def xor_aliases(ast):
    return {n for i,n,v in bindings(ast) if is_bxor(v)}
def calls_to(n,names):
    if isinstance(n,tuple):
        if n and n[0]=='call' and n[1][0]=='name' and n[1][1] in names:
            return True
        return any(calls_to(x,names) for x in n if isinstance(x,(tuple,list)))
    if isinstance(n,list):
        return any(calls_to(x,names) for x in n)
    return False
def has_node(n,kind):
    if isinstance(n,tuple):
        if n and n[0]==kind:return True
        return any(has_node(x,kind) for x in n if isinstance(x,(tuple,list)))
    if isinstance(n,list):
        return any(has_node(x,kind) for x in n)
    return False
def contains_str(n,sub):
    if isinstance(n,str):return sub in n
    if isinstance(n,(tuple,list)):return any(contains_str(x,sub) for x in n)
    return False
def find_strdec(ast,xors):
    best=None
    for i,n,v in bindings(ast):
        f=unparen(v)
        if f[0]=='function' and len(f[1])==2 and not f[2]:
            if calls_to(f[3],xors) and has_node(f[3],'return') and (has_node(f[3],'fornum') or has_node(f[3],'repeat') or has_node(f[3],'while')) and contains_str(f[3],"''"):
                if best is None:best=n
    return best
def find_b64(ast):
    for i,n,v in bindings(ast):
        if contains_str(v,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'):
            return n
    return None
def find_deserializer(ast):
    for i,n,v in bindings(ast):
        f=unparen(v)
        if f[0]=='function' and len(f[1])==1 and f[3] and f[3][0][0]=='local':
            x=f[3][0][2]
            if len(x)==1 and x[0][0]=='index' and x[0][1][0]=='index' and x[0][1][2][0]=='num' and x[0][2]==('name',f[1][0]):
                return n
    return None
def find_interpreter_alias(ast):
    for s in reversed(ast):
        if s[0]=='assign' and len(s[1])==1 and len(s[2])==1 and s[1][0][0]=='name' and s[2][0][0]=='name':
            return s[1][0][1]
    return None
