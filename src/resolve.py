import sys,pickle

from lparse import *
from lemit import *
from passes import *
M32=0xFFFFFFFF
XORS=set()
def isxor(e,ps):
    return e[0]=='call' and e[1][0]=='name' and e[1][1] in XORS and len(e[2])==2 and e[2][0][0]=='name' and e[2][0][1] in ps and e[2][1][0]=='num'
def helper_consts(stat):
    if stat[0]!='assign' or len(stat[1])!=2 or len(stat[2])!=2:return None
    fi=1 if stat[2][1][0]=='function' else 0
    f=stat[2][fi]
    if f[0]!='function' or len(f[1])!=3 or len(f[3])!=2:return None
    a=f[3][0]
    if a[0]!='assign' or a[2][0][0]!='bin' or a[2][0][1]!='-':return None
    l,r=a[2][0][2],a[2][0][3]
    ps=f[1]
    if not(isxor(l,ps) and isxor(r,ps)):return None
    return stat[1][fi][1],(ps.index(l[2][0][1]),tonum(l[2][1])),(ps.index(r[2][0][1]),tonum(r[2][1]))
def resolve_block(b,env):
    env=dict(env)
    for s in b:
        h=helper_consts(s)
        if h:env[h[0]]=((h[1][0],h[1][1]),(h[2][0],h[2][1]))
    return [resolve_stmt(s,env) for s in b],env
def rexp(e,env):
    if isinstance(e,tuple) and e and isinstance(e[0],str):
        t=e[0]
        if t=='bin' and e[1]=='or' and e[2][0]=='index' and e[3][0]=='call' and e[3][1][0]=='name' and e[3][1][1] in env:
            c=env[e[3][1][1]];a=e[3][2]
            if len(a)==3 and all(tonum(x) is not None for x in a):
                v=(((int(tonum(a[c[0][0]]))&M32)^c[0][1])&M32)-(((int(tonum(a[c[1][0]]))&M32)^c[1][1])&M32)
                return ('num',v)
        if t=='function':
            nb,_=resolve_block(e[3],env)
            return ('function',e[1],e[2],nb)
        return tuple([t]+[rexp(x,env) if isinstance(x,(tuple,list)) else x for x in e[1:]])
    if isinstance(e,list):return [rexp(x,env) for x in e]
    return e
def resolve_stmt(s,env):
    t=s[0]
    if t=='function':return rexp(s,env)
    out=[t]
    for x in s[1:]:
        if t in('if',) and isinstance(x,list) and x and isinstance(x[0],tuple) and len(x[0])==2 and isinstance(x[0][1],list):
            out.append([(rexp(c,env),resolve_block(b,env)[0]) for c,b in x])
        elif isinstance(x,list) and x and isinstance(x[0],tuple) and x[0] and isinstance(x[0][0],str) and x[0][0] in ('local','assign','callstat','do','while','repeat','if','fornum','forin','funcstat','localfunc','return','break','continue','nop'):
            out.append(resolve_block(x,env)[0])
        elif t=='if' and x is not None and isinstance(x,list):
            out.append(resolve_block(x,env)[0])
        elif isinstance(x,(tuple,list)):out.append(rexp(x,env))
        else:out.append(x)
    return tuple(out)
