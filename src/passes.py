import math
from lemit import pyval
M32=0xFFFFFFFF
def tonum(e):
    if e[0]=='num':
        v=e[1]
        return pyval(v) if isinstance(v,str) else v
    return None
def walk(n,f):
    if isinstance(n,list):
        return [walk(x,f) for x in n]
    if isinstance(n,tuple):
        if n and isinstance(n[0],str):
            n=tuple([n[0]]+[walk(x,f) for x in n[1:]])
            return f(n)
        return tuple(walk(x,f) for x in n)
    return n
def fold(n):
    if n[0]=='bin':
        a=tonum(n[2]);b=tonum(n[3]);op=n[1]
        if a is not None and b is not None:
            try:
                if op=='+':r=a+b
                elif op=='-':r=a-b
                elif op=='*':r=a*b
                elif op=='/':r=a/b
                elif op=='%':r=a-math.floor(a/b)*b
                elif op=='^':r=float(a)**b
                else:return n
                if isinstance(r,float) and r.is_integer() and abs(r)<2**53:r=int(r)
                return ('num',r)
            except Exception:return n
    if n[0]=='un' and n[1]=='-':
        a=tonum(n[2])
        if a is not None:return ('num',-a)
    if n[0]=='paren' and n[1][0]=='num':return n[1]
    return n
