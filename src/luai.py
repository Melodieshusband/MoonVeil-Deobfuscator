import struct,math
from lemit import pyval
from strdec import unlua
class BreakEx(Exception):pass
class ContinueEx(Exception):pass
class ReturnEx(Exception):
    def __init__(s,v):s.v=v
class LuaError(Exception):
    def __init__(s,v):
        Exception.__init__(s,v);s.v=v
class Scope:
    __slots__=('v','p')
    def __init__(s,p=None):
        s.v={};s.p=p
class LuaTable:
    __slots__=('h','mt','n')
    def __init__(s):
        s.h={};s.mt=None;s.n=0
    def get(s,k):
        return s.h.get(nk(k))
    def set(s,k,v):
        k=nk(k)
        if v is None:s.h.pop(k,None)
        else:s.h[k]=v
    def length(s):
        n=s.n;h=s.h
        while (n+1) in h:n+=1
        while n>0 and n not in h:n-=1
        s.n=n;return n
def nk(k):
    if k is True:return ('b',1)
    if k is False:return ('b',0)
    if isinstance(k,float) and k.is_integer():return int(k)
    return k
class LuaFunction:
    __slots__=('ps','va','body','sc','interp')
    def __init__(s,ps,va,body,sc,interp):
        s.ps=ps;s.va=va;s.body=body;s.sc=sc;s.interp=interp
def norm(x):
    if isinstance(x,float) and x.is_integer() and abs(x)<2**53:return int(x)
    return x
def truthy(v):
    return v is not None and v is not False
def isnum(v):
    return isinstance(v,(int,float)) and not isinstance(v,bool)
def tonum(v):
    if isnum(v):return v
    if isinstance(v,bytes):
        try:return norm(float(v))
        except ValueError:pass
    raise LuaError(b'attempt to perform arithmetic on a non-number value')
def tostr(v):
    if isinstance(v,bytes):return v
    if isinstance(v,bool):return b'true' if v else b'false'
    if v is None:return b'nil'
    if isinstance(v,int):return str(v).encode()
    if isinstance(v,float):
        if v!=v:return b'nan'
        if v in(float('inf'),float('-inf')):return b'inf' if v>0 else b'-inf'
        return ('%.14g'%v).encode()
    return b'table'
def leq(a,b):
    if isinstance(a,bool) or isinstance(b,bool):return a is b
    return a==b
def lt(a,b):
    if isnum(a) and isnum(b):return a<b
    if isinstance(a,bytes) and isinstance(b,bytes):return a<b
    raise LuaError(b'attempt to compare incompatible values')
def le(a,b):
    if isnum(a) and isnum(b):return a<=b
    if isinstance(a,bytes) and isinstance(b,bytes):return a<=b
    raise LuaError(b'attempt to compare incompatible values')
class Interp:
    def __init__(s):
        s.G=LuaTable()
        s.glob=s.G
        s.strlib=LuaTable()
    def lookup(s,sc,name):
        while sc is not None:
            d=sc.v
            if name in d:return d
            sc=sc.p
        return None
    def getvar(s,sc,name):
        while sc is not None:
            d=sc.v
            if name in d:return d[name]
            sc=sc.p
        return s.G.get(name.encode('latin-1'))
    def setvar(s,sc,name,val):
        d=s.lookup(sc,name)
        if d is not None:d[name]=val
        else:s.G.set(name.encode('latin-1'),val)
    def index(s,o,k):
        if isinstance(o,LuaTable):
            v=o.h.get(nk(k))
            if v is not None or o.mt is None:return v
            mi=o.mt.get(b'__index')
            if mi is None:return None
            if isinstance(mi,LuaTable):return s.index(mi,k)
            r=s.call(mi,[o,k])
            return r[0] if r else None
        if isinstance(o,bytes):
            return s.strlib.get(k)
        raise LuaError(b'attempt to index a non-table value')
    def setindex(s,o,k,v):
        if isinstance(o,LuaTable):
            if o.mt is not None and nk(k) not in o.h:
                ni=o.mt.get(b'__newindex')
                if ni is not None:
                    if isinstance(ni,LuaTable):return s.setindex(ni,k,v)
                    s.call(ni,[o,k,v]);return
            o.set(k,v);return
        raise LuaError(b'attempt to index a non-table value')
    def call(s,f,args):
        if isinstance(f,LuaFunction):
            sc=Scope(f.sc)
            ps=f.ps
            for i,p in enumerate(ps):
                sc.v[p]=args[i] if i<len(args) else None
            if f.va:sc.v['...']=list(args[len(ps):])
            try:
                s.block(f.body,sc)
            except ReturnEx as r:
                return r.v
            return []
        if callable(f):
            r=f(*args)
            if r is None:return []
            return r
        if isinstance(f,LuaTable) and f.mt is not None:
            c=f.mt.get(b'__call')
            if c is not None:return s.call(c,[f]+list(args))
        raise LuaError(b'attempt to call a non-function value')
    def evm(s,e,sc):
        t=e[0]
        if t=='call':
            f=s.ev(e[1],sc)
            return s.call(f,s.args(e[2],sc))
        if t=='mcall':
            o=s.ev(e[1],sc)
            f=s.index(o,e[2].encode('latin-1'))
            return s.call(f,[o]+s.args(e[3],sc))
        if t=='vararg':
            return list(s.getvar(sc,'...') or [])
        return [s.ev(e,sc)]
    def args(s,es,sc):
        out=[]
        n=len(es)
        for i,a in enumerate(es):
            if i==n-1:out.extend(s.evm(a,sc))
            else:out.append(s.ev(a,sc))
        return out
    def ev(s,e,sc):
        t=e[0]
        if t=='name':return s.getvar(sc,e[1])
        if t=='num':
            v=e[1]
            if isinstance(v,str):v=pyval(v)
            return v
        if t=='str':
            v=e[1]
            if v[0]=='[':
                i=v.index('[',1);eq=v[1:i]
                return v[i+1:-(len(eq)+2)].encode('latin-1')
            return unlua(v)
        if t=='nil':return None
        if t=='true':return True
        if t=='false':return False
        if t=='paren':return s.ev(e[1],sc)
        if t=='index':
            return s.index(s.ev(e[1],sc),s.ev(e[2],sc))
        if t=='call' or t=='mcall':
            r=s.evm(e,sc)
            return r[0] if r else None
        if t=='vararg':
            r=s.getvar(sc,'...')
            return r[0] if r else None
        if t=='bin':return s.binop(e,sc)
        if t=='un':
            o=e[1];v=s.ev(e[2],sc)
            if o=='not':return not truthy(v)
            if o=='-':return norm(-tonum(v))
            if o=='#':
                if isinstance(v,bytes):return len(v)
                return v.length()
            raise LuaError(b'bad unary')
        if t=='function':
            return LuaFunction(e[1],e[2],e[3],sc,s)
        if t=='table':
            tb=LuaTable();ar=1;items=e[1]
            for i,it in enumerate(items):
                if it[0]=='kv':
                    tb.set(s.ev(it[1],sc),s.ev(it[2],sc))
                else:
                    if i==len(items)-1:
                        for v in s.evm(it[1],sc):
                            tb.set(ar,v);ar+=1
                    else:
                        tb.set(ar,s.ev(it[1],sc));ar+=1
            return tb
        if t=='ifexp':
            for c,a in e[1]:
                if truthy(s.ev(c,sc)):return s.ev(a,sc)
            return s.ev(e[2],sc)
        raise LuaError(('bad expr '+t).encode())
    def binop(s,e,sc):
        o=e[1]
        if o=='and':
            a=s.ev(e[2],sc)
            return s.ev(e[3],sc) if truthy(a) else a
        if o=='or':
            a=s.ev(e[2],sc)
            return a if truthy(a) else s.ev(e[3],sc)
        a=s.ev(e[2],sc);b=s.ev(e[3],sc)
        if o=='==':return leq(a,b)
        if o=='~=':return not leq(a,b)
        if o=='<':return lt(a,b)
        if o=='>':return lt(b,a)
        if o=='<=':return le(a,b)
        if o=='>=':return le(b,a)
        if o=='..':
            return tostr(a)+tostr(b)
        a=tonum(a);b=tonum(b)
        if o=='+':return norm(a+b)
        if o=='-':return norm(a-b)
        if o=='*':return norm(a*b)
        if o=='/':
            if b==0:
                if a==0 or a!=a:return float('nan')
                return float('inf') if a>0 else float('-inf')
            return norm(a/b)
        if o=='%':
            if b==0:return float('nan')
            return norm(a-math.floor(a/b)*b)
        if o=='//':
            if b==0:return float('inf')
            return norm(math.floor(a/b))
        if o=='^':
            try:return norm(float(a)**b)
            except Exception:return float('nan')
        raise LuaError(('bad op '+o).encode())
    def block(s,b,sc):
        for st in b:
            s.stat(st,sc)
    def stat(s,st,sc):
        t=st[0]
        if t=='assign':
            ts=st[1]
            vals=s.args(st[2],sc)
            for i,tg in enumerate(ts):
                v=vals[i] if i<len(vals) else None
                if tg[0]=='name':s.setvar(sc,tg[1],v)
                else:s.setindex(s.ev(tg[1],sc),s.ev(tg[2],sc),v)
            return
        if t=='local':
            vals=s.args(st[2],sc) if st[2] else []
            for i,n in enumerate(st[1]):
                sc.v[n]=vals[i] if i<len(vals) else None
            return
        if t=='callstat':
            s.evm(st[1],sc);return
        if t=='if':
            for c,b in st[1]:
                if truthy(s.ev(c,sc)):
                    s.block(b,Scope(sc));return
            if st[2] is not None:s.block(st[2],Scope(sc))
            return
        if t=='while':
            while truthy(s.ev(st[1],sc)):
                try:s.block(st[2],Scope(sc))
                except BreakEx:break
                except ContinueEx:continue
            return
        if t=='repeat':
            while True:
                bs=Scope(sc)
                try:s.block(st[1],bs)
                except BreakEx:break
                except ContinueEx:pass
                if truthy(s.ev(st[2],bs)):break
            return
        if t=='do':
            s.block(st[1],Scope(sc));return
        if t=='fornum':
            a=tonum(s.ev(st[2],sc));b=tonum(s.ev(st[3],sc))
            c=tonum(s.ev(st[4],sc)) if st[4] else 1
            i=a
            while (c>0 and i<=b) or (c<=0 and i>=b):
                bs=Scope(sc);bs.v[st[1]]=i
                try:s.block(st[5],bs)
                except BreakEx:break
                except ContinueEx:pass
                i=norm(i+c)
            return
        if t=='forin':
            vals=s.args(st[2],sc)
            while len(vals)<3:vals.append(None)
            f,state,ctl=vals[0],vals[1],vals[2]
            if f is lua_next and isinstance(state,LuaTable):
                for k,v in list(state.h.items()):
                    if state.h.get(k) is None:continue
                    if isinstance(k,tuple):k=bool(k[1])
                    bs=Scope(sc)
                    bs.v[st[1][0]]=k
                    if len(st[1])>1:bs.v[st[1][1]]=v
                    try:s.block(st[3],bs)
                    except BreakEx:break
                    except ContinueEx:pass
                return
            while True:
                r=s.call(f,[state,ctl])
                if not r or r[0] is None:break
                ctl=r[0]
                bs=Scope(sc)
                for i,n in enumerate(st[1]):
                    bs.v[n]=r[i] if i<len(r) else None
                try:s.block(st[3],bs)
                except BreakEx:break
                except ContinueEx:pass
            return
        if t=='localfunc':
            sc.v[st[1]]=None
            sc.v[st[1]]=LuaFunction(st[2][1],st[2][2],st[2][3],sc,s)
            return
        if t=='funcstat':
            f=LuaFunction(st[3][1],st[3][2],st[3][3],sc,s)
            names=st[1]
            if len(names)==1:
                s.setvar(sc,names[0],f);return
            o=s.getvar(sc,names[0])
            for n in names[1:-1]:o=s.index(o,n.encode('latin-1'))
            s.setindex(o,names[-1].encode('latin-1'),f);return
        if t=='return':
            raise ReturnEx(s.args(st[1],sc))
        if t=='break':raise BreakEx()
        if t=='continue':raise ContinueEx()
        if t=='nop':return
        raise LuaError(('bad stat '+t).encode())
def lua_next(t,k=None):
    it=list(t.h.keys())
    if k is None:
        return [it[0],t.h[it[0]]] if it else [None]
    k=nk(k)
    i=it.index(k)+1
    if i<len(it):return [it[i],t.h[it[i]]]
    return [None]
M32=0xFFFFFFFF
def toint(v):
    if isinstance(v,float):v=int(math.floor(v))
    return v&M32
def b_xor(*a):
    r=0
    for x in a:r^=toint(x)
    return [r]
def b_and(*a):
    r=M32
    for x in a:r&=toint(x)
    return [r]
def b_or(*a):
    r=0
    for x in a:r|=toint(x)
    return [r]
def b_not(a):return [(~toint(a))&M32]
def b_lshift(x,n):
    n=int(n);x=toint(x)
    if n<0:return [x>>(-n) if -n<32 else 0]
    return [(x<<n)&M32 if n<32 else 0]
def b_rshift(x,n):
    n=int(n);x=toint(x)
    if n<0:return [(x<<(-n))&M32 if -n<32 else 0]
    return [x>>n if n<32 else 0]
def b_btest(*a):
    r=M32
    for x in a:r&=toint(x)
    return [r!=0]
def b_extract(n,f,w=1):
    return [(toint(n)>>int(f))&((1<<int(w))-1)]
def b_arshift(x,n):
    x=toint(x);n=int(n)
    if x&0x80000000:x-=1<<32
    return [(x>>n)&M32]
def b_lrotate(x,n):
    x=toint(x);n=int(n)%32
    return [((x<<n)|(x>>(32-n)))&M32]
def b_rrotate(x,n):
    x=toint(x);n=int(n)%32
    return [((x>>n)|(x<<(32-n)))&M32]
def s_unpack(fmt,data,pos=1):
    fmt=fmt.decode()
    if not fmt:raise LuaError(b'bad format')
    p=int(pos)-1
    little=True
    if fmt[0] in '<>=':
        little=fmt[0]!='>';f=fmt[1:]
    else:
        f=fmt
    c=f[0];num=f[1:]
    if c=='c':
        n=int(num);return [data[p:p+n],p+n+1]
    if c=='d':
        v=struct.unpack('<d' if little else '>d',data[p:p+8])[0];return [norm(v),p+9]
    if c=='f':
        v=struct.unpack('<f' if little else '>f',data[p:p+4])[0];return [norm(v),p+5]
    sizes={'B':1,'b':1,'H':2,'h':2,'L':4,'l':4,'I':int(num) if num else 4,'i':int(num) if num else 4}
    n=sizes[c]
    if p+n>len(data):raise LuaError(b'data string too short')
    v=int.from_bytes(data[p:p+n],'little' if little else 'big',signed=c in 'bhli')
    return [v,p+n+1]
def s_sub(s,i,j=-1):
    n=len(s);i=int(i);j=int(j)
    if i<0:i=max(n+i+1,1)
    elif i==0:i=1
    if j<0:j=n+j+1
    elif j>n:j=n
    return [s[i-1:j] if i<=j else b'']
def s_byte(s,i=1,j=None):
    n=len(s);i=int(i)
    if j is None:j=i
    j=int(j)
    if i<0:i=n+i+1
    if j<0:j=n+j+1
    return list(s[max(i,1)-1:min(j,n)])
def s_char(*a):
    return [bytes(int(x)&255 for x in a)]
def s_len(s):return [len(s)]
def s_rep(s,n):return [s*int(n)]
def t_insert(t,a,b=None):
    if b is None:
        t.set(t.length()+1,a)
    else:
        n=t.length();a=int(a)
        for i in range(n,a-1,-1):t.set(i+1,t.get(i))
        t.set(a,b)
    return []
def t_concat(t,sep=b'',i=1,j=None):
    if j is None:j=t.length()
    return [sep.join(tostr(t.get(k)) for k in range(int(i),int(j)+1))]
def t_pack(*a):
    t=LuaTable()
    for i,v in enumerate(a):t.set(i+1,v)
    t.set(b'n',len(a));return [t]
def t_unpack(t,i=1,j=None):
    if j is None:j=t.length()
    return [t.get(k) for k in range(int(i),int(j)+1)]
def t_create(n,v=None):
    t=LuaTable()
    if v is not None:
        for i in range(1,int(n)+1):t.set(i,v)
    return [t]
def t_move(a,f,e,t,b=None):
    if b is None:b=a
    f=int(f);e=int(e);t=int(t)
    vals=[a.get(i) for i in range(f,e+1)]
    for i,v in enumerate(vals):b.set(t+i,v)
    return [b]
def l_select(n,*a):
    if n==b'#':return [len(a)]
    n=int(n)
    if n<0:n=len(a)+n+1
    return list(a[n-1:])
def l_type(v):
    if v is None:return [b'nil']
    if isinstance(v,bool):return [b'boolean']
    if isnum(v):return [b'number']
    if isinstance(v,bytes):return [b'string']
    if isinstance(v,LuaTable):return [b'table']
    return [b'function']
def l_setmt(t,m):
    t.mt=m;return [t]
def l_getmt(t):
    return [t.mt if isinstance(t,LuaTable) else None]
def l_pairs(t):
    return [lua_next,t,None]
def l_ipairs(t):
    def it(tt,i):
        i=i+1;v=tt.get(i)
        return [i,v] if v is not None else [None]
    return [it,t,0]
def l_error(m=None,lv=None):
    raise LuaError(m)
def l_assert(v=None,m=b'assertion failed!',*a):
    if not truthy(v):raise LuaError(m)
    return [v]+list(a)
def l_tonumber(v,base=None):
    if isnum(v):return [v]
    if isinstance(v,bytes):
        try:
            if base is not None:return [int(v,int(base))]
            return [pyval(v.decode())]
        except Exception:return [None]
    return [None]
def l_tostring(v):return [tostr(v)]
def make_interp():
    it=Interp()
    def lib(d):
        t=LuaTable()
        for k,v in d.items():t.set(k.encode(),v)
        return t
    it.strlib=lib({'unpack':s_unpack,'sub':s_sub,'byte':s_byte,'char':s_char,'len':s_len,'rep':s_rep})
    G=it.G
    def pcall(f,*a):
        try:
            return [True]+it.call(f,list(a))
        except LuaError as e:
            return [False,e.v]
    G.set(b'string',it.strlib)
    G.set(b'bit32',lib({'bxor':b_xor,'band':b_and,'bor':b_or,'bnot':b_not,'lshift':b_lshift,'rshift':b_rshift,'btest':b_btest,'extract':b_extract,'arshift':b_arshift,'lrotate':b_lrotate,'rrotate':b_rrotate}))
    G.set(b'table',lib({'insert':t_insert,'concat':t_concat,'pack':t_pack,'unpack':t_unpack,'create':t_create,'move':t_move}))
    G.set(b'coroutine',lib({}))
    G.set(b'math',lib({'floor':lambda x:[math.floor(x)],'ceil':lambda x:[math.ceil(x)],'abs':lambda x:[abs(x)],'huge':float('inf')}))
    for k,v in {'type':l_type,'select':l_select,'setmetatable':l_setmt,'getmetatable':l_getmt,'pairs':l_pairs,'ipairs':l_ipairs,'error':l_error,'assert':l_assert,'tonumber':l_tonumber,'tostring':l_tostring,'pcall':pcall,'next':lua_next,'unpack':t_unpack}.items():
        G.set(k.encode(),v)
    G.set(b'getfenv',lambda *a:[G])
    return it
