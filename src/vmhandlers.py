import sys
sys.setrecursionlimit(100000)
from lemit import B,E
from passes import tonum
from cff import ycond

INV_HOLDS={'<':lambda s,v:s<v,'>':lambda s,v:s>v,'<=':lambda s,v:s<=v,'>=':lambda s,v:s>=v,'==':lambda s,v:s==v,'~=':lambda s,v:s!=v}

def size(n):
    if isinstance(n,(tuple,list)):
        return 1+sum(size(x) for x in n)
    return 1

def find_loops(node,acc):
    if isinstance(node,list):
        for x in node:find_loops(x,acc)
    elif isinstance(node,tuple):
        if node and node[0]=='while':
            c=node[1]
            while c[0]=='paren':c=c[1]
            if c[0]=='bin' and c[1]=='~=' and c[2][0]=='name' and tonum(c[3]) is not None:
                acc.append((size(node),c[2][1],tonum(c[3]),node))
        elif node and node[0]=='repeat':
            c=node[2]
            while c[0]=='paren':c=c[1]
            if c[0]=='bin' and c[1] in ('==','~=') and c[2][0]=='name' and tonum(c[3]) is not None:
                acc.append((size(node),c[2][1],tonum(c[3]),node))
        for x in node[1:]:
            if isinstance(x,(tuple,list)):find_loops(x,acc)

def locate(ast):
    acc=[]
    find_loops(ast,acc)
    acc.sort(key=lambda x:-x[0])
    if not acc:raise Exception('no state machine loop found')
    _,var,end,node=acc[0]
    body=node[1] if node[0]=='repeat' else node[2]
    return var,end,body

class Machine:
    def __init__(self,ast):
        self.var,self.end,self.body=locate(ast)
        self.fetch=None
        self.ovar=None
        self.start=None
        self.qvar=None
        self.scan()

    def holds(self,cd,s):
        return INV_HOLDS[cd[0]](s,cd[1])

    def leaf(self,s):
        block=self.body
        while True:
            if len(block)==1 and block[0][0]=='if':
                st=block[0];cl=st[1]
                cds=[ycond(c,self.var) for c,_ in cl]
                if all(cds):
                    for (c,b),cd in zip(cl,cds):
                        if self.holds(cd,s):
                            block=b;break
                    else:
                        block=st[2] if st[2] is not None else []
                    continue
            return block

    def leaves(self):
        import cff
        out={};warn=[]
        cff.collect(self.body,self.var,[],out,warn)
        res=list(out.values())
        for w in warn:
            if w[0]=='range':res.append(w[3])
        return res

    def scan(self):
        for b in self.leaves():
            b=[x for x in b if x[0]!='nop']
            if len(b)==2 and b[0][0]=='assign' and b[1][0]=='assign':
                a,s=b
                if len(a[1])==1 and a[1][0][0]=='name' and a[2][0][0]=='index' and a[2][0][1][0]=='name' and a[2][0][2][0]=='name':
                    if len(s[1])==2 and len(s[2])==2:
                        iv=None
                        if s[1][0]==('name',self.var):iv=0
                        elif s[1][1]==('name',self.var):iv=1
                        if iv is not None:
                            io=1-iv
                            if s[1][io][0]=='name' and tonum(s[2][iv]) is not None and s[2][io][0]=='index' and s[2][io][1]==a[1][0]:
                                self.qvar=a[1][0][1]
                                self.ovar=s[1][io][1]
                                self.start=tonum(s[2][iv])
                                self.fetch=(a,s)
                                return
        raise Exception('fetch block not found')

def uses(c,name):
    if isinstance(c,tuple):
        if c==('name',name):return True
        return any(uses(x,name) for x in c[1:] if isinstance(x,(tuple,list)))
    if isinstance(c,list):return any(uses(x,name) for x in c)
    return False

def ev(c,name,o):
    t=c[0]
    if t=='paren':return ev(c[1],name,o)
    if t=='name' and c[1]==name:return o
    if t=='num':return tonum(c)
    if t=='un' and c[1]=='not':return not ev(c[2],name,o)
    if t=='bin':
        op=c[1]
        if op=='and':return ev(c[2],name,o) and ev(c[3],name,o)
        if op=='or':return ev(c[2],name,o) or ev(c[3],name,o)
        a=ev(c[2],name,o);b=ev(c[3],name,o)
        return {'>':a>b,'<':a<b,'>=':a>=b,'<=':a<=b,'==':a==b,'~=':a!=b}[op]
    raise Exception('cond '+str(c))

def opaque(c):
    while c[0]=='paren':c=c[1]
    if c[0]=='bin' and c[1] in('~=','==') and c[2]==c[3] and c[2][0]=='name':
        return c[1]=='=='
    return None

class Tracer:
    def __init__(self,m):
        self.m=m

    def sval(self,st):
        if st[0]!='assign':return None
        for tg,vv in zip(st[1],st[2]):
            if tg==('name',self.m.var):return tonum(vv)
        return None

    def strip(self,st):
        ts=[];vs=[]
        for tg,vv in zip(st[1],st[2]):
            if tg==('name',self.m.var):continue
            ts.append(tg);vs.append(vv)
        if not ts:return None
        return ('assign',ts,vs)

    def is_fetch(self,st):
        if st[0]!='assign':return False
        q=self.m.qvar;o=self.m.ovar
        for tg in st[1]:
            if tg==('name',q) or tg==('name',o):return True
        return False

    def goto(self,s,o,seen,depth):
        if s is None:return [('end',)]
        if s==self.m.start:return [('next',)]
        if s==self.m.end:return [('exit',)]
        if s in seen or depth>80:return [('goto',s)]
        return self.run(self.m.leaf(s),None,o,seen|{s},depth+1)

    def run(self,stmts,nxt,o,seen,depth):
        out=[];stmts=list(stmts);i=0
        ov=self.m.ovar
        while i<len(stmts):
            st=stmts[i]
            if st[0]=='continue':
                return out+self.goto(nxt,o,seen,depth)
            if st[0]=='if':
                rest=stmts[i+1:]
                if len(st[1])==1:
                    c=st[1][0][0]
                    op=opaque(c)
                    if op is None and uses(c,ov):
                        op=bool(ev(c,ov,o))
                    if op is not None:
                        chosen=st[1][0][1] if op else (st[2] or [])
                        stmts=stmts[:i]+list(chosen)+rest
                        continue
                arms=[]
                for c,bb in st[1]:
                    arms.append((c,self.run(list(bb)+rest,nxt,o,seen,depth)))
                if st[2] is not None:
                    arms.append((None,self.run(list(st[2])+rest,nxt,o,seen,depth)))
                else:
                    arms.append((None,self.run(rest,nxt,o,seen,depth)))
                out.append(('cond',arms))
                return out
            n=self.sval(st)
            if n is not None:nxt=n
            y=self.strip(st) if st[0]=='assign' else st
            if y and not self.is_fetch(y):out.append(y)
            i+=1
        return out+self.goto(nxt,o,seen,depth)

    def trace(self,o):
        return self.run(self.m.leaf(self.m.start),None,o,frozenset({self.m.start}),0)

def render(tr,ind=0):
    pad='  '*ind;L=[]
    for t in tr:
        if t[0]=='cond':
            texts=[render(sub,ind+1) for c,sub in t[1]]
            if len(set(texts))==1:
                L.append(render(t[1][0][1],ind))
                continue
            first=True
            for (c,sub),tx in zip(t[1],texts):
                if c is None:L.append(pad+'else')
                else:L.append(pad+('if ' if first else 'elseif ')+E(c)+' then')
                first=False
                L.append(tx)
            L.append(pad+'end')
        elif t[0]=='goto':L.append(pad+'goto state '+str(t[1]))
        elif t[0]=='end':L.append(pad+'stop')
        elif t[0]=='next':L.append(pad+'next')
        elif t[0]=='exit':L.append(pad+'exit')
        else:L.append(B([t],ind).rstrip('\n'))
    return '\n'.join(x for x in L if x!='')

def dump_all(ast,path):
    m=Machine(ast)
    tr=Tracer(m)
    groups={}
    for o in range(256):
        try:
            txt=render(tr.trace(o))
        except Exception as e:
            txt='error: '+str(e)
        groups.setdefault(txt,[]).append(o)
    lines=['state variable: %s'%m.var,'opcode variable: %s'%m.ovar,'instruction variable: %s'%m.qvar,'dispatch start: %s'%m.start,'']
    for txt,ops in sorted(groups.items(),key=lambda kv:kv[1][0]):
        lines.append('=== opcodes %s'%(','.join(map(str,ops))))
        lines.append(txt)
        lines.append('')
    with open(path,'w',encoding='latin-1') as f:f.write('\n'.join(lines))
    return len(groups)
