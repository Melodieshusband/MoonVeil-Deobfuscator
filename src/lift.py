import sys,os,re
from vmdecode import load,decode_proto

KW={'and','break','do','else','elseif','end','false','for','function','goto','if','in','local','nil','not','or','repeat','return','then','true','until','while','continue'}
IDENT=re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PFX='vwxyzabcdefghijklmnopqrstu'
ATOM=10
RANK={'pure':0,'mem':1,'table':2,'call':3,'multi':3}
CONDOPS=('JUMPIF','JUMPIFNOT','JUMPIFEQ','JUMPIFNOTEQ','JUMPIFLT','JUMPIFNOTLT','JUMPIFLE','JUMPIFNOTLE','JUMPEQK','JUMPNIL','JUMPEQB')
CTRL=set(CONDOPS)|{'JUMP','RETURN','FORNPREP','FORNLOOP','FORGPREP','FORGLOOP'}
ALLK=('pure','mem','table','call','multi')
STOREK=('mem','table','call','multi')
EFFK=('call','multi')
STATS={'functions':0,'gotos':0,'instructions':0}
CACHE={}

def quote(s):
    o=['"']
    for ch in s:
        n=ord(ch)
        if ch=='"':o.append('\\"')
        elif ch=='\\':o.append('\\\\')
        elif ch=='\n':o.append('\\n')
        elif ch=='\r':o.append('\\r')
        elif ch=='\t':o.append('\\t')
        elif 32<=n<127:o.append(ch)
        else:o.append('\\%03d'%n)
    o.append('"')
    return ''.join(o)

def lit(k):
    if k is None:return ('nil',ATOM)
    if k is True:return ('true',ATOM)
    if k is False:return ('false',ATOM)
    if isinstance(k,str):return (quote(k),ATOM)
    if isinstance(k,float):
        t=repr(k)
        if t.endswith('.0'):t=t[:-2]
    else:t=str(k)
    return (t,8 if t.startswith('-') else ATOM)

def idx(k):
    if isinstance(k,str):
        if IDENT.match(k) and k not in KW:return '.'+k
        return '['+quote(k)+']'
    return '['+lit(k)[0]+']'

def par(e,p):
    t,q=e
    return '('+t+')' if q<p else t

def objtext(e):
    t,q=e
    if q<ATOM or t.startswith('"') or t.startswith('{'):return '('+t+')'
    return t

class Gen:
    def __init__(self,p,depth,ups,labels):
        self.p=p;self.depth=depth;self.ups=ups;self.labels=labels
        self.code=p['code'];self.n=len(self.code);self.np=p['nparams']
        self.pc2i={c['pc']:i for i,c in enumerate(self.code)}
        self.tgt={};self.skip={}
        for i,c in enumerate(self.code):
            t=c.get('target')
            if t is None:continue
            ti=self.pc2i.get(t,self.n)
            if c['op']=='LOADB':
                self.skip[i]=ti>i+1
                if ti>i+1:self.tgt[i]=ti
            else:
                self.tgt[i]=ti
        self.vararg=any(c['op']=='GETVARARGS' for c in self.code)
        self.leaders=set(self.tgt.values())
        self.heads={}
        for i,t in self.tgt.items():
            op=self.code[i]['op']
            if op in('FORNLOOP','FORGLOOP','LOADB','FORGPREP','FORNPREP'):continue
            if t<=i:self.heads[t]=max(self.heads.get(t,0),i+1)
        self.rwc=[self.rw(i) for i in range(self.n)]

    def mtop(self,i):
        for j in range(i-1,-1,-1):
            c=self.code[j]
            if c['op']=='CALL' and c['nres']==-1:return c['a']
            if c['op']=='GETVARARGS' and c['n']==-1:return c['a']
        return self.code[i-1]['a']

    def rw(self,i):
        c=self.code[i];op=c['op']
        if op=='MOVE':return [c['b']],[c['a']]
        if op in('LOADNIL','LOADN','LOADK','GETUPVAL','GETIMPORT','NEWTABLE','LOADB'):return [],[c['a']]
        if op=='SETUPVAL':return [c['a']],[]
        if op=='GETTABLE':return [c['t'],c['k']],[c['a']]
        if op in('GETFIELD','GETTABLEN'):return [c['t']],[c['a']]
        if op in('SETFIELD','SETTABLEN'):return [c['t'],c['v']],[]
        if op=='SETTABLE':return [c['t'],c['k'],c['v']],[]
        if op=='SETGLOBAL':return [c['v']],[]
        if op=='NAMECALL':return [c['o']],[c['a'],c['a']+1]
        if op=='CALL':
            a=c['a'];na=c['nargs'];nr=c['nres']
            r=list(range(a,a+na+1)) if na>=0 else list(range(a,self.mtop(i)+1))
            w=list(range(a,a+nr)) if nr>=0 else [a]
            return r,w
        if op=='RETURN':
            a=c['a'];n=c['n']
            return (list(range(a,a+n)) if n>=0 else list(range(a,self.mtop(i)+1))),[]
        if op=='GETVARARGS':
            a=c['a'];n=c['n']
            return [],(list(range(a,a+n)) if n>=0 else [a])
        if op=='SETLIST':
            s=c['src'];n=c['n']
            return [c['t']]+(list(range(s,s+n)) if n>=0 else list(range(s,self.mtop(i)+1))),[]
        if op=='CONCAT':return list(range(c['first'],c['last']+1)),[c['a']]
        if op in('ADD','SUB','MUL','DIV'):return [c['b'],c['c']],[c['a']]
        if op in('ADDK','SUBK','MULK','SUBRK','ORK','NOT','LEN'):return [c['b']],[c['a']]
        if op in('JUMPIF','JUMPIFNOT','JUMPEQK','JUMPNIL','JUMPEQB'):return [c['a']],[]
        if op in('JUMPIFEQ','JUMPIFNOTEQ','JUMPIFLT','JUMPIFNOTLT','JUMPIFLE','JUMPIFNOTLE'):return [c['a'],c['b']],[]
        if op=='FORNPREP':a=c['a'];return [a,a+1,a+2],[a+3]
        if op=='FORNLOOP':return [],[c['a']+3]
        if op=='FORGPREP':
            a=c['a'];j=self.tgt.get(i,self.n)
            nv=self.nvars(j)
            return [a,a+1,a+2],list(range(a+3,a+3+nv))
        if op=='FORGLOOP':
            return [],list(range(c['a']+3,c['a']+3+self.nvars(i)))
        if op=='CLOSURE':return [B for A,B in c['caps'] if A in(0,1)],[c['a']]
        return [],[]

    def nvars(self,j):
        if j<self.n and self.code[j]['op']=='FORGLOOP':
            v=self.code[j].get('nvars')
            if isinstance(v,int):
                v&=255
                if v>0:return v
        return 1

    def succ(self,i):
        c=self.code[i];op=c['op']
        if op=='RETURN':return []
        if op=='JUMP':return [self.tgt[i]]
        if op=='LOADB':return [self.tgt[i]] if self.skip[i] else [i+1]
        if op=='FORGPREP':return [self.tgt[i]]
        if op in CONDOPS or op in('FORNPREP','FORNLOOP','FORGLOOP'):return [i+1,self.tgt[i]]
        return [i+1]

    def readers(self,i,reg,tbl=False):
        seen=set();found=set()
        stack=[j for j in self.succ(i) if j<self.n]
        while stack:
            j=stack.pop()
            if j in seen or j>=self.n:continue
            seen.add(j)
            r,w=self.rwc[j]
            if tbl:
                c=self.code[j]
                if c['op'] in('SETFIELD','SETTABLE','SETTABLEN','SETLIST') and c['t']==reg:
                    found.add((j,'c'))
                    stack.extend(self.succ(j))
                    continue
            if reg in r:found.add((j,'r'))
            if reg in w:continue
            stack.extend(self.succ(j))
        return found

    def straight(self,i,j):
        for k in range(i+1,j+1):
            if k in self.leaders:return False
        for k in range(i+1,j):
            if self.code[k]['op'] in CTRL or (self.code[k]['op']=='LOADB' and self.skip[k]):return False
        return True

    def inl(self,i,reg):
        f=self.readers(i,reg)
        if len(f)!=1:return False
        j=next(iter(f))[0]
        if j<=i:return False
        if self.rwc[j][0].count(reg)!=1:return False
        return self.straight(i,j)

    def tbl_inl(self,i,reg):
        f=self.readers(i,reg,True)
        real=[j for j,k in f if k=='r']
        cons=[j for j,k in f if k=='c']
        if len(real)!=1:return None
        j=real[0]
        if j<=i or self.rwc[j][0].count(reg)!=1:return None
        if any(k>j for k in cons):return None
        if not self.straight(i,j):return None
        return j

    def name(self,r):
        self.used.add(r)
        return PFX[self.depth%len(PFX)]+str(r)

    def upname(self,u):
        return self.ups[u] if u<len(self.ups) else 'u%d'%u

    def emit(self,text,ind=None):
        if ind is None:ind=len(self.stack)
        pad='  '*ind
        self.lines.append(pad+text.replace('\n','\n'+pad))

    def begin(self):
        self.cur=set();self.ck='pure'

    def bump(self,kind):
        if RANK[kind]>RANK[self.ck]:self.ck=kind

    def pexpr(self,P):
        if 'items' in P:return ('{'+', '.join(P['items'])+'}',ATOM)
        return P['e']

    def assign(self,reg,expr):
        t=self.name(reg)
        self.assigned.add(reg)
        s=par(expr,0)
        if s==t:return
        self.emit(t+' = '+s)

    def flush(self,reg):
        P=self.pend.pop(reg)
        self.assign(reg,self.pexpr(P))

    def flush_kinds(self,kinds):
        for k in list(self.pend):
            P=self.pend.get(k)
            if P is not None and P['kind'] in kinds:self.flush(k)

    def flush_write(self,reg):
        for k in list(self.pend):
            P=self.pend.get(k)
            if P is None:continue
            if k==reg or reg in P['deps']:self.flush(k)

    def get(self,reg):
        P=self.pend.get(reg)
        if P is not None:
            if 'items' in P:
                if P['j'] is not None:
                    del self.pend[reg];self.cur|=P['deps'];self.bump('table')
                    return self.pexpr(P)
                self.flush(reg)
            else:
                del self.pend[reg];self.cur|=P['deps'];self.bump(P['kind'])
                return P['e']
        self.cur.add(reg)
        return (self.name(reg),ATOM)

    def define(self,i,reg,expr,base):
        kind=base
        if RANK[self.ck]>RANK[kind]:kind=self.ck
        deps=set(self.cur)
        self.flush_write(reg)
        if kind in EFFK:self.flush_kinds(EFFK)
        if kind=='multi' or self.inl(i,reg):
            self.pend[reg]={'e':expr,'deps':deps,'kind':kind}
        else:
            self.assign(reg,expr)

    def loop(self):
        for b in reversed(self.stack):
            if b['kind'] in('while','for'):return b
        return None

    def goto(self,T):
        self.gotos.add(T)
        self.emit('goto L%d'%T)

    def close_to(self,k):
        while len(self.stack)>k+1:
            self.stack.pop();self.emit('end')
        self.stack.pop();self.emit('end')

    def find_while(self,T,end=None):
        for k in range(len(self.stack)-1,-1,-1):
            b=self.stack[k]
            if b['kind']=='while' and b['head']==T and (end is None or b['end']==end):return k
        return None

    def jump_to(self,i,T):
        L=self.loop()
        if T>i:
            if L and T==L['end']:
                self.emit('break');return
            top=self.stack[-1] if self.stack else None
            if top and top['kind']=='if' and top['end']==i+1 and T>i+1:
                parent=self.stack[-2] if len(self.stack)>1 else None
                if parent is None or T<=parent['end']:
                    self.emit('else',len(self.stack)-1)
                    top['kind']='else';top['end']=T
                    return
            if L and L['kind']=='for' and T==L['end']-1:
                self.emit('continue');return
            self.goto(T)
        else:
            k=self.find_while(T,i+1)
            if k is not None:
                self.close_to(k);return
            if self.find_while(T) is not None:
                self.emit('continue');return
            self.goto(T)

    def cond_jump(self,i,body,jump):
        T=self.tgt[i]
        self.flush_kinds(ALLK)
        L=self.loop()
        if T>i:
            if L and T==L['end']:
                self.emit('if %s then break end'%jump);return
            if L and L['kind']=='for' and T==L['end']-1:
                self.emit('if %s then continue end'%jump);return
            lim=self.stack[-1]['end'] if self.stack else self.n+1
            if T<=lim:
                self.emit('if %s then'%body)
                self.stack.append({'kind':'if','end':T})
                return
            self.gotos.add(T)
            self.emit('if %s then goto L%d end'%(jump,T))
        else:
            k=self.find_while(T,i+1)
            if k is not None:
                self.emit('if %s then break end'%body)
                self.close_to(k);return
            if self.find_while(T) is not None:
                self.emit('if %s then continue end'%jump);return
            self.gotos.add(T)
            self.emit('if %s then goto L%d end'%(jump,T))

    def conds(self,c):
        op=c['op'];x=self.get(c['a'])
        if op=='JUMPIF':
            t=par(x,8)
            return 'not '+t,par(x,0)
        if op=='JUMPIFNOT':
            return par(x,0),'not '+par(x,8)
        if op in('JUMPEQK','JUMPNIL','JUMPEQB'):
            if op=='JUMPEQK':k=lit(c['k'])[0]
            elif op=='JUMPNIL':k='nil'
            else:k='true' if c['k'] else 'false'
            eq=par(x,4)+' == '+k
            ne=par(x,4)+' ~= '+k
            if c['neg']:return eq,ne
            return ne,eq
        y=self.get(c['b'])
        a=par(x,4);b=par(y,4)
        if op=='JUMPIFEQ':return a+' ~= '+b,a+' == '+b
        if op=='JUMPIFNOTEQ':return a+' == '+b,a+' ~= '+b
        if op=='JUMPIFLT':return 'not ('+a+' < '+b+')',a+' < '+b
        if op=='JUMPIFNOTLT':return a+' < '+b,'not ('+a+' < '+b+')'
        if op=='JUMPIFLE':return 'not ('+a+' <= '+b+')',a+' <= '+b
        return a+' <= '+b,'not ('+a+' <= '+b+')'

    def o_cond(self,i,c):
        self.begin()
        for r in (c.get('a'),c.get('b')):
            if r is not None and r in self.pend:
                e=self.pend[r]['e']
                if isinstance(e,tuple) and '\n' in e[0]:self.flush(r)
        body,jump=self.conds(c)
        self.cond_jump(i,body,jump)

    o_JUMPIF=o_JUMPIFNOT=o_JUMPIFEQ=o_JUMPIFNOTEQ=o_JUMPIFLT=o_JUMPIFNOTLT=o_JUMPIFLE=o_JUMPIFNOTLE=o_JUMPEQK=o_JUMPNIL=o_JUMPEQB=o_cond

    def o_JUMP(self,i,c):
        self.begin()
        self.flush_kinds(ALLK)
        self.jump_to(i,self.tgt[i])

    def o_MOVE(self,i,c):
        self.begin()
        x=self.get(c['b'])
        self.define(i,c['a'],x,'pure')

    def o_LOADNIL(self,i,c):
        self.begin();self.define(i,c['a'],lit(None),'pure')

    def o_LOADN(self,i,c):
        self.begin();self.define(i,c['a'],lit(c['value']),'pure')

    def o_LOADK(self,i,c):
        self.begin();self.define(i,c['a'],lit(c['k']),'pure')

    def o_LOADB(self,i,c):
        self.begin()
        a=c['a']
        if self.skip[i]:
            self.flush_kinds(ALLK)
            self.flush_write(a)
            self.assign(a,lit(c['value']))
            self.jump_to(i,self.tgt[i])
        else:
            self.define(i,a,lit(c['value']),'pure')

    def o_GETUPVAL(self,i,c):
        self.begin();self.define(i,c['a'],(self.upname(c['u']),ATOM),'mem')

    def o_SETUPVAL(self,i,c):
        self.begin()
        x=self.get(c['a'])
        t=self.upname(c['u'])+' = '+par(x,0)
        self.flush_kinds(STOREK)
        self.emit(t)

    def o_GETIMPORT(self,i,c):
        self.begin()
        p=c['path']
        t=str(p[0])+''.join(idx(x) for x in p[1:])
        self.define(i,c['a'],(t,ATOM),'mem')

    def o_GETFIELD(self,i,c):
        self.begin()
        o=self.get(c['t'])
        self.define(i,c['a'],(objtext(o)+idx(c['k']),ATOM),'mem')

    def o_GETTABLE(self,i,c):
        self.begin()
        o=self.get(c['t']);k=self.get(c['k'])
        self.define(i,c['a'],(objtext(o)+'['+par(k,0)+']',ATOM),'mem')

    def o_GETTABLEN(self,i,c):
        self.begin()
        o=self.get(c['t'])
        self.define(i,c['a'],(objtext(o)+'[%d]'%c['n'],ATOM),'mem')

    def o_SETFIELD(self,i,c):
        self.begin()
        t=c['t'];v=c['v']
        P=self.pend.get(t)
        if P is not None and 'items' in P:
            Pv=self.pend.get(v)
            if Pv is not None and Pv['kind'] in EFFK and P['j']!=i+1:
                self.flush(t);P=None
        if P is not None and 'items' in P:
            val=self.get(v)
            k=c['k']
            key=k if isinstance(k,str) and IDENT.match(k) and k not in KW else '['+(quote(k) if isinstance(k,str) else lit(k)[0])+']'
            P['items'].append(key+' = '+par(val,0))
            P['deps']|=self.cur
            return
        o=self.get(t);val=self.get(v)
        text=objtext(o)+idx(c['k'])+' = '+par(val,0)
        self.flush_kinds(STOREK)
        self.emit(text)

    def o_SETTABLE(self,i,c):
        self.begin()
        o=self.get(c['t']);k=self.get(c['k']);val=self.get(c['v'])
        text=objtext(o)+'['+par(k,0)+'] = '+par(val,0)
        self.flush_kinds(STOREK)
        self.emit(text)

    def o_SETTABLEN(self,i,c):
        self.begin()
        o=self.get(c['t']);val=self.get(c['v'])
        text=objtext(o)+'[%d] = '%c['n']+par(val,0)
        self.flush_kinds(STOREK)
        self.emit(text)

    def o_SETGLOBAL(self,i,c):
        self.begin()
        val=self.get(c['v']);k=c['k']
        key=k if isinstance(k,str) and IDENT.match(k) and k not in KW else '_G['+(quote(k) if isinstance(k,str) else lit(k)[0])+']'
        self.flush_kinds(STOREK)
        self.emit(key+' = '+par(val,0))

    def o_NEWTABLE(self,i,c):
        self.begin()
        a=c['a']
        self.flush_write(a)
        self.pend[a]={'kind':'table','items':[],'deps':set(),'narr':0,'j':self.tbl_inl(i,a)}

    def o_SETLIST(self,i,c):
        self.begin()
        t=c['t'];s=c['src'];n=c['n'];start=c['start']
        top=self.mtop(i) if n==-1 else s+n-1
        regs=list(range(s,top+1))
        P=self.pend.get(t)
        if P is not None and 'items' in P:
            risky=any(self.pend.get(r) is not None and self.pend[r]['kind'] in EFFK for r in regs)
            if (risky and P['j']!=i+1) or start!=P['narr']+1:
                self.flush(t);P=None
        if P is not None and 'items' in P:
            vals=[par(self.get(r),0) for r in regs]
            P['items']+=vals
            P['narr']+=len(vals)
            P['deps']|=self.cur
            return
        o=self.get(t)
        vals=[self.get(r) for r in regs]
        lines=[]
        multi=n==-1
        for k,v in enumerate(vals):
            if multi and k==len(vals)-1:
                lines.append('table.move({%s},1,select("#",%s),%d,%s)'%(par(v,0),par(v,0),start+k,objtext(o)))
            else:
                lines.append(objtext(o)+'[%d] = %s'%(start+k,par(v,0)))
        self.flush_kinds(STOREK)
        for l in lines:self.emit(l)

    def o_NAMECALL(self,i,c):
        self.begin()
        a=c['a'];o=c['o'];k=c['k']
        P=self.pend.get(o)
        kind=P['kind'] if P is not None else None
        e=self.get(o)
        self.flush_write(a);self.flush_write(a+1)
        if kind in EFFK or not(isinstance(k,str) and IDENT.match(k) and k not in KW):
            self.flush_kinds(EFFK)
            self.assign(a+1,e)
            e=(self.name(a+1),ATOM)
        self.meth[a]=(objtext(e),k)

    def o_CALL(self,i,c):
        self.begin()
        a=c['a'];na=c['nargs'];nr=c['nres']
        m=self.meth.pop(a,None)
        if m is None:
            fn=self.get(a);first=a+1
        else:
            fn=None;first=a+2
        last=a+na if na>=0 else self.mtop(i)
        args=', '.join(par(self.get(r),0) for r in range(first,last+1))
        if m is None:
            text=par(fn,ATOM)+'('+args+')'
        else:
            text=m[0]+':'+m[1]+'('+args+')'
        expr=(text,ATOM)
        if nr==0:
            self.flush_kinds(EFFK)
            self.emit(text)
        elif nr==1:
            self.define(i,a,expr,'call')
        elif nr==-1:
            self.define(i,a,expr,'multi')
        else:
            nx=self.code[i+1] if i+1<self.n else None
            if nr==3 and nx is not None and nx['op']=='FORGPREP' and nx['a']==a:
                self.define(i,a,expr,'multi')
            else:
                for r in range(a,a+nr):self.flush_write(r)
                self.flush_kinds(EFFK)
                names=', '.join(self.name(r) for r in range(a,a+nr))
                for r in range(a,a+nr):self.assigned.add(r)
                self.emit(names+' = '+text)

    def o_RETURN(self,i,c):
        self.begin()
        a=c['a'];n=c['n']
        regs=range(a,a+n) if n>=0 else range(a,self.mtop(i)+1)
        vals=[par(self.get(r),0) for r in regs]
        if i==self.n-1 and not vals and not self.stack:
            self.flush_kinds(ALLK);return
        self.flush_kinds(ALLK)
        t='return'+(' '+', '.join(vals) if vals else '')
        if i+1<self.n and i+1 not in self.leaders:t='do '+t+' end'
        self.emit(t)

    def o_GETVARARGS(self,i,c):
        self.begin()
        a=c['a'];n=c['n']
        if n==-1:self.define(i,a,('...',ATOM),'multi')
        elif n==1:self.define(i,a,('(...)',ATOM),'pure')
        elif n>1:
            for r in range(a,a+n):self.flush_write(r);self.assigned.add(r)
            self.emit(', '.join(self.name(r) for r in range(a,a+n))+' = ...')

    def o_CONCAT(self,i,c):
        self.begin()
        parts=[par(self.get(r),6) for r in range(c['first'],c['last']+1)]
        self.define(i,c['a'],(' .. '.join(parts),5),'mem')

    def arith(self,i,c,sym,p,x,y):
        self.define(i,c['a'],(par(x,p)+' '+sym+' '+par(y,p+1),p),'mem')

    def o_ADD(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'+',6,x,y)

    def o_SUB(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'-',6,x,y)

    def o_MUL(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'*',7,x,y)

    def o_DIV(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'/',7,x,y)

    def o_MOD(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'%',7,x,y)

    def o_POW(self,i,c):
        self.begin();x=self.get(c['b']);y=self.get(c['c']);self.arith(i,c,'^',8,x,y)

    def o_ADDK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'+',6,x,lit(c['k']))

    def o_SUBK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'-',6,x,lit(c['k']))

    def o_MULK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'*',7,x,lit(c['k']))

    def o_DIVK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'/',7,x,lit(c['k']))

    def o_MODK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'%',7,x,lit(c['k']))

    def o_POWK(self,i,c):
        self.begin();x=self.get(c['b']);self.arith(i,c,'^',8,x,lit(c['k']))

    def o_SUBRK(self,i,c):
        self.begin();y=self.get(c['b']);self.arith(i,c,'-',6,lit(c['k']),y)

    def o_DIVRK(self,i,c):
        self.begin();y=self.get(c['b']);self.arith(i,c,'/',7,lit(c['k']),y)

    def o_MODRK(self,i,c):
        self.begin();y=self.get(c['b']);self.arith(i,c,'%',7,lit(c['k']),y)

    def o_POWRK(self,i,c):
        self.begin();y=self.get(c['b']);self.arith(i,c,'^',8,lit(c['k']),y)

    def o_ORK(self,i,c):
        self.begin()
        x=self.get(c['b'])
        self.define(i,c['a'],(par(x,2)+' or '+par(lit(c['k']),2),1),'mem')

    def o_NOT(self,i,c):
        self.begin();x=self.get(c['b']);self.define(i,c['a'],('not '+par(x,8),8),'mem')

    def o_LEN(self,i,c):
        self.begin();x=self.get(c['b']);self.define(i,c['a'],('#'+par(x,8),8),'mem')

    def o_CLOSEUPVALS(self,i,c):
        pass

    def o_CLOSURE(self,i,c):
        self.begin()
        a=c['a'];child=self.p['children'][c['child']]
        ups=[]
        for A,B in c['caps']:
            if A==2:
                ups.append(self.upname(B))
            else:
                if B in self.pend:self.flush(B)
                ups.append(self.name(B))
                self.captured.add(B)
                self.cur.add(B)
        text=lift_function(child,self.depth+1,ups)
        self.define(i,a,(text,0),'pure')

    def find_loop_end(self,i,op):
        c=self.code[i]
        for j in range(i+1,self.n):
            d=self.code[j]
            if d['op']==op and d['a']==c['a'] and self.tgt.get(j)==i+1:return j
        return max(self.tgt.get(i,i+1)-1,i)

    def o_FORNPREP(self,i,c):
        self.begin()
        a=c['a']
        init=self.get(a+2);lim=self.get(a);st=self.get(a+1)
        v=self.name(a+3);self.forvars.add(a+3)
        h='for %s = %s, %s'%(v,par(init,0),par(lim,0))
        if st[0]!='1':h+=', '+par(st,0)
        self.flush_kinds(ALLK)
        self.emit(h+' do')
        j=self.find_loop_end(i,'FORNLOOP')
        self.stack.append({'kind':'for','end':j+1})

    def o_FORGPREP(self,i,c):
        self.begin()
        a=c['a'];j=self.tgt[i]
        nv=self.nvars(j)
        P=self.pend.get(a)
        if P is not None and P['kind']=='multi':
            ex=[par(self.get(a),0)]
        else:
            es=[self.get(a),self.get(a+1),self.get(a+2)]
            while len(es)>1 and es[-1][0]=='nil':es.pop()
            ex=[par(x,0) for x in es]
        vs=[self.name(a+3+k) for k in range(nv)]
        for k in range(nv):self.forvars.add(a+3+k)
        self.flush_kinds(ALLK)
        self.emit('for %s in %s do'%(', '.join(vs),', '.join(ex)))
        self.stack.append({'kind':'for','end':j+1})

    def close_for(self):
        k=None
        for x in range(len(self.stack)-1,-1,-1):
            if self.stack[x]['kind']=='for':k=x;break
        if k is None:return
        self.close_to(k)

    def o_FORNLOOP(self,i,c):
        self.begin();self.flush_kinds(ALLK);self.close_for()

    o_FORGLOOP=o_FORNLOOP

    def at(self,i):
        c=self.code[i]
        if i in self.leaders or i in self.heads:self.flush_kinds(ALLK)
        while self.stack and self.stack[-1]['kind'] in('if','else') and self.stack[-1]['end']<=i:
            self.stack.pop();self.emit('end')
        if i in self.labels:self.emit('::L%d::'%i)
        if i in self.heads:
            self.emit('while true do')
            self.stack.append({'kind':'while','end':self.heads[i],'head':i})
        getattr(self,'o_'+c['op'])(i,c)

    def build(self,chunk):
        self.lines=[];self.stack=[];self.pend={};self.meth={}
        self.assigned=set();self.captured=set();self.forvars=set();self.used=set();self.gotos=set()
        self.begin()
        for i in range(self.n):
            self.at(i)
        self.flush_kinds(ALLK)
        while self.stack:
            self.stack.pop();self.emit('end')
        decl=sorted((self.assigned|self.captured)-set(range(self.np))-(self.forvars-self.assigned))
        names=[self.name(r) for r in decl]
        body=list(self.lines)
        if names:body.insert(0,'local '+', '.join(names))
        if chunk:
            return '\n'.join(body)+'\n'
        params=[self.name(r) for r in range(self.np)]
        if self.vararg:params.append('...')
        out=['function('+', '.join(params)+')']
        for l in body:out.append('  '+l.replace('\n','\n  '))
        out.append('end')
        return '\n'.join(out)

def lift_function(p,depth,ups,chunk=False):
    key=(id(p),depth,tuple(ups),chunk)
    if key in CACHE:return CACHE[key]
    g=Gen(p,depth,ups,set())
    t=g.build(chunk)
    if g.gotos:
        g=Gen(p,depth,ups,set(g.gotos))
        t=g.build(chunk)
    STATS['functions']+=1
    STATS['gotos']+=len(g.gotos)
    STATS['instructions']+=g.n
    CACHE[key]=t
    return t

def lift(root):
    sys.setrecursionlimit(100000)
    CACHE.clear()
    for k in STATS:STATS[k]=0
    return lift_function(root,0,[],True)

def main(src,dst):
    root=decode_proto(load(src))
    text=lift(root)
    with open(dst,'w',encoding='utf-8') as f:f.write(text)
    print('functions: %d'%STATS['functions'])
    print('instructions: %d'%STATS['instructions'])
    print('goto fallbacks: %d'%STATS['gotos'])
    print('lines: %d'%(text.count('\n')+1))

if __name__=='__main__':
    src=sys.argv[1] if len(sys.argv)>1 else 'out/proto.json'
    dst=sys.argv[2] if len(sys.argv)>2 else 'out/lifted.lua'
    main(src,dst)
