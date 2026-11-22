def fmtnum(x):
    if isinstance(x,float):
        if x.is_integer() and abs(x)<1e15:return str(int(x))
        return repr(x)
    return str(x)
PREC={'or':1,'and':2,'<':3,'>':3,'<=':3,'>=':3,'~=':3,'==':3,'..':4,'+':6,'-':6,'*':7,'/':7,'//':7,'%':7,'^':9}
def pyval(s):
    if s.lower().startswith('0x'):return int(s,16)
    if s.lower().startswith('0b'):return int(s,2)
    f=float(s)
    return int(f) if f.is_integer() and 'e' not in s.lower() and '.' not in s else f
def E(e,p=0):
    t=e[0]
    if t=='num':
        v=e[1]
        if isinstance(v,str):v=pyval(v)
        return fmtnum(v)
    if t=='str':return e[1]
    if t in('nil','true','false'):return t
    if t=='vararg':return '...'
    if t=='name':return e[1]
    if t=='paren':return '('+E(e[1])+')'
    if t=='index':
        b=E(e[1],20)
        if e[1][0] in('num','str','function','table','nil','true','false'):b='('+b+')'
        if e[2][0]=='str' and e[2][1][1:-1].isidentifier():return b+'.'+e[2][1][1:-1]
        return b+'['+E(e[2])+']'
    if t=='call':return E(e[1],20)+'('+','.join(E(a) for a in e[2])+')'
    if t=='mcall':return E(e[1],20)+':'+e[2]+'('+','.join(E(a) for a in e[3])+')'
    if t=='un':
        s=e[1]+(' ' if e[1]=='not' else '')+E(e[2],8)
        return '('+s+')' if p>8 else s
    if t=='bin':
        q=PREC[e[1]]
        s=E(e[2],q)+' '+e[1]+' '+E(e[3],q+1)
        return '('+s+')' if q<p else s
    if t=='table':
        it=[]
        for x in e[1]:
            if x[0]=='v':it.append(E(x[1]))
            else:it.append('['+E(x[1])+']='+E(x[2]))
        return '{'+','.join(it)+'}'
    if t=='function':
        return 'function('+','.join(e[1]+(['...'] if e[2] else []))+')\n'+B(e[3],1)+'end'
    if t=='ifexp':
        s='if '+E(e[1][0][0])+' then '+E(e[1][0][1])
        for c,a in e[1][1:]:s+=' elseif '+E(c)+' then '+E(a)
        return '('+s+' else '+E(e[2])+')'
    raise Exception('emit '+t)
def B(b,ind=0):
    out=[]
    pad='  '*ind
    for s in b:
        t=s[0]
        if t=='nop':continue
        if t=='local':
            l=pad+'local '+','.join(s[1])
            if s[2]:l+=' = '+','.join(E(x) for x in s[2])
            out.append(l)
        elif t=='assign':out.append(pad+','.join(E(x) for x in s[1])+' = '+','.join(E(x) for x in s[2]))
        elif t=='callstat':out.append(pad+E(s[1]))
        elif t=='do':out.append(pad+'do\n'+B(s[1],ind+1)+pad+'end')
        elif t=='while':out.append(pad+'while '+E(s[1])+' do\n'+B(s[2],ind+1)+pad+'end')
        elif t=='repeat':out.append(pad+'repeat\n'+B(s[1],ind+1)+pad+'until '+E(s[2]))
        elif t=='if':
            l=pad+'if '+E(s[1][0][0])+' then\n'+B(s[1][0][1],ind+1)
            for c,b2 in s[1][1:]:l+=pad+'elseif '+E(c)+' then\n'+B(b2,ind+1)
            if s[2] is not None:l+=pad+'else\n'+B(s[2],ind+1)
            out.append(l+pad+'end')
        elif t=='fornum':
            out.append(pad+'for '+s[1]+' = '+E(s[2])+', '+E(s[3])+((', '+E(s[4])) if s[4] else '')+' do\n'+B(s[5],ind+1)+pad+'end')
        elif t=='forin':out.append(pad+'for '+','.join(s[1])+' in '+','.join(E(x) for x in s[2])+' do\n'+B(s[3],ind+1)+pad+'end')
        elif t=='funcstat':
            f=s[3];nm='.'.join(s[1][:-1])+(':' if s[2] else '.')+s[1][-1] if len(s[1])>1 else s[1][0]
            ps=f[1][1:] if s[2] else f[1]
            out.append(pad+'function '+nm+'('+','.join(ps+(['...'] if f[2] else []))+')\n'+B(f[3],ind+1)+pad+'end')
        elif t=='localfunc':
            f=s[2];out.append(pad+'local function '+s[1]+'('+','.join(f[1]+(['...'] if f[2] else []))+')\n'+B(f[3],ind+1)+pad+'end')
        elif t=='return':out.append(pad+'return'+((' '+','.join(E(x) for x in s[1])) if s[1] else ''))
        elif t=='break':out.append(pad+'break')
        elif t=='continue':out.append(pad+'continue')
        else:raise Exception('stmt '+t)
    return '\n'.join(out)+('\n' if out else '')
