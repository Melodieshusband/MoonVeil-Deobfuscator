import re
import sys
sys.setrecursionlimit(100000)

LABEL=re.compile(r'^::(L\d+)::$')
GOTOIF=re.compile(r'^if (.*) then goto (L\d+) end$')
GOTO=re.compile(r'^goto (L\d+)$')
IFHEAD=re.compile(r'^if (.*) then$')
CLOSER=re.compile(r'^end(?![A-Za-z0-9_])')
ELSEP=re.compile(r'^(else|elseif .* then)$')
FUNCTAIL=re.compile(r'function\([^)]*\)$')
ASSIGN=re.compile(r'^([A-Za-z_][A-Za-z0-9_]*) = (.*)$')
RETURNS=re.compile(r'^return(?![A-Za-z0-9_])')
BINOPS=(' and ',' or ',' == ',' ~= ',' < ',' <= ',' > ',' >= ',' .. ',' + ',' - ',' * ',' / ',' % ',' ^ ')
CMPOPS=(' == ',' ~= ',' < ',' <= ',' > ',' >= ')

class Node:
    def __init__(self,kind,text=None,parts=None,close=None):
        self.kind=kind
        self.text=text
        self.parts=parts
        self.close=close

def kind_of(header):
    if header.startswith('if '):return 'if'
    if header.startswith('for ') or header.startswith('while ') or header.startswith('repeat'):return 'loop'
    if header=='do':return 'do'
    return 'f'

def parse_lines(text):
    lines=[]
    for raw in text.split('\n'):
        if not raw.strip():continue
        body=raw.lstrip(' ')
        lines.append((len(raw)-len(body),body))
    pos=[0]
    def block(indent):
        out=[]
        while pos[0]<len(lines):
            ind,t=lines[pos[0]]
            if ind<indent:break
            if ind==indent and (CLOSER.match(t) or ELSEP.match(t)):break
            out.append(stmt(ind))
        return out
    def stmt(indent):
        ind,t=lines[pos[0]]
        pos[0]+=1
        nxt=lines[pos[0]] if pos[0]<len(lines) else None
        isopen=nxt is not None and (nxt[0]>indent or (nxt[0]==indent and (CLOSER.match(nxt[1]) or ELSEP.match(nxt[1]))))
        if not isopen:return Node('s',t)
        parts=[]
        header=t
        while True:
            if pos[0]<len(lines) and lines[pos[0]][0]>indent:
                body=block(lines[pos[0]][0])
            else:
                body=[]
            parts.append([header,body])
            if pos[0]>=len(lines):raise ValueError('unterminated block: '+t)
            ind2,t2=lines[pos[0]]
            if ind2!=indent:raise ValueError('bad indent near: '+t2)
            if ELSEP.match(t2):
                header=t2;pos[0]+=1;continue
            if CLOSER.match(t2):
                pos[0]+=1
                if FUNCTAIL.search(t2):
                    header=t2;continue
                return Node(kind_of(parts[0][0]),parts=parts,close=t2)
            raise ValueError('bad closer: '+t2)
    out=[]
    while pos[0]<len(lines):
        out.append(stmt(lines[pos[0]][0]))
    return out

def render(nodes,indent,out):
    pad=' '*indent
    for n in nodes:
        if n.kind=='s':
            out.append(pad+n.text)
        else:
            for h,b in n.parts:
                out.append(pad+h)
                render(b,indent+2,out)
            out.append(pad+n.close)

def mask(s):
    m=[False]*len(s)
    d=0;q=None;i=0
    while i<len(s):
        ch=s[i]
        if q:
            if ch=='\\':
                i+=2;continue
            if ch==q:q=None
            i+=1;continue
        if ch=='"' or ch=="'":
            q=ch;i+=1;continue
        if ch in '([{':d+=1
        elif ch in ')]}':d-=1
        m[i]=(d==0)
        i+=1
    return m

def split_top(s,word):
    pat=' '+word+' '
    m=mask(s)
    parts=[];start=0;i=0
    while True:
        j=s.find(pat,i)
        if j<0:break
        if m[j]:
            parts.append(s[start:j]);start=j+len(pat);i=start
        else:
            i=j+1
    parts.append(s[start:])
    return parts

def has_op(s,ops):
    m=mask(s)
    for op in ops:
        i=0
        while True:
            j=s.find(op,i)
            if j<0:break
            if m[j]:return True
            i=j+1
    return False

def has_binop(s):
    return has_op(s,BINOPS)

def unparen(s):
    if not s.startswith('('):return s
    m=mask(s)
    d=0;q=None;i=0
    while i<len(s):
        ch=s[i]
        if q:
            if ch=='\\':
                i+=2;continue
            if ch==q:q=None
            i+=1;continue
        if ch=='"' or ch=="'":
            q=ch
        elif ch in '([{':d+=1
        elif ch in ')]}':
            d-=1
            if d==0:
                return s[1:-1] if i==len(s)-1 else s
        i+=1
    return s

def and_join(parts):
    out=[]
    for p in parts:
        out.append('('+p+')' if len(split_top(p,'or'))>1 else p)
    return ' and '.join(out)

def or_join(parts):
    return ' or '.join(parts)

def neg(c):
    c=c.strip()
    if c=='true':return 'false'
    if c=='false':return 'true'
    ors=split_top(c,'or')
    if len(ors)>1:return and_join([neg(x) for x in ors])
    ands=split_top(c,'and')
    if len(ands)>1:return or_join([neg(x) for x in ands])
    if c.startswith('not ') and not has_binop(c[4:]):
        return unparen(c[4:])
    for a,b in(('<=','>'),('>=','<'),('==','~='),('~=','=='),('<','>='),('>','<=')):
        parts=split_top(c,a)
        if len(parts)==2 and not any(has_op(x,CMPOPS) for x in parts):
            return parts[0]+' '+b+' '+parts[1]
    if has_binop(c):return 'not ('+c+')'
    return 'not '+c

def conj(a,b):
    return and_join([a,b])


def whole_paren(p):
    if not p.startswith('('):return False
    return unparen(p)!=p

def simp(c):
    ors=split_top(c,'or')
    if len(ors)>1:return or_join([simp(x) for x in ors])
    ands=split_top(c,'and')
    if len(ands)>1:return and_join([simp(x) for x in ands])
    if c.startswith('not ') and whole_paren(c[4:]):
        n=neg(unparen(c[4:]))
        if n.startswith('not ') and whole_paren(n[4:]):return n
        return simp(n)
    if whole_paren(c):
        inner=simp(unparen(c))
        return '('+inner+')' if has_binop(inner) else inner
    return c

def simp_headers(body):
    for n in walk(body):
        if n.kind=='if':
            for part in n.parts:
                m=IFHEAD.match(part[0])
                if m:part[0]='if %s then'%simp(m.group(1))
        elif n.kind=='s':
            m=GOTOIF.match(n.text)
            if m:n.text='if %s then goto %s end'%(simp(m.group(1)),m.group(2))

def label_of(n):
    if n.kind!='s':return None
    m=LABEL.match(n.text)
    return m.group(1) if m else None

def goto_if(n):
    if n.kind!='s':return None
    m=GOTOIF.match(n.text)
    return (m.group(1),m.group(2)) if m else None

def children(n):
    for h,b in n.parts:
        yield b

def walk(nodes,into_loops=True):
    for n in nodes:
        yield n
        if n.kind in('if','do') or (n.kind=='loop' and into_loops):
            for b in children(n):
                yield from walk(b,into_loops)

def goto_target(n):
    if n.kind!='s':return None
    m=GOTOIF.match(n.text)
    if m:return m.group(2)
    m=GOTO.match(n.text)
    if m:return m.group(1)
    return None

def count_gotos(nodes,L):
    c=0
    for n in walk(nodes):
        if goto_target(n)==L:c+=1
    return c

def labels_in(nodes):
    return {label_of(n) for n in walk(nodes) if label_of(n)}

def all_blocks(body,tail=None):
    if tail is None:tail=set()
    for i,nd in enumerate(body):
        if nd.kind in('s','f'):continue
        j=i+1;labs=set()
        while j<len(body) and label_of(body[j]):
            labs.add(label_of(body[j]));j+=1
        t=set(labs)
        if j>=len(body):t|=tail
        if nd.kind in('if','do'):
            for b in children(nd):
                yield from all_blocks(b,t)
        else:
            for b in children(nd):
                yield from all_blocks(b,set())
    yield body,tail

def find_label(blk,L,start):
    for i in range(start,len(blk)):
        if label_of(blk[i])==L:return i
    return None

def safe_region(rest,ctx):
    for L in labels_in(rest):
        if count_gotos(ctx,L)!=count_gotos(rest,L):return False
    return True

def pass_collapse(blk,tail,ctx):
    for i,n in enumerate(blk):
        if n.kind=='if' and len(n.parts)==1:
            h,b=n.parts[0]
            m=IFHEAD.match(h)
            if m and len(b)==1 and b[0].kind=='s':
                g=GOTOIF.match(b[0].text)
                if g:
                    blk[i]=Node('s','if %s then goto %s end'%(conj(m.group(1),g.group(1)),g.group(2)))
                    return True
                g=GOTO.match(b[0].text)
                if g:
                    blk[i]=Node('s','if %s then goto %s end'%(m.group(1),g.group(1)))
                    return True
    return False

def flat_if(n):
    h,b=n.parts[0]
    cond=IFHEAD.match(h).group(1)
    while len(b)==1 and b[0].kind=='if' and len(b[0].parts)==1 and IFHEAD.match(b[0].parts[0][0]):
        cond=conj(cond,IFHEAD.match(b[0].parts[0][0]).group(1))
        b=b[0].parts[0][1]
    return cond,b

def mentions(text,name):
    return re.search(r'(?<![A-Za-z0-9_.])'+re.escape(name)+r'(?![A-Za-z0-9_])',text) is not None

def pass_value(blk,tail,ctx):
    for q in range(len(blk)):
        n=blk[q]
        if n.kind=='if' and len(n.parts)==1 and IFHEAD.match(n.parts[0][0]) and q+2<len(blk):
            cond,b=flat_if(n)
            if len(b)==2 and b[0].kind=='s' and b[1].kind=='s':
                ma=ASSIGN.match(b[0].text)
                g=GOTOIF.match(b[1].text)
                nx=blk[q+1]
                if ma and g and nx.kind=='s':
                    mb=ASSIGN.match(nx.text)
                    X,E1=ma.groups()
                    gc,L=g.groups()
                    if mb and mb.group(1)==X and gc==X and label_of(blk[q+2])==L and count_gotos(ctx,L)==1 and not mentions(mb.group(2),X):
                        text='%s = %s'%(X,or_join([and_join([cond,E1]),mb.group(2)]))
                        blk[q:q+3]=[Node('s',text)]
                        return True
        if n.kind=='s' and q+3<len(blk):
            ma=ASSIGN.match(n.text)
            g=goto_if(blk[q+1])
            nx=blk[q+2]
            if ma and g and nx.kind=='s':
                mb=ASSIGN.match(nx.text)
                X,E1=ma.groups()
                gc,L=g
                if mb and mb.group(1)==X and label_of(blk[q+3])==L and count_gotos(ctx,L)==1 and not mentions(mb.group(2),X):
                    if gc==X:
                        text='%s = %s'%(X,or_join([E1,mb.group(2)]))
                    elif gc=='not '+X:
                        text='%s = %s'%(X,and_join([E1,mb.group(2)]))
                    else:
                        continue
                    blk[q:q+4]=[Node('s',text)]
                    return True
    return False

def pass_skip(blk,tail,ctx):
    for q in range(len(blk)-1,-1,-1):
        g=goto_if(blk[q])
        if not g:continue
        c,L=g
        p=find_label(blk,L,q+1)
        if p is None:
            if L not in tail:continue
            p=len(blk)
        rest=blk[q+1:p]
        if not safe_region(rest,ctx):continue
        new=[]
        if rest:
            new.append(Node('if',parts=[['if %s then'%neg(c),rest]],close='end'))
        elif '(' in c:
            new.append(Node('if',parts=[['if %s then'%c,[]]],close='end'))
        keep=[]
        if p<len(blk):
            cnt=count_gotos(ctx,L)-1
            if cnt>0:keep=[blk[p]]
            blk[q:p+1]=new+keep
        else:
            blk[q:]=new
        return True
    return False

def loop_gotos(nodes,L,inloop=False):
    res=[]
    for n in nodes:
        if goto_target(n)==L:res.append(inloop)
        if n.kind in('if','do'):
            for b in children(n):res+=loop_gotos(b,L,inloop)
        elif n.kind=='loop':
            for b in children(n):res+=loop_gotos(b,L,True)
    return res

def has_loopctl(nodes,inloop=False):
    for n in nodes:
        if n.kind=='s' and not inloop:
            t=n.text
            if t in('break','continue') or t.endswith(' then break end') or t.endswith(' then continue end'):return True
        if n.kind in('if','do'):
            for b in children(n):
                if has_loopctl(b,inloop):return True
        elif n.kind=='loop':
            for b in children(n):
                if has_loopctl(b,True):return True
    return False

def retarget(nodes,L,inloop=False):
    for n in nodes:
        if n.kind=='s' and not inloop:
            m=GOTOIF.match(n.text)
            if m and m.group(2)==L:n.text='if %s then break end'%m.group(1)
            elif n.text=='goto '+L:n.text='break'
        if n.kind in('if','do'):
            for b in children(n):retarget(b,L,inloop)
        elif n.kind=='loop':
            for b in children(n):retarget(b,L,True)

def pass_fallback(blk,tail,ctx):
    for p,n in enumerate(blk):
        L=label_of(n)
        if not L:continue
        q0=None
        for q in range(p):
            if count_gotos([blk[q]],L)>0:
                q0=q;break
        if q0 is None:continue
        region=blk[q0:p]
        if any(loop_gotos(region,L)):continue
        if has_loopctl(region):continue
        if not safe_region(region,ctx):continue
        retarget(region,L)
        wrapped=Node('loop',parts=[['repeat',region]],close='until true')
        keep=[blk[p]] if count_gotos(ctx,L)-count_gotos(region,L)>0 else []
        blk[q0:p+1]=[wrapped]+keep
        return True
    return False


def or2(a,b):
    if b=='false':return a
    if a=='false':return b
    if b=='true':return 'true'
    return or_join([a,b])

def and2(a,b):
    if b=='true':return a
    if a=='true':return b
    return and_join([a,b])

def is_pure(n):
    if goto_if(n):return True
    if n.kind=='if' and len(n.parts)==1 and IFHEAD.match(n.parts[0][0]):
        return all(is_pure(x) for x in n.parts[0][1])
    return False

def targets(nodes):
    return {goto_target(n) for n in walk(nodes) if goto_target(n)}

def jump_cond(nodes,T,i=0):
    if i>=len(nodes):return 'false'
    n=nodes[i]
    rest=jump_cond(nodes,T,i+1)
    g=goto_if(n)
    if g:return or2(g[0],rest)
    c=IFHEAD.match(n.parts[0][0]).group(1)
    return or2(and2(c,jump_cond(n.parts[0][1],T)),rest)

def reach(nodes,i,L,X):
    if i>=len(nodes):return 'true'
    n=nodes[i]
    rest=reach(nodes,i+1,L,X)
    g=goto_if(n)
    if g:
        c,T=g
        if T==L:return or2(c,rest)
        return and2(neg(c),rest)
    c=IFHEAD.match(n.parts[0][0]).group(1)
    ts=targets(n.parts[0][1])
    j=jump_cond(n.parts[0][1],None)
    if ts=={L}:return or2(and2(c,j),rest)
    return and2(neg(and2(c,j)),rest)

def pass_decide(blk,tail,ctx):
    for p,n in enumerate(blk):
        L=label_of(n)
        if not L:continue
        q0=p
        while q0>0 and is_pure(blk[q0-1]):q0-=1
        region=blk[q0:p]
        if not region:continue
        ts=targets(region)
        if L not in ts:continue
        others=ts-{L}
        if len(others)>1:continue
        for x in region:
            if x.kind=='if':
                if len(targets(x.parts[0][1]))!=1:break
        else:
            X=next(iter(others)) if others else None
            if not safe_region(region,ctx):continue
            e=reach(region,0,L,X)
            new=[]
            if X is not None and e!='true':
                new=[Node('s','if %s then goto %s end'%(neg(e),X))]
            keep=[blk[p]] if count_gotos(ctx,L)-count_gotos(region,L)>0 else []
            blk[q0:p+1]=new+keep
            return True
    return False

def pass_labels(blk,tail,ctx):
    for i,n in enumerate(blk):
        L=label_of(n)
        if L and count_gotos(ctx,L)==0:
            del blk[i]
            return True
    return False

def pass_returns(blk,tail,ctx):
    changed=False
    for i,n in enumerate(blk[:-1]):
        if n.kind=='s' and (RETURNS.match(n.text) or n.text in('break','continue')):
            blk[i]=Node('s','do '+n.text+' end')
            changed=True
    return changed

def run_pass(body,fn):
    for blk,tail in list(all_blocks(body)):
        if fn(blk,tail,body):return True
    return False

def functions(body):
    for n in walk(body):
        if n.kind=='f':
            yield n

def fix_function(body):
    guard=0
    while guard<200000:
        guard+=1
        if run_pass(body,pass_collapse):continue
        if run_pass(body,pass_value):continue
        if run_pass(body,pass_labels):continue
        if run_pass(body,pass_skip):continue
        if run_pass(body,pass_decide):continue
        if run_pass(body,pass_fallback):continue
        break
    while run_pass(body,pass_returns):pass
    simp_headers(body)
    for f in functions(body):
        for h,b in f.parts:
            fix_function(b)

def remaining(body):
    c=0
    for n in walk(body):
        if goto_target(n) or label_of(n):c+=1
        if n.kind=='f':
            for h,b in n.parts:c+=remaining(b)
    return c

def fix(text):
    body=parse_lines(text)
    fix_function(body)
    out=[]
    render(body,0,out)
    return '\n'.join(out)+'\n',remaining(body)

if __name__=='__main__':
    src=sys.argv[1] if len(sys.argv)>1 else 'out/lifted.lua'
    dst=sys.argv[2] if len(sys.argv)>2 else 'out/final.lua'
    text,left=fix(open(src,encoding='utf-8').read())
    open(dst,'w',encoding='utf-8').write(text)
    print('goto/label left: %d'%left)
    print('lines: %d'%(text.count('\n')))
