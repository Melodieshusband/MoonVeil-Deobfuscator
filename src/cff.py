import sys,pickle

from lemit import *
from passes import tonum
INV={'<':'>=','>':'<=','<=':'>','>=':'<','==':'~=','~=':'=='}
FLIP={'<':'>','>':'<','<=':'>=','>=':'<=','==':'==','~=':'~='}
def ycond(c,yn):
    while c[0]=='paren':c=c[1]
    if c[0]=='un' and c[1]=='not':
        r=ycond(c[2],yn)
        return (INV[r[0]],r[1]) if r else None
    if c[0]=='bin' and c[1] in INV:
        if c[2]==('name',yn) and tonum(c[3]) is not None:return (c[1],tonum(c[3]))
        if c[3]==('name',yn) and tonum(c[2]) is not None:return (FLIP[c[1]],tonum(c[2]))
    return None
def apply(cons,cond,neg):
    op,v=cond
    if neg:op=INV[op]
    return cons+[(op,v)]
def interval(cons):
    lo,hi=-10**12,10**12;ne=set()
    for op,v in cons:
        if op=='<':hi=min(hi,v-1)
        elif op=='<=':hi=min(hi,v)
        elif op=='>':lo=max(lo,v+1)
        elif op=='>=':lo=max(lo,v)
        elif op=='==':lo=max(lo,v);hi=min(hi,v)
        elif op=='~=':ne.add(v)
    return lo,hi,ne
def collect(block,yn,cons,out,warn):
    if len(block)==1 and block[0][0]=='if':
        s=block[0]
        cl=s[1];el=s[2]
        conds=[ycond(c,yn) for c,_ in cl]
        if all(conds):
            prev=cons
            for (c,b),yc in zip(cl,conds):
                collect(b,yn,apply(prev,yc,False),out,warn)
                prev=apply(prev,yc,True)
            if el is not None:collect(el,yn,prev,out,warn)
            return
    lo,hi,ne=interval(cons)
    while lo in ne and lo<hi:lo+=1
    while hi in ne and lo<hi:hi-=1
    if lo==hi:
        if lo in out:warn.append(('dup',lo))
        out[lo]=block
    else:warn.append(('range',lo,hi,block))
def find_loop(body):
    for s in body:
        if s[0]=='repeat':return s
    return None
def extract(fn,yn):
    body=fn[3]
    rp=find_loop(body)
    out={};warn=[]
    collect(rp[1],yn,[],out,warn)
    return rp,out,warn
def yassigns(block,yn,acc):
    for s in block:
        t=s[0]
        if t=='assign':
            for tg,v in zip(s[1],s[2]):
                if tg==('name',yn):
                    n=tonum(v)
                    if n is not None:acc.add(n)
        if t=='if':
            for c,b in s[1]:yassigns(b,yn,acc)
            if s[2]:yassigns(s[2],yn,acc)
        elif t in('do',):yassigns(s[1],yn,acc)
        elif t=='while':yassigns(s[2],yn,acc)
        elif t=='repeat':yassigns(s[1],yn,acc)
        elif t=='fornum':yassigns(s[5],yn,acc)
        elif t=='forin':yassigns(s[3],yn,acc)
def extract2(fn,yn):
    rp,out,warn=extract(fn,yn)
    acc=set()
    yassigns(fn[3],yn,acc)
    for w in warn:
        if w[0]=='range':
            _,lo,hi,blk=w
            cand=[v for v in acc if lo<=v<=hi and v not in out]
            if len(cand)==1:out[cand[0]]=blk
            else:out.setdefault(('amb',lo,hi),blk)
    return rp,out,acc
