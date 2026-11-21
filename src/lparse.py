import sys
sys.setrecursionlimit(100000)
from lex import lex
BIN={'or':(1,1),'and':(2,2),'<':(3,3),'>':(3,3),'<=':(3,3),'>=':(3,3),'~=':(3,3),'==':(3,3),'..':(5,4),'+':(6,6),'-':(6,6),'*':(7,7),'/':(7,7),'//':(7,7),'%':(7,7),'^':(10,9)}
UNP=8
class P:
    def __init__(s,toks):
        s.t=toks;s.i=0
    def peek(s,o=0):
        return s.t[s.i+o] if s.i+o<len(s.t) else ('eof','')
    def nxt(s):
        x=s.t[s.i];s.i+=1;return x
    def isk(s,v,o=0):
        k,x=s.peek(o);return x==v and k in('id','op')
    def accept(s,v):
        if s.isk(v):s.i+=1;return True
        return False
    def expect(s,v):
        if not s.accept(v):raise Exception('expected %s got %r at %d: %s'%(v,s.peek(),s.i,' '.join(x[1] for x in s.t[s.i-8:s.i+8])))
    def name(s):
        k,x=s.nxt()
        if k!='id':raise Exception('name expected got %r at %d'%(x,s.i))
        return x
    def block(s):
        out=[]
        while True:
            k,x=s.peek()
            if k=='eof' or (k=='id' and x in('end','else','elseif','until')):break
            if k=='id' and x=='return':
                s.i+=1
                es=[]
                k2,x2=s.peek()
                if not(k2=='eof' or (k2=='id' and x2 in('end','else','elseif','until')) or x2==';'):
                    es=s.explist()
                s.accept(';')
                out.append(('return',es));break
            out.append(s.stat())
        return out
    def stat(s):
        k,x=s.peek()
        if x==';' and k=='op':s.i+=1;return ('nop',)
        if x=='::' and k=='op':
            s.i+=1;n=s.name();s.expect('::');return ('label',n)
        if k=='id':
            if x=='do':
                s.i+=1;b=s.block();s.expect('end');return ('do',b)
            if x=='while':
                s.i+=1;c=s.exp();s.expect('do');b=s.block();s.expect('end');return ('while',c,b)
            if x=='repeat':
                s.i+=1;b=s.block();s.expect('until');c=s.exp();return ('repeat',b,c)
            if x=='if':
                s.i+=1;cl=[];c=s.exp();s.expect('then');b=s.block();cl.append((c,b));el=None
                while True:
                    if s.accept('elseif'):
                        c=s.exp();s.expect('then');b=s.block();cl.append((c,b))
                    elif s.accept('else'):
                        el=s.block();s.expect('end');break
                    else:
                        s.expect('end');break
                return ('if',cl,el)
            if x=='for':
                s.i+=1;n=s.name()
                if s.accept('='):
                    a=s.exp();s.expect(',');b=s.exp();c=None
                    if s.accept(','):c=s.exp()
                    s.expect('do');bl=s.block();s.expect('end');return ('fornum',n,a,b,c,bl)
                ns=[n]
                while s.accept(','):ns.append(s.name())
                s.expect('in');es=s.explist();s.expect('do');bl=s.block();s.expect('end');return ('forin',ns,es,bl)
            if x=='function':
                s.i+=1;n=[s.name()];isself=False
                while True:
                    if s.accept('.'):n.append(s.name())
                    elif s.accept(':'):n.append(s.name());isself=True;break
                    else:break
                f=s.funcbody(isself);return ('funcstat',n,isself,f)
            if x=='local':
                s.i+=1
                if s.accept('function'):
                    n=s.name();f=s.funcbody(False);return ('localfunc',n,f)
                ns=[s.name()]
                while s.accept(','):ns.append(s.name())
                es=[]
                if s.accept('='):es=s.explist()
                return ('local',ns,es)
            if x=='break':s.i+=1;return ('break',)
            if x=='continue':s.i+=1;return ('continue',)
            if x=='goto':
                s.i+=1;return ('goto',s.name())
        e=s.suffixed()
        if s.isk('=') or s.isk(','):
            ts=[e]
            while s.accept(','):ts.append(s.suffixed())
            s.expect('=');es=s.explist();return ('assign',ts,es)
        k,x=s.peek()
        if k=='op' and x in('+','-','*','/','%','^','..') and s.isk('=',1):
            s.i+=2;v=s.exp();return ('assign',[e],[('bin',x,e,v)])
        if e[0] not in('call','mcall'):raise Exception('bad stat at %d: %s'%(s.i,' '.join(y[1] for y in s.t[s.i-8:s.i+8])))
        return ('callstat',e)
    def funcbody(s,isself):
        s.expect('(');ps=['self'] if isself else [];va=False
        if not s.isk(')'):
            while True:
                if s.accept('...'):va=True;break
                ps.append(s.name())
                if not s.accept(','):break
        s.expect(')');b=s.block();s.expect('end');return ('function',ps,va,b)
    def explist(s):
        es=[s.exp()]
        while s.accept(','):es.append(s.exp())
        return es
    def primary(s):
        k,x=s.peek()
        if k=='id' and x not in('nil','true','false','function','if','not'):
            s.i+=1;return ('name',x)
        if x=='(' and k=='op':
            s.i+=1;e=s.exp();s.expect(')');return ('paren',e)
        raise Exception('unexpected %r at %d: %s'%(x,s.i,' '.join(y[1] for y in s.t[s.i-8:s.i+8])))
    def suffixed(s):
        e=s.primary()
        while True:
            k,x=s.peek()
            if x=='.' and k=='op':
                s.i+=1;e=('index',e,('str',"'"+s.name()+"'"))
            elif x=='[' and k=='op':
                s.i+=1;i=s.exp();s.expect(']');e=('index',e,i)
            elif x==':' and k=='op':
                s.i+=1;n=s.name();a=s.callargs();e=('mcall',e,n,a)
            elif (x=='(' and k=='op') or k=='str' or (x=='{' and k=='op'):
                a=s.callargs();e=('call',e,a)
            else:break
        return e
    def callargs(s):
        k,x=s.peek()
        if k=='str':s.i+=1;return [('str',x)]
        if x=='{':return [s.table()]
        s.expect('(')
        if s.accept(')'):return []
        es=s.explist();s.expect(')');return es
    def table(s):
        s.expect('{');items=[]
        while not s.isk('}'):
            if s.isk('[') and s.peek()[0]=='op':
                s.i+=1;kx=s.exp();s.expect(']');s.expect('=');items.append(('kv',kx,s.exp()))
            elif s.peek()[0]=='id' and s.isk('=',1) and s.peek(1)[0]=='op':
                n=s.name();s.i+=1;items.append(('kv',('str',"'"+n+"'"),s.exp()))
            else:items.append(('v',s.exp()))
            if not(s.accept(',') or s.accept(';')):break
        s.expect('}');return ('table',items)
    def simple(s):
        k,x=s.peek()
        if k=='num':s.i+=1;return ('num',x)
        if k=='str':s.i+=1;return ('str',x)
        if k=='lstr':s.i+=1;return ('str',x)
        if k=='id':
            if x=='nil':s.i+=1;return ('nil',)
            if x=='true':s.i+=1;return ('true',)
            if x=='false':s.i+=1;return ('false',)
            if x=='function':
                s.i+=1;return s.funcbody(False)
            if x=='if':
                s.i+=1;c=s.exp();s.expect('then');a=s.exp();cl=[(c,a)]
                while s.accept('elseif'):
                    c=s.exp();s.expect('then');a=s.exp();cl.append((c,a))
                s.expect('else');e=s.exp();return ('ifexp',cl,e)
        if x=='...' and k=='op':s.i+=1;return ('vararg',)
        if x=='{' and k=='op':return s.table()
        return s.suffixed()
    def exp(s,lim=0):
        k,x=s.peek()
        if (k=='id' and x=='not') or (k=='op' and x in('-','#')):
            s.i+=1;o=s.exp(UNP);e=('un',x,o)
        else:e=s.simple()
        while True:
            k,x=s.peek()
            if x in BIN and k in('op','id'):
                l,r=BIN[x]
                if l<=lim:break
                s.i+=1;rhs=s.exp(r);e=('bin',x,e,rhs)
            else:break
        return e
def parse(src):
    p=P(lex(src));b=p.block()
    if p.peek()[0]!='eof':raise Exception('trailing at %d'%p.i)
    return b
