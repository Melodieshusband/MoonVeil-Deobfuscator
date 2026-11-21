import sys,pickle,re

from lemit import B
from passes import walk
ESC={'a':7,'b':8,'f':12,'n':10,'r':13,'t':9,'v':11,'\\':92,'"':34,"'":39,'\n':10}
def unlua(tok):
    q=tok[0]
    if q not in('"',"'"):return None
    s=tok[1:-1];out=bytearray();i=0
    while i<len(s):
        c=s[i]
        if c!='\\':
            out+=c.encode('latin-1');i+=1;continue
        i+=1;c=s[i]
        if c.isdigit():
            j=i
            while j<len(s) and j<i+3 and s[j].isdigit():j+=1
            out.append(int(s[i:j])&255);i=j
        elif c=='x':
            out.append(int(s[i+1:i+3],16));i+=3
        elif c in ESC:
            out.append(ESC[c]);i+=1
        else:
            out+=c.encode('latin-1');i+=1
    return bytes(out)
def lua(b):
    o=["'"]
    for x in b:
        if x==39:o.append("\\'")
        elif x==92:o.append('\\\\')
        elif x==10:o.append('\\n')
        elif x==13:o.append('\\r')
        elif x==0:o.append('\\0')
        elif 32<=x<127:o.append(chr(x))
        else:o.append('\\%d'%x)
    o.append("'");return ''.join(o)
def xdec(a,k):
    return bytes(a[i]^k[i%len(k)] for i in range(len(a)))
def mk(name):
    def f(n):
        if n[0]=='call' and n[1]==('name',name) and len(n[2])==2 and n[2][0][0]=='str' and n[2][1][0]=='str':
            a=unlua(n[2][0][1]);k=unlua(n[2][1][1])
            if a is not None and k:return ('str',lua(xdec(a,k)))
        return n
    return f
if __name__=='__main__':
    ast=pickle.load(open('ast3.pkl','rb'))
    ast=walk(ast,mk('Kb'))
    pickle.dump(ast,open('ast4.pkl','wb'))
    s=B(ast);open('stage4.lua','w',encoding='latin-1').write(s)
    print(len(s),len(re.findall(r'Kb\(',s)))
