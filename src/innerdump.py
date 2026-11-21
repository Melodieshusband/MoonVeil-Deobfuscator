import sys,os,re,subprocess
sys.setrecursionlimit(1000000)
from lemit import B
from stages import front
import detect

PRELUDE='''local __n=0
__dump=function(s)
	__n=__n+1
	io_out=s:gsub(".",function(c) return string.format("%02x",string.byte(c)) end)
	print("@@DUMP "..__n.." "..#s.." "..io_out)
end
'''

def patch(text,des):
    pat=re.compile(r'(local\s+'+re.escape(des)+r'\s*=\s*\(function\(([A-Za-z_]\w*)\)\n)')
    m=pat.search(text)
    if not m:
        raise Exception('deserializer definition not found in text')
    return text[:m.end()]+'  __dump('+m.group(2)+')\n'+text[m.end():]

def run(src,out,luau,timeout=120):
    os.makedirs(out,exist_ok=True)
    ast,sd,b64=front(src)
    des=detect.find_deserializer(ast)
    text=patch(B(ast),des)
    path=os.path.join(out,'patched.lua')
    with open(path,'w',encoding='latin-1') as f:
        f.write(PRELUDE+text)
    try:
        p=subprocess.run([os.path.abspath(luau),'patched.lua'],cwd=out,capture_output=True,timeout=timeout)
        stdout=p.stdout;stderr=p.stderr
    except subprocess.TimeoutExpired as e:
        stdout=e.stdout or b'';stderr=b'timeout'
    dumps=[]
    for line in stdout.split(b'\n'):
        if line.startswith(b'@@DUMP '):
            _,n,ln,hx=line.split(b' ',3)
            data=bytes.fromhex(hx.decode().strip())
            with open(os.path.join(out,'inner_%s.bin'%n.decode()),'wb') as f:
                f.write(data)
            dumps.append((int(n),len(data)))
    return dumps,stderr.decode('latin-1')[:400]

if __name__=='__main__':
    src=open(sys.argv[1],encoding='latin-1').read()
    d,e=run(src,sys.argv[2],sys.argv[3])
    print('deserializer calls:',d)
    if e.strip():print('stderr:',e.strip())
