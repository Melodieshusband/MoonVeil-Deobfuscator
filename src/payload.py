import re,base64,struct,sys
def lz(data):
    db=b'';out=bytearray();i=0;n=len(data)
    while i<n:
        sc=data[i];i+=1
        for _ in range(8):
            ta=None
            if sc&1:
                if i<n:
                    ta=data[i:i+1];i+=1
            else:
                if i+1<n:
                    xa=struct.unpack('>H',data[i:i+2])[0];i+=2
                    aa=len(db)-(xa>>5)
                    t=(xa&31)+3
                    s=max(aa,1)-1
                    ta=db[s:s+t] if aa>=1 else db[0:max(aa+t-1,0)]
            sc>>=1
            if ta is not None:
                out+=ta
                db=(db+ta)[-2048:]
    return bytes(out)
def extract(src):
    m=re.search(r"Jb\('([A-Za-z0-9+/=]+)'\)",src)
    return base64.b64decode(m.group(1)+'==')
if __name__=='__main__':
    src=open('stage4.lua',encoding='latin-1').read()
    raw=extract(src)
    d=lz(raw)
    open('payload.bin','wb').write(d)
    print(len(raw),len(d))
    print(d[:200])
    print(d[:64].hex())
