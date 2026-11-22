import re,base64,struct,sys
from lparse import parse
from lemit import B,E
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
DEFAULT_MUL = 104729
DEFAULT_ADD = 17617
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def is_v2(text):
    return re.search(r'\}\):\w+\(\{', text) is not None and 'return({' in text


def container(text):
    ast = parse(text)
    call = ast[-1][1][0]
    items = call[1][1][1]
    names = [E(x[-1]).strip('"') for x in call[3][0][1]]
    entry = E(call[3][1]).strip('"')
    return call[2], items, names, entry


def mapping_constants(items):
    for it in items:
        if it[0] == 'kv' and E(it[1]).strip('\'"') == 'l':
            code = B([('return', [it[-1]])])
            m = re.search(r'(\w+) = (\d+)\s+\w+,\w+ = \1 \* \w+,(\d+)', code)
            if m:
                return int(m.group(2)), int(m.group(3))
    return DEFAULT_MUL, DEFAULT_ADD


def render(expr):
    if expr[0] == 'function':
        return B([('return', [expr])])
    return E(expr)


def members(items, names, mul, add):
    positional = [it for it in items if it[0] == 'v']
    h = len(names)
    result = {}
    for p, it in enumerate(positional):
        result[names[(mul * p + add) % h]] = render(it[1])
    for it in items:
        if it[0] == 'kv':
            result[E(it[1]).strip('\'"')] = render(it[-1])
    return result


def table_and_names(text, method, entry):
    start = text.index('return(') + len('return(')
    split = text.rindex('}):' + method + '(')
    table = text[start:split + 1]
    rest = text[split + len('}):' + method + '('):]
    end = rest.index('},"' + entry + '"')
    return table, rest[:end + 1]


def find_payload(text):
    literals = STR_RE.findall(text)
    payload = max(literals, key=len)
    alphabet = None
    for lit in literals:
        if len(lit) == 85 and '0123456789' in lit and 'ABCDEF' in lit:
            alphabet = lit
            break
    payload = payload.replace('\\\\', '\\').replace('\\"', '"')
    return payload, alphabet


def b85_decode(s, alphabet):
    index = {c: i for i, c in enumerate(alphabet)}
    pad_char = alphabet[-1]
    out = bytearray()
    for i in range(0, len(s), 5):
        chunk = s[i:i + 5]
        pad = 5 - len(chunk)
        chunk += pad_char * pad
        v = 0
        for c in chunk:
            v = v * 85 + index[c]
        out += (v & 0xffffffff).to_bytes(4, 'big')[:4 - pad]
    return bytes(out)


def lua_sub(s, i, j):
    n = len(s)
    if i < 0:
        i = max(n + i + 1, 1)
    elif i == 0:
        i = 1
    if j < 0:
        j = n + j + 1
    elif j > n:
        j = n
    return s[i - 1:j] if i <= j else b''


def lz_decompress(data, window=2048):
    pos = 1
    length = len(data)
    win = b''
    chunks = []
    while pos <= length:
        flags = data[pos - 1]
        pos += 1
        for _ in range(8):
            piece = None
            if flags & 1:
                if pos <= length:
                    piece = data[pos - 1:pos]
                    pos += 1
            elif pos + 1 <= length:
                k = struct.unpack_from('>H', data, pos - 1)[0]
                pos += 2
                start = len(win) - (k >> 5)
                size = (k & 31) + 3
                piece = lua_sub(win, start, start + size - 1)
            flags >>= 1
            if piece is not None:
                chunks.append(piece)
                win = lua_sub(win + piece, -window, -1)
    return b''.join(chunks)

if __name__=='__main__':
    src=open('stage4.lua',encoding='latin-1').read()
    raw=extract(src)
    d=lz(raw)
    open('payload.bin','wb').write(d)
    print(len(raw),len(d))
    print(d[:200])
    print(d[:64].hex())
