import re,base64
from lparse import parse
from lemit import B
from passes import walk,fold
import resolve,detect
from strdec import mk
def front(src):
    ast=parse(src)
    resolve.XORS.clear();resolve.XORS.update(detect.xor_aliases(ast))
    sd=detect.find_strdec(ast,resolve.XORS)
    b64=detect.find_b64(ast)
    if not sd or not b64:raise Exception('string decoder or base64 function not found')
    ast=walk(ast,fold)
    ast,_=resolve.resolve_block(ast,{})
    ast=walk(ast,fold)
    ast=walk(ast,mk(sd))
    return ast,sd,b64
def payload_of(ast,b64):
    text=B([ast[-1]])
    m=re.search(re.escape(b64)+r"\('([A-Za-z0-9+/=]+)'\)",text)
    if not m:raise Exception('payload not found')
    return base64.b64decode(m.group(1)+'==')
