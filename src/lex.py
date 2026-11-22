import re
TOK=re.compile(r"""
 (?P<ws>\s+)
|(?P<comment>--\[(?P<eq>=*)\[.*?\](?P=eq)\]|--[^\n]*)
|(?P<str>'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")
|(?P<lstr>\[(?P<eq2>=*)\[.*?\](?P=eq2)\])
|(?P<num>0[bB][01]+|0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)
|(?P<id>[A-Za-z_]\w*)
|(?P<op>\.\.\.|\.\.|==|~=|<=|>=|//|::|[-+*/%^#<>=(){}\[\];:,.])
""",re.X|re.S)
def lex(s):
    out=[];p=0
    while p<len(s):
        m=TOK.match(s,p)
        if not m: raise Exception('lex fail at %d: %r'%(p,s[p:p+40]))
        p=m.end()
        k=m.lastgroup
        if k in('eq','eq2'):
            k='comment' if m.group('comment') else 'lstr'
        if k=='ws' or k=='comment':continue
        out.append((k,m.group(0)))
    return out
