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

V2_SANDBOX=r'''local G0 = getfenv(0)
local env = {}
for _, n in ipairs({"print", "pairs", "ipairs", "type", "tostring", "tonumber", "select", "next", "rawget", "rawset", "rawequal", "rawlen", "pcall", "xpcall", "error", "assert", "getmetatable", "setmetatable", "unpack", "getfenv", "setfenv", "string", "table", "math", "bit32", "utf8", "coroutine", "buffer", "debug"}) do
	env[n] = G0[n]
end
env.os = {clock = os.clock, time = os.time}
env._G = env

local PL = 0
local function plog(...)
	PL = PL + 1
	if PL <= 5000 then
		print("TRACE", ...)
	end
end

local mk
local mt = {}
mt.__index = function(t, k)
	local p = rawget(t, "__path") .. "." .. tostring(k)
	plog("GET", p)
	return mk(p)
end
mt.__newindex = function(t, k, v)
	plog("SET", rawget(t, "__path") .. "." .. tostring(k))
end
mt.__call = function(t, ...)
	local p = rawget(t, "__path")
	plog("CALL", p .. "(...)")
	return mk(p .. "()")
end
mt.__tostring = function(t) return rawget(t, "__path") end
mt.__concat = function(a, b) return tostring(a) .. tostring(b) end
mt.__len = function() return 0 end
mt.__eq = function() return false end
mt.__lt = function() return false end
mt.__le = function() return false end
mt.__add = function() return 0 end
mt.__sub = function() return 0 end
mt.__mul = function() return 0 end
mt.__div = function() return 0 end
mt.__unm = function() return 0 end
mt.__iter = function() return function() return nil end end
mk = function(p) return setmetatable({__path = p}, mt) end

setmetatable(env, {__index = function(_, k)
	plog("GLOBAL", k)
	local x = mk(k)
	rawset(env, k, x)
	return x
end})

local valid = {GetService = 1, FindService = 1, GetChildren = 1, GetDescendants = 1, IsA = 1, FindFirstChild = 1, FindFirstChildOfClass = 1, WaitForChild = 1, HttpGet = 1, Workspace = 1, Players = 1, JobId = 1, PlaceId = 1, GameId = 1, IsLoaded = 1, Loaded = 1, ClassName = 1, Name = 1, Parent = 1}
local gmt = {}
gmt.__index = function(t, k)
	plog("GET", "game." .. tostring(k))
	if valid[k] then return mk("game." .. tostring(k)) end
	error(tostring(k) .. " is not a valid member of DataModel \"Game\"", 2)
end
gmt.__newindex = function(t, k, v) plog("SET", "game." .. tostring(k)) end
gmt.__call = function(t, ...)
	plog("CALL", "game()")
	error("attempt to call a DataModel value", 2)
end
gmt.__tostring = function() return "Game" end
rawset(env, "game", setmetatable({__path = "game"}, gmt))

local v3mt = {}
local function V(x, y, z) return setmetatable({X = x, Y = y, Z = z}, v3mt) end
v3mt.__add = function(a, b) return V(a.X + b.X, a.Y + b.Y, a.Z + b.Z) end
v3mt.__sub = function(a, b) return V(a.X - b.X, a.Y - b.Y, a.Z - b.Z) end
v3mt.__mul = function(a, b)
	if type(a) == "number" then return V(a * b.X, a * b.Y, a * b.Z) end
	if type(b) == "number" then return V(a.X * b, a.Y * b, a.Z * b) end
	return V(a.X * b.X, a.Y * b.Y, a.Z * b.Z)
end
v3mt.__div = function(a, b)
	if type(b) == "number" then return V(a.X / b, a.Y / b, a.Z / b) end
	return V(a.X / b.X, a.Y / b.Y, a.Z / b.Z)
end
v3mt.__unm = function(a) return V(-a.X, -a.Y, -a.Z) end
v3mt.__eq = function(a, b) return a.X == b.X and a.Y == b.Y and a.Z == b.Z end
v3mt.__tostring = function(a) return a.X .. ", " .. a.Y .. ", " .. a.Z end
v3mt.__index = function(t, k)
	if k == "Magnitude" then return math.sqrt(t.X * t.X + t.Y * t.Y + t.Z * t.Z) end
	if k == "Unit" then
		local m = math.sqrt(t.X * t.X + t.Y * t.Y + t.Z * t.Z)
		return V(t.X / m, t.Y / m, t.Z / m)
	end
	return nil
end
rawset(env, "Vector3", {new = function(x, y, z)
	plog("CALL", "Vector3.new(" .. tostring(x) .. "," .. tostring(y) .. "," .. tostring(z) .. ")")
	return V(x or 0, y or 0, z or 0)
end})
rawset(env, "CFrame", {new = function(x, y, z)
	plog("CALL", "CFrame.new(" .. tostring(x) .. "," .. tostring(y) .. "," .. tostring(z) .. ")")
	local p = V(x or 0, y or 0, z or 0)
	return {Position = p, X = p.X, Y = p.Y, Z = p.Z}
end})

local function dsc(v)
	if type(v) == "table" and rawget(v, "ClassName") == "Part" then
		local c = rawget(v, "CFrame")
		return "Part@z" .. (c and c.Z or "?")
	end
	if type(v) == "table" and rawget(v, "ClassName") then return tostring(rawget(v, "ClassName")) end
	if type(v) == "table" and getmetatable(v) == v3mt then return "Vector3(" .. tostring(v) .. ")" end
	if type(v) == "table" and rawget(v, "Position") then return "CFrame@" .. tostring(rawget(v, "Position")) end
	if type(v) == "table" and rawget(v, "__path") then return "<" .. rawget(v, "__path") .. ">" end
	if type(v) == "table" then
		local o = {}
		for _, x in ipairs(v) do o[#o + 1] = dsc(x) end
		return "{" .. table.concat(o, ", ") .. "}"
	end
	return tostring(v)
end

local rpmt = {}
rpmt.__tostring = function() return "RaycastParams" end
rpmt.__newindex = function(t, k, v)
	plog("SET", "RaycastParams." .. tostring(k) .. " = " .. dsc(v))
	rawset(t, k, v)
end
rawset(env, "RaycastParams", {new = function() return setmetatable({}, rpmt) end})

local imeth = {}
imeth.Destroy = function(self)
	plog("CALL", "Destroy(" .. tostring(rawget(self, "ClassName")) .. ")")
	rawset(self, "__dead", true)
end
imeth.GetChildren = function(self)
	local o = {}
	for _, c in ipairs(self.__kids) do o[#o + 1] = c end
	return o
end
imeth.Raycast = function(self, o, dir, params)
	local inc = params and rawget(params, "IncludeInstances")
	local best, bt
	for _, p in ipairs(self.__kids) do
		local ok = true
		if inc then
			ok = false
			for _, q in ipairs(inc) do
				if q == p then ok = true end
			end
		end
		local s, c = rawget(p, "Size"), rawget(p, "CFrame")
		if ok and s and c then
			local lo = {c.X - s.X / 2, c.Y - s.Y / 2, c.Z - s.Z / 2}
			local hi = {c.X + s.X / 2, c.Y + s.Y / 2, c.Z + s.Z / 2}
			local oo = {o.X, o.Y, o.Z}
			local dd = {dir.X, dir.Y, dir.Z}
			local t0, t1 = 0, 1
			for i = 1, 3 do
				if dd[i] == 0 then
					if oo[i] < lo[i] or oo[i] > hi[i] then t0 = 2 end
				else
					local a, b = (lo[i] - oo[i]) / dd[i], (hi[i] - oo[i]) / dd[i]
					if a > b then a, b = b, a end
					if a > t0 then t0 = a end
					if b < t1 then t1 = b end
				end
			end
			if t0 <= t1 and (not bt or t0 < bt) then
				bt = t0
				best = p
			end
		end
	end
	if not best then
		plog("RAYCAST", "miss")
		return nil
	end
	local pos = V(o.X + dir.X * bt, o.Y + dir.Y * bt, o.Z + dir.Z * bt)
	plog("RAYCAST", "hit z=" .. tostring(pos.Z))
	return {Position = pos, Instance = best, Distance = bt * math.sqrt(dir.X ^ 2 + dir.Y ^ 2 + dir.Z ^ 2), Normal = V(0, 0, 1)}
end
local imt = {}
imt.__index = function(t, k)
	local m = imeth[k]
	if m then return m end
	return rawget(t, k)
end
imt.__newindex = function(t, k, v)
	local c = rawget(t, "CFrame")
	plog("SET", tostring(rawget(t, "ClassName")) .. (c and "@z" .. c.Z or "") .. "." .. tostring(k) .. " = " .. dsc(v))
	rawset(t, k, v)
	if k == "Parent" and type(v) == "table" and rawget(v, "__kids") then
		table.insert(v.__kids, t)
	end
end
imt.__tostring = function(t) return rawget(t, "ClassName") or "Instance" end
rawset(env, "Instance", {new = function(cls)
	plog("CALL", "Instance.new(" .. tostring(cls) .. ")")
	return setmetatable({ClassName = cls, __kids = {}}, imt)
end})

local __pid = 0
local __seen = setmetatable({}, {__mode = "k"})
local __print, __tostring, __type, __pairs, __fmt, __sort, __concat = print, tostring, type, pairs, string.format, table.sort, table.concat
local function __ser(v)
	local t = __type(v)
	if t == "number" then
		return "n:" .. __tostring(v)
	elseif t == "string" then
		return "s:" .. (v:gsub(".", function(c) return __fmt("%02x", c:byte()) end))
	elseif t == "boolean" then
		return v and "b:1" or "b:0"
	end
	return "x:" .. t
end
env.__dumpins = function(gb, ha)
	if __seen[gb] then
		return
	end
	__seen[gb] = true
	__pid = __pid + 1
	__print("PROTO", __pid, #gb, __tostring(ha))
	for i = 1, #gb do
		local parts = {}
		for k, v in __pairs(gb[i]) do
			parts[#parts + 1] = __tostring(k) .. "=" .. __ser(v)
		end
		__sort(parts)
		__print("INS", __pid, i, __concat(parts, ";"))
	end
end
setfenv(1, env)

local T = @@TABLE@@
local names = @@NAMES@@
local h = #names
for p = 0, h - 1 do
	T[names[(@@MUL@@ * p + @@ADD@@) % h + 1]] = T[p + 1]
end

local function hx(s)
	return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function wrap(tag, f)
	return function(...)
		local a = table.pack(...)
		local r = table.pack(f(...))
		local ins, outs = {}, {}
		for i = 1, a.n do
			ins[#ins + 1] = type(a[i]) == "string" and hx(a[i]) or "-"
		end
		for i = 1, r.n do
			outs[#outs + 1] = type(r[i]) == "string" and hx(r[i]) or "-"
		end
		print(tag, table.concat(ins, "\t"), table.concat(outs, "\t"))
		return table.unpack(r, 1, r.n)
	end
end

@@RUN@@
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
