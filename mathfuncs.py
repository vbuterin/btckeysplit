def get_code_string(base):
   if base == 2: return '01'
   elif base == 10: return '0123456789'
   elif base == 16: return "0123456789abcdef"
   elif base == 58: return "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
   elif base == 256: return ''.join([chr(x) for x in range(256)])
   else: raise ValueError("Invalid base!")

def encode(val,base):
   code_string = get_code_string(base)
   result = ""   
   while val > 0:
      result = code_string[val % base] + result
      val /= base
   return result

def decode(string,base):
   code_string = get_code_string(base)
   result = 0
   if base == 16: string = string.lower()
   while len(string) > 0:
      result *= base
      result += code_string.find(string[0])
      string = string[1:]
   return result

def changebase(string,frm,to):
   return encode(decode(string,frm),to)

# A basic field for testing purposes
class Normal:
  def __init__(self,val): self.val = val
  def __add__(self,other): return Normal(self.val + other.val)
  def __sub__(self,other): return Normal(self.val - other.val)
  def __mul__(self,other): return Normal(self.val * other.val)
  def __div__(self,other): return Normal(self.val * 1.0 / other.val)
  def xcor(self,x): return Normal(x)
  def export(self): return self.val

# Integers mod the Bitcoin protocol's N

modulus_hexv = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
modulus = decode(modulus_hexv,16)

class ModularInt:
  def __init__(self,val): self.val = val % modulus
  def __add__(self,other): return ModularInt(self.val + other.val)
  def __sub__(self,other): return ModularInt(self.val - other.val)
  def __mul__(self,other): return ModularInt(self.val * other.val)
  def modularinv(self,v): # 1/v mod n
    high, ha, hb = modulus,1,0
    low, la, lb = v,0,1
    while low > 1:
       new = high % low
       na = ha - la * (high / low)
       nb = hb - lb * (high / low)
       high, ha, hb = low, la, lb
       low, la, lb = new, na, nb
    return lb if lb > 0 else (lb + modulus)
  def __div__(self,other):
    return self * ModularInt(self.modularinv(other.val))
  def xcor(self,x): return ModularInt(x)
  def export(self): return self.val

# per-byte 2^8 Galois field

# Precomputing a multiplication and XOR table for increased speed
def galoistpl(a):
   # 2 is not a primitive root, so we have to use 3 as our logarithm base
   unrolla = [a/(2**k) % 2 for k in range(8)]
   res = [0] + unrolla
   for i in range(8): res[i] = (res[i] + unrolla[i]) % 2
   if res[-1] == 0: res.pop()
   else:
     # AES Polynomial
     for i in range(9): res[i] = (res[i] - [1,1,0,1,1,0,0,0,1][i]) % 2
     res.pop()
   return sum([res[k] * 2**k for k in range(8)])
glogtable = [0] * 256
gexptable = []
gxortable = []
v = 1
for i in range(255):
  glogtable[v] = i
  gexptable.append(v)
  v = galoistpl(v)
for i in range(16):
  gxortable.append([])
  for j in range(16):
     unrolli = [i/(2**k) % 2 for k in range(4)]
     unrollj = [j/(2**k) % 2 for k in range(4)]
     x = sum([((unrolli[k] + unrollj[k]) % 2) * 2**k for k in range(4)])
     gxortable[i].append(x)

class Galois:
  def __init__(self,val):
    if isinstance(val,list): self.val = val
    else:
      self.val = []
      for i in range(32):
        self.val.append(val % 256)
        val /= 256
  def gxor(self,a,b):
     return 16 * (gxortable[a/16][b/16]) + gxortable[a%16][b%16]
  def gmul(self,a,b):
    if a == 0 or b == 0: return 0
    return gexptable[(glogtable[a]+glogtable[b])%255]
  def gdiv(self,a,b):
    if a == 0: return 0
    return gexptable[(glogtable[a]-glogtable[b])%255]
  def wrap(self,f):
    return lambda a,b: Galois([f(c,d) for c,d in zip (a.val,b.val)])
  def __add__(self,other): return self.wrap(self.gxor)(self,other)
  def __sub__(self,other): return self.wrap(self.gxor)(self,other)
  def __mul__(self,other): return self.wrap(self.gmul)(self,other)
  def __div__(self,other): return self.wrap(self.gdiv)(self,other)
  def xcor(self,x): return Galois([x] * 32)
  def export(self):
     return sum([self.val[k] * 256**k for k in range(32)])
