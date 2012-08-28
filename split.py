import hashlib, random, copy, re

def hash256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()

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

def base58check(inp,vbyte='',length=0):
   if isinstance(vbyte,str):
      if len(vbyte) == 2: vbyte = decode(vbyte,16)
      elif len(vbyte) == 0: vbyte = 0
   padding = '\x00' * max(length - len(encode(inp,256)),0)
   inp256 = chr(vbyte) + padding + encode(inp,256)
   leadingzbytes = len(re.match('^\x00*',inp256).group(0))
   checksum = hash256(inp256)[:4]
   return '1' * leadingzbytes + changebase(inp256+checksum,256,58)

def base58export(b58string,to256=False):
   binary = changebase(b58string,58,256)
   for i in range(6):
      checkhash = hash256('\x00'*i+binary[:-4])
      if (checkhash[:4] ==   binary[-4:]):
         string256 = ('\x00'*i+binary[:-4])[1:]
         return string256 if to256 else decode(string256,256)
   print "Base 58 checksum failed"

def frontpad(string, length='64', char='0'):
   return char*(length-len(string))+string if len(string) < length else string

def xor256(a,b):
   conv = {'00':'0','01':'1','10':'1','11':'0'}
   a = frontpad(encode(a,2),256)
   b = frontpad(encode(b,2),256)
   return decode(''.join([conv[a[i]+b[i]] for i in range(256)]),2)

def trial_and_error_decode(inp):
   if isinstance(inp,str):
      try: return int(inp)
      except: pass
      for i in (range(32)+range(123,256)):
         if chr(i) in [x for x in inp]:
            return decode(inp,256)
      for i in 'GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz':
         if i in [x for x in inp]:
            return base58export(inp)
      return decode(inp,16)
   return inp

def split(inp, k, n, v1=None):
   vals = [v1 if v1 else random.randrange(2**256)]
   inp = trial_and_error_decode(inp)
   remainder = xor256(inp,vals[0])
   for i in range(k-2):
      # Max value is needed because at higher values of n and k
      # there is a risk of overflow. Different implementations
      # of randmax are nevertheless compatible with each other
      randmax = 2**275 / (3*i+1) ** (i+1)
      vals.append(random.randrange(min(2**256,randmax)))
      remainder = xor256(remainder,vals[-1])
   vals.insert(1,remainder)
   res = 0
   for i in range(len(vals)): res = xor256(res,vals[i])
   assert res == inp, 'xor256 failed'
   output = []
   # The pieces skip 1 because giving away a+b as a single
   # piece when the original key is XOR(a,b) may have unacceptably high
   # information leakage. If it is agreed that this fear is unfounded,
   # pieces can start counting from 1 without fear of breaking backward
   # compatibility
   for x in [0] + range(2,n+1):
      prefix = encode(147+k,16)
      checksum = ord(hash256(encode(inp,256))[0])
      prefix += encode(24576 + x*256 + checksum,16)
      # Keypieces made from a seed have no metadata
      if x == 0 and v1: prefix = '936000'
      total = 0
      # Equivalent to Shamir's secret sharing scheme - vals[j] is the jth order
      # polynominal coefficient, and x is the x coordinate
      for j in range(k):
         total += vals[j] * x**j #Fortunately, 0**0 == 1
      final_value = decode(prefix,16) * 256 ** 35 + total
      output.append(base58check(final_value,'4f'))
   return output

def elim(a,b):
   # Two-equation linear system solver
   # Format:
   # 3x + 4y = 80 (ie. 3x + 4y - 80 = 0) -> a = [3,4,-80]
   # 5x + 2y = 70 (ie. 5x + 2y - 70 = 0) -> b = [5,2,-70]
   aprime = [x*b[0] for x in a]
   bprime = [x*a[0] for x in b]
   c = [aprime[i] - bprime[i] for i in range(1,len(a))]
   return c

def evaluate(a,vals):
   # Linear equation solver
   # Format:
   # 3x + 4y = 80, y = 5 (ie. 3x + 4y - 80z = 0, y = 5, z = -1)
   #      -> a = [3,4,-80], vals = [5,1]
   tot = 0
   for i in range(len(vals)):
      tot += a[i+1] * vals[i]
   return -tot / a[0]

def reconstitute(pieces,formt):
   # Takes in k pieces in base58 form and outputs the original private key
   # in the desired format
   hexpc = [encode(base58export(p),16) for p in pieces]
   k = max([decode(hexpc[i][0:2],16) - 147 for i in range(len(hexpc))])
   if len(pieces) > k: hexpc = hexpc[:k]
   places = [decode(h[3],16) for h in hexpc]
   vals = [decode(h[6:],16) for h in hexpc]
   eqs = []
   for i in range(len(vals)):
      eqs.append([])
      for j in range(k):
         eqs[-1].append(places[i]**j)
      eqs[-1].append(-vals[i])
   back_eqs = [eqs[0]]
   while len(eqs) > 1:
      neweqs = []
      for i in range(len(eqs)-1):
         neweqs.append(elim(eqs[i],eqs[i+1]))
      eqs = neweqs
      back_eqs.insert(0,eqs[0])
   kvals = [1]
   for i in range(k):
      kvals.insert(0,evaluate(back_eqs[i],kvals))
   result = 0
   for i in range(k):
      result = xor256(result,kvals[i])
   realhash = ord(hash256(encode(result,256))[0])
   for i in range(len(hexpc)):
      # DO NOT expect a keypiece that can potentially be regenerated
      # without knowing the address to have a valid checksum
      if decode(hexpc[i][0:2],16) != 147:
         checkhash = decode(hexpc[i][4:6],16)
         assert checkhash == realhash, "Error: reconstitution checksum failed"
   return formatpk(result,formt)

def formatpk(inp,formt):
   formats= {10: lambda x: str(x),
             16: lambda x: encode(x,16),
             58: lambda x: base58check(x,'80',32),
             256: lambda x: encode(x,256)}
   return formats[formt](trial_and_error_decode(inp))

def makepk(seed,formt):
   return formatpk(hashlib.sha256(seed).hexdigest(),formt)
   
def make_keypiece(seed):
   base = decode(hashlib.sha256(seed).digest(),256)
   # No checksum
   val = (147 * 65536 + 24576) * (256 ** 35) + base
   return base58check(val,'4f')
