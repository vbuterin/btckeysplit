from shamir import *

# Double SHA256, standard for BTC
def hash256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()

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
   print ("Base 58 checksum failed")

# Attempts to decode a privkey in any format to an integer
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

def formatpk(inp,formt):
   formats= {10: lambda x: str(x),
             16: lambda x: encode(x,16),
             58: lambda x: base58check(x,'80',32),
             256: lambda x: encode(x,256)}
   return formats[formt](trial_and_error_decode(inp))

def makepk(seed,formt):
   return formatpk(hashlib.sha256(seed).hexdigest(),formt)

def split(inp, k, n, arithmetic=ModularInt):
   inp = trial_and_error_decode(inp)
   shares = shamir_share(inp,k,n,arithmetic)
   output = []
   for i in range(n):
      ## Format
      ## [00 = prefix] [01 = 96+xcor] [02 = checksum] [03 = version byte]
      ## [04-05 = reserved for later use] [06 .. 37 = payload]
      checksum = ord(hash256(encode(inp,256))[0])
      prefix = [147+k,96+i+1,checksum,2 if arithmetic == Galois else 1,0,0]
      final_value = reduce(lambda x,y: x*256+y,prefix[:6]) * 256 ** 32 + shares[i]
      output.append(base58check(final_value,'4f'))
   return output

def reconstitute(pieces,formt):
   ## Format
   ## [00 = prefix] [01 = 96+xcor] [02 = checksum] [03 = version byte]
   ## [04-05 = reserved for later use] [06 .. 37 = payload]
   binpc = [encode(base58export(p),256) for p in pieces]
   k = max([ord(binpc[i][0]) - 147 for i in range(len(binpc))])
   arithmetic = Galois if ord(binpc[0][3]) == 2 else ModularInt
   if len(pieces) > k: binpc = binpc[:k]
   places = [ord(b[1]) % 16 for b in binpc]
   vals = [decode(b[6:],256) for b in binpc]
   result = lagrange_interp(vals,places,arithmetic).export()
   realhash = ord(hash256(encode(result,256))[0])
   for i in range(len(binpc)):
      checkhash = ord(binpc[i][2])
      assert checkhash == realhash, "Error: reconstitution checksum failed"
   return formatpk(result,formt)

