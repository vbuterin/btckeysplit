
from __future__ import print_function
import hashlib, random, copy, re, sys, time
from mathfuncs import *


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

def split(inp, k, n, arithmetic=ModularInt):
   inp = trial_and_error_decode(inp)
   vals = [inp]
   for i in range(k-1):
      vals.append(random.randrange(2**256))
   output = []
   for x in range(1,n+1):
      ## Format
      ## [00 = prefix] [01 = 96+xcor] [02 = checksum] [03 = version byte]
      ## [04-05 = reserved for later use] [06 .. 37 = payload]
      checksum = ord(hash256(encode(inp,256))[0])
      prefix = [147+k,96+x,checksum,2 if arithmetic == Galois else 1,0,0]
      total = 0
      # Equivalent to Shamir's secret sharing scheme - vals[j] is the jth order
      # polynominal coefficient, and x is the x coordinate
      total = shamir_encode(vals,x,arithmetic)
      final_value = reduce(lambda x,y: x*256+y,prefix[:6]) * 256 ** 32 + total
      output.append(base58check(final_value,'4f'))
   return output

# Returns the result of taking the x coordinate of the polynomial vals
def shamir_encode(vals,x,arithmetic):
   # vals [int2^256, int2^256 ...], x int2^8, ModInt/Galois -> int2^256
   total = arithmetic(0)
   xfactor = arithmetic(0).xcor(1)
   xv = arithmetic(0).xcor(x)
   for j in range(len(vals)):
      total = total + arithmetic(vals[j]) * xfactor
      xfactor = xfactor * xv
   return total.export()

def lagrange_interp(pieces,xs,arithmetic=Normal):
   zero, one = arithmetic(0), arithmetic(0).xcor(1)
   # Generate master numerator polynomial
   root = [one]
   xobjs = [arithmetic(0).xcor(x) for x in xs]
   for i in range(len(xs)):
     root.insert(0,zero)
     for j in range(len(root)-1):
       root[j] = root[j] - root[j+1] * xobjs[i]
   # Generate per-value numerator polynomials by dividing the master
   # polynomial back by each x coordinate
   nums = []
   for i in range(len(xs)):
     output = []
     last = one
     for j in range(2,len(root)+1):
       output.insert(0,last)
       if j != len(root): last = root[-j] + last * xobjs[i]
     nums.append(output)
   # Generate denominators by evaluating numerator polys at their x
   denoms = []
   for i in range(len(xs)):
     denom = zero
     xcpower = one
     for j in range(len(nums[i])):
       denom += xcpower * nums[i][j]
       xcpower *= xobjs[i]
     denoms.append(denom)
   # Generate output polynomial
   poly = [zero] * len(xs)
   for i in range(len(xs)):
     yslice = arithmetic(pieces[i]) / denoms[i]
     for j in range(len(xs)):
       poly[j] += nums[i][j] * yslice
   return poly

def reconstitute(pieces,formt):
   # Takes in k pieces in base58 form and outputs the original private key
   # in the desired format
   ## Format
   ## [00 = prefix] [01 = 96+xcor] [02 = checksum] [03 = version byte]
   ## [04-05 = reserved for later use] [06 .. 37 = payload]
   binpc = [encode(base58export(p),256) for p in pieces]
   k = max([ord(binpc[i][0]) - 147 for i in range(len(binpc))])
   arithmetic = Galois if ord(binpc[0][3]) == 2 else ModularInt
   if len(pieces) > k: binpc = binpc[:k]
   places = [ord(b[1]) % 16 for b in binpc]
   vals = [decode(b[6:],256) for b in binpc]
   kvals = lagrange_interp(vals,places,arithmetic)
   result = kvals[0].export()
   realhash = ord(hash256(encode(result,256))[0])
   for i in range(len(binpc)):
      checkhash = ord(binpc[i][2])
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
