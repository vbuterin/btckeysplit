
from __future__ import print_function
import hashlib, random, copy, re, sys, time
from mathfuncs import *

# Shamir's Secret Sharing scheme
def shamir_share(val,k,n,arithmetic=ModularInt):
  vals = [val]
  for i in range(k-1): vals.append(random.randrange(2**256))
  output = []
  for x in range(1,n+1):
    output.append(shamir_encode(vals,x,arithmetic))
  return output

# Returns the result of taking the x coordinate of the polynomial vals
def shamir_encode(vals,x,arithmetic=ModularInt):
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
   # Generate output y-intercept
   b = zero
   for i in range(len(xs)):
     yslice = arithmetic(pieces[i]) / denoms[i]
     b += nums[i][0] * yslice
   return b
