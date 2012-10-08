import unittest
import random
import hashlib
import shamir as s
import bitcoin as b
import mathfuncs

class Tests(unittest.TestCase):

  def base_encoder_tests(self):
    self.assertEqual(b.encode(1029,256),'\x04\x05')
    self.assertEqual(b.decode('DEADBEEF',16),3735928559)
    r = random.randrange(2**256)
    self.assertEqual(b.decode(b.changebase(b.encode(r,16),16,58),58),r)
    self.assertEqual(b.base58export(b.base58check(r,101,34)),r)
  
  def pk_function_tests(self):
    seed = 'horse rabbit cow'
    k58 = b.makepk(seed,58)
    k16 = b.makepk(seed,16)
    self.assertEqual(k58,'5KLipFbYY8NTU4SJdKmzidVsw3WhdrwsmCTbLgYVCY4NWF3Hwxs')
    self.assertEqual(k16,'c8cd79f6a89a089ecf0035b1cce059cbbecd85d2d6a2a5edb023a825a3cb2624')
    self.assertEqual(b.base58export('18Tw87wAwjWXg3RQ2oY4oTsn68scDQ2gsL'),467443130064359750498234077082078405762457967729)
    self.assertEqual(b.encode(b.base58export(k58),16),k16)

  def split_reconstitute_tests_with_modularint(self):
    mi = mathfuncs.ModularInt
    seed = 'horse rabbit dog'
    pk16 = b.makepk(seed,16)
    pk58 = b.makepk(seed,58)
    e16 = b.split(pk16,3,7,mi)
    e58 = b.split(pk58,3,7,mi)
    self.assertEqual(b.reconstitute([e16[2],e16[5],e16[4]],16),pk16)
    self.assertEqual(b.reconstitute([e16[1],e16[3],e16[6]],58),pk58)
    self.assertEqual(b.reconstitute([e58[3],e58[4],e58[0]],16),pk16)
    self.assertEqual(b.reconstitute([e58[0],e58[2],e58[4],e58[6]],58),pk58)

  def split_reconstitute_tests_with_galois(self):
    gal = mathfuncs.Galois
    seed = 'horse rabbit dog'
    pk16 = b.makepk(seed,16)
    pk58 = b.makepk(seed,58)
    e16 = b.split(pk16,3,7,gal)
    e58 = b.split(pk58,3,7,gal)
    self.assertEqual(b.reconstitute([e16[2],e16[5],e16[4]],16),pk16)
    self.assertEqual(b.reconstitute([e16[1],e16[3],e16[6]],58),pk58)
    self.assertEqual(b.reconstitute([e58[3],e58[4],e58[0]],16),pk16)
    self.assertEqual(b.reconstitute([e58[0],e58[2],e58[4],e58[6]],58),pk58)

if __name__ == '__main__':
  unittest.main()
