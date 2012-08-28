import split, hashlib

def get_format(userinput):
      return {'integer': 10, '10': 10, 'i': 10,
              'hexadecimal': 16, 'hex': 16, 'h': 16, '16': 16,
              'base58check': 58, '58': 58}[userinput]

def root_interface():
   print "What would you like to do?"
   print "Options are split (s), reconstitute (r), deterministically " + \
         "generate new private key from seed (g), generate keypiece from " + \
         "seed (gk)"
   opt = raw_input("> ")
   if opt in ("s", "split"): split_interface()
   elif opt in ("r", "reconstitute"): reconstitute_interface()
   elif opt in ("g", "generate"): generate_interface()
   elif opt in ("gk", "keypiece"): generate_keypiece_interface()


def split_interface():
   pk = split.trial_and_error_decode(raw_input(
      "Enter private key (any format): "))
   n = int(raw_input(
      "How many parts do you want to split your key into? (1-14): "))
   key = None
   if n > 1:
      useexisting = raw_input(
         "Would you like to derive one of the pieces from a seed? (y/n) ")
      if useexisting in ('y','yes','Y','YES'):
         seed = raw_input("Enter the seed: ")
         key = split.decode(hashlib.sha256(seed).digest(),256)

   k = int(raw_input(
      "How many parts should be required to reconstitute your " + \
      "key? (%d-%d): " % (2 if key else 1,n)))
   v = split.split(pk,k,n,key) if key else split.split(pk,k,n)
   print "Write down the key parts:"
   for i in v: print i

def reconstitute_interface():
   p,k,first = [],999,True
   print "Enter the key parts:"
   while len(p) < k:
      v = raw_input("> ")
      p.append(v)
      if first:
         k = (split.trial_and_error_decode(v) / (256 ** 37)) % 256 - 147
         if k > 0:
           print "%d total pieces required, %d to go" % (k, k-len(p))
           first = False
         else:
           print "Seed-based keyparts carry no metadata; remaining pieces required unknown"
           k = 999

   formt = raw_input(
         "Please enter format: integer(10), hexadecimal(16) " + \
         "or base58check wallet import format (58): ")
   print split.reconstitute(p,get_format(formt))

def generate_interface():
   seed = raw_input("Enter your seed: ")
   formt = raw_input(
         "Please enter format: integer(10), hexadecimal(16) " + \
         "or base58check wallet import format (58): ")
   print split.makepk(seed,get_format(formt))

def generate_keypiece_interface():
   seed = raw_input("Enter your seed: ")
   print split.make_keypiece(seed)


def main():
   while 1: root_interface()

if __name__ == '__main__': main()
