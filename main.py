import split, hashlib, random, sys

def get_format(userinput):
   return {'integer': 10, '10': 10, 'i': 10,
           'hexadecimal': 16, 'hex': 16, 'h': 16, '16': 16,
           'base58check': 58, '58': 58}.get(userinput,-1)

def root_interface(givens):
   # Looks at the command and sends the code to the targe sub-interface
   if len(givens) == 0:
     print "\nWhat would you like to do?"
     print "Options are split (s), reconstitute (r), randomly generate new " + \
           "private key (rg), deterministically generate new private key " + \
           "from seed (dg), change format of a private key (f)"
     givens.append(raw_input("> "))
   # Interpret - and -- at the start as the commands without the prefixes
   if givens[0][0] == '-': givens[0] = givens[0][1:]
   if givens[0][0] == '-': givens[0] = givens[0][1:]
   if givens[0] in ("s", "split"): 
      split_interface(givens[1:])
   elif givens[0] in ("r", "reconstitute"):
      reconstitute_interface(givens[1:])
   elif givens[0] in ("g", "rg", "generate" "randomly generate"):
      random_generate_interface(givens[1:])
   elif givens[0] in ("dg", "deterministically generate"):
      generate_interface(givens[1:])
   elif givens[0] in ("f", "format", "changeformat"):
      change_format_interface(givens[1:])


def split_interface(args):
   # Splits a key
   # Grammar: python main.py --split [privkey] [n] [k (1<=k<=n)]
   if len(args) == 0:
     args.append(split.trial_and_error_decode(raw_input(
            "Enter private key (any format): ")))
   if len(args) == 1:
     args.append(raw_input(
             "How many parts do you want to split your key into? (1-14): "))
   if len(args) == 2:
     args.append(raw_input(
             "How many parts should be required to reconstitute your " + \
            "key? (1-%d): " % int(args[1])))
   v = split.split(args[0],int(args[2]),int(args[1]))
   print "Write down the key parts:"
   for i in v: print i

def reconstitute_interface(args):
   p,k,first,second,manual_input = [],999,True,True,False
   # Gather up a list of n-pieces, with some moderately complex UI logic
   # to help the user along
   # Grammar: python main.py --reconstitute [piece 1] ... [piece n] [format]
   if len(args) == 0:
    while len(p) < k:
      if len(args) == 0: 
        # The first time that we have information on k AND it's the user input
        # ting manually, print the "$1 total pieces required, $2 to go" string
        if len(p) > 0 and second:
           k = (split.trial_and_error_decode(p[0]) / (256 ** 37)) % 256 - 147
           print "%d total pieces required, %d to go" % (k, k-len(p))
           second = False
        if first: print "Enter the key parts:"
        v = raw_input("> ")
        manual_input = True
      else: v = args.pop(0)
      p.append(v)
      if first and manual_input: first = False
      # We have to do this at the end of the first round since the k
      # parameter might actually be 1, in which case we should end the
      # while loop after this immediately
      k = (split.trial_and_error_decode(p[0]) / (256 ** 37)) % 256 - 147
   # Too many pieces inputted, don't interpret an extra piece as the base
   # parameter
   while len(args) > 0 and get_format(args[0]) == -1: args.pop(0)
   if len(args) == 0: args.append(raw_input(
                     "Please enter format: integer(10), hexadecimal(16) " + \
                     "or base58check wallet import format (58): "))
   print split.reconstitute(p,get_format(args[0]))

def random_generate_interface(args):
   # Generates a random key
   if len(args) == 0: args.append(raw_input(
                      "Please enter format: integer(10), hexadecimal(16) " + \
                      "or base58check wallet import format (58): "))
   print split.formatpk(random.randrange(2**256),get_format(args[0]))

def generate_interface(args):
   # Generates a key from a seed
   if len(args) == 0: args.append(raw_input("Enter your seed: "))
   if len(args) == 1: args.append(raw_input(
                      "Please enter format: integer(10), hexadecimal(16) " + \
                      "or base58check wallet import format (58): "))
   print split.makepk(args[0],get_format(args[1]))

def change_format_interface(args):
   # Changes a key to the target format
   if len(args) == 0: args.append(raw_input("Please enter key in any format: "))
   if len(args) == 1: args.append(raw_input(
                     "Please enter format: integer(10), hexadecimal(16) " + \
                     "or base58check wallet import format (58): "))
   print split.formatpk(args[0],get_format(args[1]))

def main():
   root_interface(sys.argv[1:])

if __name__ == '__main__': main()
