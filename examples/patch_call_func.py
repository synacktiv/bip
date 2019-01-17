
from bip.base import *

name = "hello"
sc = '\xff\xd0' # call rax

# name is the name of the function,
# sc is a string of bytes
# This does not remove the xref to the IdaFunction 
def patch_call_to_func(name, sc):
    f = IdaFunction.get_by_name(name)
    for i in f.xCodeTo:
        if i.mnem == "call":
            if i.size < len(sc):
                print("Could not patch {} (not enough place)".format(i))
                continue
            s = sc + ("\x90" * (i.size - len(sc)))
            i.bytes = s
        else:
            print("Not a call at {}".format(i))



