from bip.base import *

def colorcall(color=0xFFAA55):
    for i in Instr.iter_all():
        # if the instruction is a call we color it
        if i.is_call:
            i.color = color
            continue
        # if the instruction is in a func and it jump out of it we color it
        if i.is_in_func:
            f = i.func
            for elt in i.xCfNext:
                if not f.is_inside(elt):
                    i.color = color
                    break

def colorcall_in_func(color=0xFFAA55):
    for f in BipFunction.iter_all():
        for i in f.instr:
            if i.is_call:
                i.color = color
                continue
            # if the instr jump out of the func we color it
            for elt in i.xCfNext:
                if not f.is_inside(elt):
                    i.color = color
                    break



