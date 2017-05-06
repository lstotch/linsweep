import logging
from binaryninja import *

logging.disable(logging.WARNING)
alignment = ["\xcc", "\xc3"]
suggestions = ["\x64\x48\x8b", "\x55\x8b\xec", "\x8b\xff\x56", "\x8b\xff\x55", "\xff\x25", "\x48\x8b\xc4"]
MIN_PRO_COUNT = 10
MIN_IL = 10


def model(bv, br):
    pros = {}
    for f in bv.functions:
        if len(f.low_level_il) < MIN_IL:
            continue
        br.seek(f.start)
        pro = br.read(3)
        if pro in pros:
            pros[pro] += 1
        else:
            pros[pro] = 1
    ret = []
    for k in sorted(pros, key=pros.get, reverse=True):
        if pros[k] > MIN_PRO_COUNT:
            ret.append(k)
        else:
            break
    for s in suggestions:
        if s not in ret:
            ret.append(s)
    return ret


def find_functions(bv, br, tgt, post=False):
    cur = bv.find_next_data(bv.start, tgt)
    funcs = len(bv.functions)
    while cur:
        if post:
            while True:
                br.seek(cur + 1)
                if br.read(len(tgt)) == tgt:
                    cur += 1
                else:
                    cur += len(tgt)
                    break
        if bv.get_function_at(cur) is None:
            bv.add_function(cur)
            f = bv.get_function_at(cur)
            if f.name[0:4] == 'sub_':
                if len(f.low_level_il) < 5:
                    bv.remove_user_function(f)
        cur = bv.find_next_data(cur + 1, tgt)
    if len(bv.functions) > funcs:
        print "%3d functions created using search: %s" % (len(bv.functions) - funcs, tgt.encode('hex'))


def sweep(bv):
    fs = len(bv.functions)
    br = BinaryReader(bv)
    pros = model(bv, br)
    find_functions(bv, br, "\xcc"*4, True)
    for prologue in pros:
        find_functions(bv, br, prologue)
    print("Totals: Created %d new functions" % (len(bv.functions) - fs))

PluginCommand.register("Simple Linear Sweep", "Search for function prologues from bv.start", sweep)
