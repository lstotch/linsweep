import logging
from binaryninja import *


logging.disable(logging.WARNING)
supported_archs = ['x86', 'x86_64']
alignment = ["\xcc", "\xc3"]
suggestions = ["\x64\x48\x8b", "\x8b\xff\x56", "\x8b\xff\x55", "\xff\x25", "\x48\x8b\xc4", "\x48\x83\xec", "\x48\x81\xec"]
MIN_PRO_COUNT = 8
MIN_IL = 10
CAUTIOUS = 0
AGGRESSIVE = 1


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
        if bv.get_basic_blocks_at(cur) == []:
            bv.add_function(cur)
            f = bv.get_function_at(cur)
            if f.name[0:4] == 'sub_':
                if len(f.low_level_il) < 5:
                    bv.remove_user_function(f)
        cur = bv.find_next_data(cur + 1, tgt)
    if len(bv.functions) > funcs:
        print "[linsweep] %3d functions created using search: %s" % (len(bv.functions) - funcs, tgt.encode('hex'))


def sweep(bv, mode):
    if bv.arch.name not in supported_archs:
        print "[linsweep] Arch not supported: %s" % bv.arch.name
        return
    fs = len(bv.functions)
    br = BinaryReader(bv)
    pros = model(bv, br)
    print "[linsweep] Cautious Search Start"
    for prologue in pros:
        find_functions(bv, br, prologue)
    fsc = len(bv.functions)
    print "[linsweep] Cautious: Found %d New Functions" % (fsc - fs)
    if mode == AGGRESSIVE:
        print "[linsweep] Aggressive Search Start"
        find_functions(bv, br, "\xcc" * 2, True)
        for prologue in suggestions:
            find_functions(bv, br, prologue)
        print "[linsweep] Aggressive: Found %d New Functions" % (len(bv.functions) - fsc)
    print("[linsweep] Totals: Created %d new functions" % (len(bv.functions) - fs))


def sweep_cat(bv):
    sweep(bv, CAUTIOUS)


def sweep_agro(bv):
    sweep(bv, AGGRESSIVE)


PluginCommand.register("Simple Linear Sweep - Cautious", "Search for function prologues from bv.start", sweep_cat)
PluginCommand.register("Simple Linear Sweep - Aggressive", "Search for function prologues from bv.start", sweep_agro)

