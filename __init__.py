import logging
from binaryninja import *


logging.disable(logging.WARNING)
supported_archs = ['x86', 'x86_64']
alignment = ["\xcc", "\xc3"]
suggestions = ["\x55\x8b\xec",
               "\x40\x55\x48\x83\xec",
               "\x64\x48\x8b",
               "\x8b\xff\x56",
               "\x8b\xff\x55",
               "\xff\x25",
               "\x48\x8b\xc4",
               "\x48\x83\xec",
               "\x48\x81\xec",
               "\x8b\x54\x24\x04",
               "\x8b\x4c\x24\x04"]
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


def search(bv, br, align, pro, start, end, apnd=''):
    tgt = align + pro
    cur = bv.find_next_data(start, tgt)
    funcs = len(bv.functions)
    while cur:
        if pro == '':
            while True:
                n = bv.find_next_data(cur + 1, tgt)
                if n is None or (n - cur) > 1:
                    cur = cur + len(align)
                    break
                cur = n
        else:
            cur += len(align)
        if cur > end:
            break
        if bv.get_basic_blocks_at(cur) == []:
            bv.add_function(cur)
            bv.update_analysis()
            f = bv.get_function_at(cur)
            if f.name[0:4] == 'sub_':
                # if len(f.low_level_il) < 5:
                #     print "[linsweep] Removing Function At: %s" % f.name
                #     bv.remove_user_function(f)
                # else:
                f.name = f.name + apnd
        cur = bv.find_next_data(cur + 1, tgt)
    if len(bv.functions) > funcs:
        print "[linsweep] %3d functions created using search: %s" % (len(bv.functions) - funcs, tgt.encode('hex'))


def find_functions(bv, br, tgts, start, end, apnd=''):
    for prologue in tgts:
        for align in alignment:
            search(bv, br, align, prologue, start, end, apnd)
        search(bv, br, '', prologue, start, end, apnd)


def sweep(bv, mode):
    if bv.arch.name not in supported_archs:
        interaction.show_message_box('Linear Sweep', "Architecture [%s] not currently supported" % bv.arch.name,
                                     buttons=MessageBoxButtonSet.OKButtonSet, icon=MessageBoxIcon.ErrorIcon)
        return
    fs = len(bv.functions)
    br = BinaryReader(bv)
    print "[linsweep] Cautious Search Start"
    pros = model(bv, br)
    if '.text' in bv.sections:
        start = bv.sections['.text'].start
        end = bv.sections['.text'].end
    else:
        start = bv.start
        end = bv.end
    find_functions(bv, br, pros, start, end, "-C")
    fsc = len(bv.functions)
    print "[linsweep] Cautious: Found %d New Functions" % (fsc - fs)
    if mode == AGGRESSIVE:
        print "[linsweep] Aggressive Search Start"
        find_functions(bv, br, suggestions, bv.start, bv.end, "-A")
        search(bv, br, align="\xcc"*4, pro='', start=bv.start, end=bv.end, apnd="-P")
        print "[linsweep] Aggressive: Found %d New Functions" % (len(bv.functions) - fsc)
    interaction.show_message_box('Linear Sweep', "Created %d new functions" % (len(bv.functions) - fs),
                                 buttons=MessageBoxButtonSet.OKButtonSet)


def sweep_cat(bv):
    sweep(bv, CAUTIOUS)


def sweep_agro(bv):
    sweep(bv, AGGRESSIVE)


def sweep_user(bv, addr, size):
    br = BinaryReader(bv)
    br.seek(addr)
    tgt = [br.read(size)]
    print "[linsweep] User Defined Search Start"
    fs = len(bv.functions)
    find_functions(bv, br, tgt, bv.start, bv.end, "-U")
    print "[linsweep] User: Found %d New Functions" % (len(bv.functions) - fs)
    interaction.show_message_box('Linear Sweep', "Created %d new functions" % (len(bv.functions) - fs),
                                 buttons=MessageBoxButtonSet.OKButtonSet)


PluginCommand.register("Simple Linear Sweep - Cautious", "Search for existing prologues in text section", sweep_cat)
PluginCommand.register("Simple Linear Sweep - Aggressive", "Search for function prologues from bv.start", sweep_agro)
PluginCommand.register_for_range("Simple Linear Sweep - User", "Search for selected data as a prologue", sweep_user)

