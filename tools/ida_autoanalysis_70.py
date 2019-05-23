__author__ = 'installer'

from idaapi import *
from idc import *
import extract_switch_case_70
import extract_nested_if_simple_70
import extract_hard_string_70

def extract_hard_string_main():
    open_strings_window(0)  # fixed: solve the always-0-string problem
    count = get_strlist_qty()
    strings = Strings()
    refed_str = []
    for i in range(count):
        si = string_info_t()
        get_strlist_item(si, i)
        refed_str.append((i, si))
    print "Total", len(refed_str)

    hard_strings = []
    for i, si in refed_str:
        item = {}
        item["i"] = i
        item["ea"] = si.ea
        item["length"] = si.length
        item["string"] = str(strings[i]).decode('latin-1')
        hard_strings.append(item)

    return hard_strings
    

def extract_switch_case_main():
    min_ea = get_inf_attr(INF_MIN_EA)
    max_ea = get_inf_attr(INF_MAX_EA)
    func_list = list(Functions(min_ea, max_ea))
    switches = []
    for f in func_list:
        f = int(f)
        func = get_func(f)
        if not func:
            log("Cannot get a function object for 0x%x" % f)
            exit(0)

        flow = FlowChart(func)

        for block in flow:
            for x in list(Heads(block.start_ea, block.end_ea)):
                switch = get_switch_info(x)
                if switch:
                    item = {}
                    info = {}
                    info['function'] = hex(f)
                    info['ncases'] = switch.ncases  # length of indirect table for switch statement
                    info['jumps'] = hex(switch.jumps)  # position of entrences of case branches
                    info['values'] = hex(switch.values)  # position of indirect table for switch statement
                    info['lowcase'] = hex(switch.lowcase)
                    info['defjump'] = hex(switch.defjump)  # position of default branch
                    info['startea'] = hex(switch.startea)  # start of switch insns, probably a cmp inst
                    item['switch'] = info

                    switch_cases = switch.get_jtable_size()
                    item['switch_cases'] = switch_cases  # number of cases

                    results = calc_switch_cases(x, switch)
                    result = {}
                    #result['case_len'] = len(results.cases)
                    result['target_len'] = len(results.targets)
                    result['targets'] = []
                    for idx in xrange(len(results.targets)):
                        result['targets'].append(hex(results.targets[idx]))

                    # It seems that IDAPython for idaq64 has some bug when reading
                    # switch's cases. Do not attempt to read them if the 'cur_case'
                    # returned object is not iterable.
                    result['cases'] = []
                    for idx in xrange(len(results.cases)):
                        cur_case = results.cases[idx]
                        acase = []
                        for cidx in xrange(len(cur_case)):
                            case_id = cur_case[cidx]
                            acase.append(case_id)
                        result['cases'].append(acase)

                    item['result'] = result
                    switches.append(item)
                    print item
                    print ""

    return switches


def find_longest_item(nested_if_list):
    longest_item = []
    for item in nested_if_list:
        if item in longest_item:
            continue
        
        # if longest_item is part of current item, erase it and append current one
        for l_item in longest_item:  
            if len(l_item) >= len(item):
                continue
            is_part_of = True
            for l_t in l_item:
                if l_t not in item:
                    is_part_of = False
                    break
            if is_part_of:
                longest_item.remove(l_item)
                longest_item.append(item)

        # no similar item in longest_item
        is_different_to_each_l_item = True
        for l_item in longest_item:

            is_different = False
            for t in item:
                if t not in l_item:
                    is_different = True
                    break
            if not is_different:
                is_different_to_each_l_item = False
        if is_different_to_each_l_item:
            longest_item.append(item)
            
    return longest_item
                
def get_cmp_inst(block):
    for x in list(Heads(block.startEA, block.endEA)):
        mnem = print_insn_mnem(x)
        if "cmp" in mnem.lower():
            size = get_item_size(x)
            #print GetDisasm(x)

            j_mnem = print_insn_mnem(x+size).lower()
            if j_mnem.startswith("j"):
                j_inst = GetDisasm(x+size)
                #print j_inst
                if j_mnem in ["jbe", "jna", "jle", "jng", "ja", "jnbe", "jg", "jnle"]:
                    j_op = 2 #j_op = ">&<="
                elif j_mnem in ["jae", "jnb", "jge", "jnl", "jb", "jnae", "jl", "jnge"]:
                    j_op = 1 #j_op = "<&>="
                elif j_mnem in [ "jz", "je", "jnz", "jne"]:
                    j_op = 0 # j_op = "==&<>"

                cmp_asm = GetDisasm(x)
                if ";" in cmp_asm:
                    cmp_asm = cmp_asm.split(";")[-2]
                for s in cmp_asm.split(" ")[::-1]:
                    if len(s) > 0:
                        cmp_op2 = s
                        break
                #print cmp_op2, type(cmp_op2), cmp_op2[-1]=="h"

                if cmp_op2[-1] == "h":
                    try:
                        cmp_op2_value = int(cmp_op2[:-1], 16)
                        return (cmp_op2_value, j_op)
                    except:
                        return None
                
                try:
                    cmp_op2_value = int(cmp_op2)
                    return (cmp_op2_value, j_op)
                except Exception, e:
                    #print e
                    try:
                        cmp_op2_value = int(cmp_op2, 16)
                        return (cmp_op2_value, j_op)
                    except Exception, e:
                        #print e
                        return None
    return None

def init_block_cmp_inst(flow):
    global block_cmp_inst
    block_cmp_inst = {}
    for block in flow:
        cmp_inst = get_cmp_inst(block)
        # remove (0, 0)
        if cmp_inst == (0, 0):
            cmp_inst = None
        block_cmp_inst[block.startEA] = cmp_inst


def analyze_block(block_sea, block_preds):
    global analyzed_block_result
    cur_items = []
    # entry_block
    if len(block_preds[block_sea]) == 0 and block_cmp_inst[block_sea]:
        cur_items.append([block_cmp_inst[block_sea]])

    for prev in block_preds[block_sea]:
        if len(analyzed_block_result[prev]) == 0:
            if block_cmp_inst[block_sea]:
                cur_items.append([block_cmp_inst[block_sea]])
            continue

        for item in analyzed_block_result[prev]:
            if block_cmp_inst[block_sea]:
                cur_items.append(item + [block_cmp_inst[block_sea]])
            else:
                cur_items.append(item)

    analyzed_block_result[block_sea] = find_longest_item(cur_items)
    

def visit_prev(block_sea, block_preds, length=1, visited_block=[], count=1):
    # already analyzed
    if block_sea in analyzed_block:
        return count

    # can be analyzed immediately
    prepared_for_analyzed = True
    for prev in block_preds[block_sea]:
        if prev not in analyzed_block:
            prepared_for_analyzed = False
            break
    if prepared_for_analyzed:
        analyze_block(block_sea, block_preds)
        analyzed_block.append(block_sea)
        return count+1

    # some prevs have not analyzed
    for prev in block_preds[block_sea]:
        if prev not in visited_block:
            count = visit_prev(prev, block_preds, length+1, visited_block+[block_sea], count)
        else:
            pass
    analyze_block(block_sea, block_preds)
    analyzed_block.append(block_sea)
    return count+1


def gen_block_prevs(flow, func_sea):
    block_prevs = {}
    count = 0
    for block in flow:
        count += 1
        for succ in block.succs():
            try:
                block_prevs[succ.startEA].append(block.startEA)
            except:
                block_prevs[succ.startEA] = [block.startEA]
    for block in flow:
        try:
            block_prevs[block.startEA]
        except:
            block_prevs[block.startEA] = []
    return block_prevs


# deep traversal
def extract_nested_if_main():
    all_nested_if = []
    min_ea = get_inf_attr(INF_MIN_EA)
    max_ea = get_inf_attr(INF_MAX_EA)
    func_list = list(Functions(min_ea, max_ea))
    i = 0
    for func in func_list:
        i += 1
        #print "\nFunction:", i, hex(func)
        flow = FlowChart(get_func(func))
        init_block_cmp_inst(flow)
        global block_cmp_inst

        return_blocks = []
        for block in flow:
            if sum(1 for _ in block.succs()) == 0:
                return_blocks.append(block)

        block_preds = gen_block_prevs(flow, func)
        global analyzed_block
        analyzed_block = []
        global analyzed_block_result
        analyzed_block_result = {}
        for block in flow:
            analyzed_block_result[block.startEA] = []

        count = 1
        for return_block in return_blocks:
            #print "return block:", hex(return_block.startEA)
            try:
                count = visit_prev(return_block.startEA, block_preds, count=count)
            except Exception, e:
                print "[ERROR] visit_prev:", e

        nested_ifs = []
        for return_block in return_blocks:
            nested_ifs += analyzed_block_result[return_block.startEA]
        if len(nested_ifs):
            all_nested_if.append({"if_else": find_longest_item(nested_ifs), "function": func})

    long_nested_if = []
    for item in all_nested_if:
        if item not in long_nested_if:
            long_nested_if.append(item)

    return long_nested_if
    

def auto_analysis():
    print "extracting hard string ..."
    hard_strings = extract_hard_string_main()
    print "extracting switch case ..."
    switches = extract_switch_case_main()
    print "extracting nested if ..."
    long_nested_if = extract_nested_if_main()
    

idc.Wait()
auto_analysis()
Exit(0)