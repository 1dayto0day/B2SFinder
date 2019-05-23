#-*- coding:utf-8 -*-

def merge_same_case_value(ori_switkhes):
    new_swithkes = []
    for ori_switkh in ori_switkhes:
        has_same = False
        for i in range(len(new_swithkes)):
            if ori_switkh['case_value'] == new_swithkes[i]['case_value']:
                has_same = True
                new_swithkes[i]['functions'].append(ori_switkh['function'])
        if not has_same:
            new_swithke = {"ncases": ori_switkh['ncases'],
                    "targets": ori_switkh['targets'],
                    "case_pool": ori_switkh['case_pool'],
                    'functions': [ori_switkh['function']],
                    "case_value": ori_switkh['case_value']}
            new_swithkes.append(new_swithke)
    return new_swithkes


def pretreat_binary_switch_cases(binary_switch_cases):
    switkhes = []
    #print ">>>>>>>>>>>>>>>>>>>>>>>>"
    #print "[binary_switch_cases]", len(binary_switch_cases), binary_switch_cases[0]
    for item in binary_switch_cases:
        # a switch/case structure
        case_value = []
        for atartget in item['result']['cases']:
            atartget.sort()
            case_value.append(atartget)
        case_value.sort()

        case_pool = [len(atarget) for atarget in case_value]

        switkhes.append({"ncases": item['switch']['ncases'],
                         "targets": item['result']['target_len'],
                         "case_pool": case_pool,
                         "function": item['switch']['function'],
                         "case_value": case_value})

    return merge_same_case_value(switkhes)


def pretreat_source_switch_cases(source_switch_cases):
    switkhes = []
    #print ">>>>>>>>>>>>>>>>>>>>>>>>"
    #print "[source_switch_cases]", len(source_switch_cases)
    for item in source_switch_cases:
        switkhes.append({"ncases": item['ncases'],
                         "targets": item['ntargets'],
                         "case_pool": item['case_pool'],
                         "function": item['function_name'],
                         "case_value": item['feature_value']})

    return merge_same_case_value(switkhes)

def pretreat_binary_if_else(binary_if_elses):
    new_binary_if_elses = []
    for binary_if_else in binary_if_elses:
        for a_nested_if_else in binary_if_else['if_else']:
            if len(a_nested_if_else) < 3:
                continue
            new_tuples = []
            for a_if_else in a_nested_if_else:
                new_tuples.append(tuple(a_if_else))
            if a_nested_if_else not in new_binary_if_elses:
                new_binary_if_elses.append(new_tuples)
    return new_binary_if_elses
    #for bitem in binary_if_else:
        #print bitem

def pretreat_source_if_else(source_if_else):
    p_source_if_else = []
    for sitem in source_if_else:
        if len(sitem) < 3:
            continue
        tmp = []
        for item in list(sitem['feature_value']):
            cmp = []
            num = int(item.split(',')[0])
            mark = int(item.split(',')[1])
            cmp.append(num)
            cmp.append(mark)
            cmp = tuple(cmp)
            tmp.append(cmp)
        #print tmp
        if tmp not in p_source_if_else:
            p_source_if_else.append(tmp)
    return p_source_if_else


def is_str_abort(line):
    #pdb.set_trace()
    if line.find(' ') == -1:
        if line.isalpha():
            if line.istitle() or line.islower():
                return True
            else:
                return False
        else:
            return False
    else:
        return False

def pretreat_str(source_str, binary_str):
    binary_str_list=[]
    source_str_dict={}
    for s in binary_str:
        if s.startswith("?") or s.startswith(".?"):
            continue
        if not is_str_abort(s):
            binary_str_list.append(s)

    for f in source_str:
        ori_str = f['feature_value']
        if ori_str.startswith('"') and ori_str.endswith('"'):
            ori_str = ori_str[1:-1]
        elif ori_str.startswith('L"') and ori_str.endswith('"'):
            ori_str = ori_str[2:-1]
        elif ori_str.startswith('"') and not ori_str.endswith('"'):
            ori_str = ori_str[1:]
        if not is_str_abort(ori_str):
            source_str_dict[ori_str] = f['score']
    return source_str_dict, binary_str_list


def pretreat_func(source_func,dll_func):
    flag=0
    dll_exportfunc=[]
    source_fun=[]
    for func in dll_func:
        if func.find('(') > -1 and func.find(')') > -1:
                flag = 1
        if func.split('::'):
            str1 = func.split('::')[-1]
        else:
            str1 = func
        if str1 not in dll_exportfunc:
            dll_exportfunc.append(str1)

    for func in source_func:
        if func.split('::'):
            str1 = func.split('::')[-1]
        else:
            str1 = func
        if str1 not in source_fun:
            source_fun.append(str1)

    return source_fun,dll_exportfunc,flag

def pretreat_enum_array_type(enum_array_type):
    enum_arr_type=[]
    for i in range(0,len(enum_array_type)):
        enum_arr_type.append(enum_array_type[i][0])
    return enum_arr_type






