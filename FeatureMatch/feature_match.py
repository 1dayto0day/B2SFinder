from feature_preprocessor import *
from BinaryFeatureExtract import local_binary_feature
from CommonManager import cassandra_manager
import os, copy, re, binascii, json, math, argparse, shutil, datetime

global num_arr_statistic
global enum_arr_statistic

num_arr_statistic = dict()
enum_arr_statistic = dict()


def islist(value):
    return isinstance(value, list)

def is_web_name(line):
    p = re.compile('((https)?|ftp|file)(://)?(www.)[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]')
    return (p.search(line))

def is_func_name(line):
    return bool(re.search('[a-z]', line)) & bool((re.search('[A-Z]', line)))

def has_special_char(line):
    return bool(re.search(r'\W', line, re.U)) | bool(re.search('_', line))

def hasNumbers(line):
    return bool(re.search(r'\d', line))

def get_word_key_value(word, library_name):
    weight = 0
    if word.isalpha():
        weight = 0.1
    if word.find(library_name) != -1:
        weight = weight + 5
    if word.islower():
        weight = weight + 0.1
    if word[1:].isupper():
        weight = weight + 0.25
    if hasNumbers(word):
        weight = weight + 0.25
    if has_special_char(word):
        weight = weight + 0.5
    if is_func_name(word[1:]):
        weight = weight + 0.5
    if is_web_name(word):
        weight = weight + 1
    return weight


def key_value(line, library_name):
    weight = 0
    if line.find(' ') != -1:
        for string in line.split(' '):
            weight = weight + get_word_key_value(string, library_name)
        weight = weight * (1 + len(line.split(' ')) * 0.1)
    else:
        weight = get_word_key_value(line, library_name)
    return weight


def get_export_func(source_funcname, dll_exportfunc, flag):
    func_found = {}
    dll_dict = {}
    source_dict = {}
    dll_func = []
    source_func = []
    if flag == 0:
        for f in dll_exportfunc:
            dll_func.append(f.split('(')[0])
        for f in source_funcname:
            source_func.append(f.split('(')[0])
        func_set = set(dll_func)
        source_set = set(source_func)
        func_found = func_set & source_set
    else:
        for f in dll_exportfunc:
            dll_dict[f[0:f.find('(')]] = list()
        for f in dll_exportfunc:
            l1 = []
            l = f[f.find('(') + 1:f.find(')')].split(',')
            for line in l:
                if line == '':
                    l1.append('void')
                else:
                    if line == 'const char *' or line == 'char const *':
                        line = 'const char *'
                        l1.append(line)
                    else:
                        reference_list = []
                        for reference in line.split(' '):
                            if reference == 'class' or reference == 'struct' or reference == 'enum':
                                continue
                            else:
                                reference_list.append(reference.strip(' '))
                        reference_list.sort()
                        l1.append(' '.join(reference_list))
            dll_dict[f[0:f.find('(')]].append(l1)
        for f in source_funcname:
            source_dict[f[0:f.find('(')]] = list()

        for f in source_funcname:
            l1 = []
            l = f[f.find('(') + 1:f.find(')')].split(',')
            for line in l:
                if line == '':
                    l1.append('void')
                else:
                    if line.find('const char *') != -1 or line.find('char const *') != -1:
                        l1.append('const char *')
                    else:
                        reference_list = []
                        for i in range(0, len(line.split(' ')) - 1):
                            reference_list.append(line.split(' ')[i])
                        if line.split(' ')[-1].find('*') != -1:
                            reference_list.append('*')
                        if len(line.split(' ')) == 1:
                            reference_list.append(line.strip())
                        reference_list.sort()
                        l1.append((' ').join(reference_list))
            source_dict[f[0:f.find('(')]].append(l1)

        dll_set = set(dll_dict.keys())
        source_set = set(source_dict.keys())
        same_set = dll_set & source_set

        for s in same_set:
            dll_list = list()
            if islist(dll_dict[s]):
                dll_list = dll_dict[s]
            else:
                dll_list.append(dll_dict[s])

            source_list = []
            if islist(source_dict[s]):
                source_list = source_dict[s]
            else:
                source_list.append(source_dict[s])
            for item in dll_list:
                if item in source_list:
                    func_found[s] = item
    return func_found


def get_hash_dict(source_str_dict):
    dict_str = {}
    for f in source_str_dict:
        dict_str[len(f)] = {}
    for f in source_str_dict:
        dict_str[len(f)][hash(f)] = {"string": f, "score": source_str_dict[f]}
    return dict_str


def get_string(source_str_dict, dll_str_list, library_name, use_score=True, record_details=False):
    source_dict_str = get_hash_dict(source_str_dict)
    weights = 0
    count = 0
    match_fts = []
    for l in dll_str_list:
        if len(l) not in source_dict_str.keys():
            continue
        if hash(l) not in source_dict_str[len(l)].keys():
            continue
        matched_str = source_dict_str[len(l)][hash(l)]['string']
        if record_details:
            match_fts.append(matched_str)
        score = source_dict_str[len(l)][hash(l)]['score']
        if use_score:
            count += 1 / float(score)
            weights += key_value(matched_str, library_name) * (1 / float(score))
        else:
            count += 1
            weights = weights + key_value(matched_str, library_name)

    source_total_weights = 0
    source_total_count = 0
    for l in source_str_dict:
        if use_score:
            source_total_count += 1 / float(source_str_dict[l])
            source_total_weights += key_value(l, library_name) * (1 / float(source_str_dict[l]))
        else:
            source_total_count += 1
            source_total_weights += key_value(l, library_name)
    return count, source_total_count, weights, source_total_weights, match_fts


def compare_strarr2dll(source_strings_dict, dll_string, use_score=True, record_details=False):
    ret_matched_fts = []
    new_string_arrays_dict = []
    for string_array in source_strings_dict:
        if len(string_array['value']) < 3:
            continue
        new_string_array = []
        for item in string_array['value']:
            if item.startswith('"') and item.endswith('"'):
                new_string_array.append(item[1:-1])
            elif item.startswith('L"') and item.endswith('"'):
                new_string_array.append(item[2:-1])
            elif item.startswith('"') and not item.endswith('"'):
                new_string_array.append(item[1:])
            else:
                new_string_array.append(item)
        new_string_arrays_dict.append({"value": new_string_array, "score": string_array["score"]})
    source_strings_dict = new_string_arrays_dict

    if not len(source_strings_dict):
        return 0, 0, 0, 0, ret_matched_fts

    total_strings_count = 0
    total_chars_count = 0
    matched_arrays_count = 0
    matched_strings_count = 0
    matched_chars_count = 0

    for array_item in source_strings_dict:
        string_array = array_item["value"]
        matched = set(string_array) & set(dll_string)
        if use_score:
            if float(len(matched))/len(string_array) >= 0.8:
                if record_details:
                    ret_matched_fts.append(string_array)
                print "\t\tmatch:", string_array, array_item["score"]
                matched_arrays_count += 1 * (1/float(array_item["score"]))
            total_strings_count += len(string_array) * (1/float(array_item["score"]))
            matched_strings_count += len(matched) * (1/float(array_item["score"]))
            for item in string_array:
                total_chars_count += len(item) * (1/float(array_item["score"]))
            for item in matched:
                matched_chars_count += len(item) * (1/float(array_item["score"]))
        else:
            if float(len(matched))/len(string_array) >= 0.8:
                if record_details:
                    ret_matched_fts.append(string_array)
                matched_arrays_count += 1
            total_strings_count += len(string_array)
            matched_strings_count += len(matched)
            for item in string_array:
                total_chars_count += len(item)
            for item in matched:
                matched_chars_count += len(item)
    return float(matched_arrays_count)/len(source_strings_dict), float(matched_strings_count)/total_strings_count, float(matched_chars_count)/total_chars_count, matched_strings_count, ret_matched_fts


type_dict_64 = {'byte': 2, 'char': 2, 'int': 8, 'short': 4, 'long': 16, 'unsigned int': 8,
                'unsigned short': 4, 'unsigned long': 16, 'long long': 16, 'bool': 2,
                'unsigned char': 2, 'float': 8, 'double': 16, '__int8': 2, '__int16': 4, '__int32': 8, '__int64': 16,
                'long double': 16, 'wchar_t': 4}


type_dict_32 = {'byte': 2, 'char': 2, 'int': 8, 'short': 4, 'long': 8, 'unsigned int': 8,
                'unsigned short': 4, 'unsigned long': 8, 'long long': 16, 'bool': 2,
                'unsigned char': 2, 'float': 8, 'double': 16, '__int8': 2, '__int16': 4, '__int32': 8, '__int64': 16,
                'long double': 16, 'wchar_t': 4}


def get_little_endian(num, length):
    if length % 2 == 0:
        length = length
    else:
        length = length + 1
    num = '0' * (length - len(num)) + num
    hex_search_str = []
    count = len(num) - 2
    for i in range(0, len(num) / 2):
        hex_search_str.append(num[count])
        hex_search_str.append(num[count + 1])
        count = count - 2
    hex_search_str = ''.join(hex_search_str)
    return hex_search_str


def cut_L_tail(hex_str):
    if hex_str[-1] == "L":
        return hex_str[:-1]
    return hex_str

def get_pe32_str(num_type, value):
    length = type_dict_32[num_type]
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = cut_L_tail(hex(value)[2:])
            hex_search_str = get_little_endian(hex_num, length)
        return hex_search_str
    except ValueError:
        return get_little_endian(cut_L_tail(hex(value)[2:]), length)


def get_pe64_str(num_type, value):
    length = type_dict_64[num_type]
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = hex(value)[2:]
            hex_search_str = get_little_endian(cut_L_tail(hex_num), length)
        return hex_search_str
    except ValueError:
        return get_little_endian(cut_L_tail(hex(value)[2:]), length)


def get_pe_str_value(value, length):
    try:
        if value < 0:
            if length == 2:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xff)[2:]), 2)
            elif length == 4:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffff)[2:]), 4)
            elif length == 8:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffff)[2:]), 8)
            else:
                hex_search_str = get_little_endian(cut_L_tail(hex(value & 0xffffffffffffffff)[2:]), 16)
        else:
            hex_num = hex(value)[2:]
            hex_search_str = get_little_endian(cut_L_tail(hex_num), length)
        return hex_search_str
    except ValueError:
        hex_search_str = get_little_endian(cut_L_tail(hex(value)[2:]), length)
        return hex_search_str


def get_hex_search_list(const_num_arrays, lib_name, bin_file):
    flag_x86 = local_binary_feature.is_pe32_or_pe64(bin_file)

    # num_array contains unrepeated array items
    num_array = dict()
    for arr in const_num_arrays:
        if len(arr["feature_value"]) < 3:
            continue
        arr_tur = tuple(arr["feature_value"])

        all_0_flag = True
        for item in arr_tur:
            if item != 0:
                all_0_flag = False
                break
        if all_0_flag:
            continue

        # ignore the case that two arrays has same value but different element type
        if not num_array.has_key(arr_tur):
            num_array[arr_tur] = {'count': 1, 'type': arr["element_type"], 'array_name': [arr["var_name"] + '_' + lib_name], 'hex_list': [], 'score': arr['score']}
        else:
            num_array[arr_tur]['count'] += 1
            num_array[arr_tur]['array_name'].append(arr["var_name"] + '_' + lib_name)
            continue
        num_type = num_array[arr_tur]['type']

        if num_type and num_type in type_dict_32:
            hex_search_str = ''
            for array_item in arr_tur:
                if flag_x86:
                    hex_search_str += get_pe32_str(num_type, array_item)
                else:
                    hex_search_str += get_pe64_str(num_type, array_item)
            num_array[arr_tur]['hex_list'].append(hex_search_str)
        else:
            max_item = max(arr_tur)
            waiting_potential_len = [2, 4, 8, 16]
            potential_len = []
            for plen in waiting_potential_len:
                if 16 ** plen <= max_item:
                    continue
                potential_len.append(plen)

            for length in potential_len:
                hex_search_str = ''
                for array_item in arr_tur:
                    cur_num = array_item
                    hex_search_str += get_pe_str_value(cur_num, length)
                num_array[arr_tur]['hex_list'].append(hex_search_str)

    hex_search_list = []
    hex_set = []
    for arr_tur in num_array:
        hex_set += num_array[arr_tur]['hex_list']
    hex_set = list(set(hex_set))
    for hex_item1 in hex_set:
        flag = True
        for hex_item2 in hex_set:
            if len(hex_item1) < len(hex_item2) and hex_item1 in hex_item2:
                flag = False
                break
        if flag:
            hex_search_list.append(hex_item1)

    new_num_array = {}
    for arr_tur in num_array:
        pre_hex_list = num_array[arr_tur]['hex_list']
        new_hex_list = []
        for item in pre_hex_list:
            if item in hex_search_list:
                new_hex_list.append(item)
        if len(new_hex_list):
            new_num_array[arr_tur] =  num_array[arr_tur]
            new_num_array[arr_tur]['hex_list'] = new_hex_list
    return hex_search_list, new_num_array


def get_score(score=1, count=1, length=1,use_score=True):
    if not use_score:
        return count
    return (count * (math.log(length, 2)+ 1)) / float(score)


def compare_arr2dll(hex_file, unrepeat_num_arr, use_score=True, record_details=False):
    success_match = 0
    success_match_num_len = 0
    total_count = 0
    total_num_len = 0
    ret_matched_fts = []
    for array_item in unrepeat_num_arr:
        for hex_item in unrepeat_num_arr[array_item]['hex_list']:
            pos = hex_file.find(hex_item)
            if pos != -1:
                if record_details:
                    ret_matched_fts.append(array_item)
                print "\t\tmatch:", hex_item, array_item, unrepeat_num_arr[array_item]['array_name'], hex(pos),unrepeat_num_arr[array_item]['count'], unrepeat_num_arr[array_item]['score'], get_score(score=unrepeat_num_arr[array_item]['score'], count=unrepeat_num_arr[array_item]['count'], length=len(array_item), use_score=use_score)
                success_match +=  get_score(score=unrepeat_num_arr[array_item]['score'], count=unrepeat_num_arr[array_item]['count'], length=len(array_item), use_score=use_score)
                success_match_num_len += len(array_item) * get_score(score=unrepeat_num_arr[array_item]['score'], count=unrepeat_num_arr[array_item]['count'], use_score=use_score)
                break
        total_count +=  get_score(score=unrepeat_num_arr[array_item]['score'], count=unrepeat_num_arr[array_item]['count'], length=len(array_item), use_score=use_score)
        total_num_len += len(array_item) * get_score(score=unrepeat_num_arr[array_item]['score'], count=unrepeat_num_arr[array_item]['count'], use_score=use_score)
    print "\t\t >> success_match:", success_match, "total_count:", total_count, "success_match_num_len:", success_match_num_len, "total_num_len:", total_num_len
    return success_match, total_count, ret_matched_fts


def match_case_pool(sitem, bitem):
    s_case_pool = sitem['case_pool']
    b_case_pool = bitem['case_pool']
    if len(s_case_pool) + 1 == len(b_case_pool):
        for i in range(len(b_case_pool) - 1, -1, -1):
            if s_case_pool == b_case_pool[:i] + b_case_pool[i + 1:]:
                return True
    return False


def completely_match_case_value(s_case_value, b_case_value):
    if len(s_case_value) + 1 == len(b_case_value):
        for i in range(len(b_case_value) - 1, -1, -1):
            if s_case_value == b_case_value[:i] + b_case_value[i + 1:]:
                return True
    return False


def match_case_value_from_0(s_case_value, b_case_value):
    # Is binary case value starts from 0 ?
    flag = False
    for atarget in b_case_value:
        if 0 in atarget:
            flag = True
            break
    if not flag:
        return False

    # Is source case value starts from not-0 ?
    flag = False
    for atarget in s_case_value:
        if 0 in atarget:
            flag = True
            break
    if flag:
        return False

    # find base value of source case value
    base = s_case_value[0][0]
    for atarget in s_case_value:
        for acase in atarget:
            if acase < base:
                base = acase

    new_s_case_value = []
    for atarget in s_case_value:
        new_atarget = []
        for acase in atarget:
            new_atarget.append(acase - base)
        new_s_case_value.append(new_atarget)

    return completely_match_case_value(new_s_case_value, b_case_value)


def match_case_value(sitem, bitem):
    b_case_value = bitem['case_value']
    s_case_value = sitem['case_value']
    # 1) completely matched
    if completely_match_case_value(s_case_value, b_case_value):
        return True
    # 2) binary case values start from 0, but source does not
    if match_case_value_from_0(s_case_value, b_case_value):
        return True
    return False


def is_special_switch(switch_item, is_src):
    if is_src and switch_item['targets'] < 4:  # too short
        return False
    if not is_src and switch_item['targets'] < 3:  # too short
        return False
    if switch_item['ncases'] - switch_item['targets'] > 1:
        return True
    if switch_item['case_value'][-1][0] - switch_item['case_value'][0][0] > len(switch_item['case_value']) + 3:
        return True
    return False


def match_switch_case(binary_switch_cases, source_switch_cases):
    count = 0
    all_branch_count = 0
    matched_branch_count = 0
    all_case_count = 0
    matched_case_count = 0
    valid_src_count = 0
    matched_switch_cases = []

    for sitem in source_switch_cases:
        if is_special_switch(sitem, True):
            valid_src_count += 1
            all_branch_count += sitem['targets']
            all_case_count += sitem['ncases']
            for bitem in binary_switch_cases:
                if is_special_switch(sitem, False):  # filter of special switch/case
                    if match_case_pool(sitem, bitem):
                        if match_case_value(sitem, bitem):
                            count += 1
                            matched_branch_count += sitem['targets']
                            matched_case_count += sum([item for item in sitem['case_pool']])
                            matched_switch_cases.append(sitem)
                            break

    if valid_src_count and count:
        print "\t\t >> count percent: %.2f%%" % ((float(count) / valid_src_count) * 100)
        print "\t\t >> matched_branch_count: %.2f%% (%d/%d)" % (float(matched_branch_count) / all_branch_count * 100, matched_branch_count, all_branch_count),
        print "  matched_case_count: %.2f%% (%d/%d)" % (float(matched_case_count) / all_case_count * 100, matched_case_count, all_case_count)

    if valid_src_count < 5:  # too few switch/case features
        return False, count, matched_switch_cases
    if count > 2 and (float(count) / valid_src_count) * 100 >= 50:
        return True, count, matched_switch_cases
    if count > 5 and (float(count) / valid_src_count) * 100 >= 20:
        return True, count, matched_switch_cases
    return False, count, matched_switch_cases


def match_if_else(binary_if_else, source_if_else):
    Match_count = 0
    Fully_match_count = 0
    minLength = len(source_if_else)
    matched_nested_if = []

    if minLength < 3:
        return False, 0, []

    tmp_binary_if_else = copy.deepcopy(binary_if_else)
    for sitem in source_if_else:
        part_match_max = None
        part_match_count = 0
        for bitem in tmp_binary_if_else:
            if sitem == bitem:  #fully match
                Fully_match_count += 1
                part_match_max = bitem
                part_match_count = len(sitem)
                matched_nested_if.append(sitem)
                break
            else:
                set1 = set(sitem)
                set2 = set(bitem)
                count = len(set1 & set2)

                l_item = max(float(len(sitem)), float(len(bitem)))
                if count > part_match_count and count / l_item * 100 > 40.00:
                    part_match_count = count
                    part_match_max = bitem

        if part_match_count >= 3:
            Match_count += 1
            matched_nested_if.append(sitem)
            tmp_binary_if_else.remove(part_match_max)

    if Match_count == 0:
        return False, 0, matched_nested_if
    else:
        print "\t\t >> Match: %.2f%%(%d/%d)" % (float(Match_count) / minLength * 100, Match_count, minLength)
        print "\t\t >> Fully Match: %.2f%%(%d/%d)" % (float(Fully_match_count) / minLength * 100, Fully_match_count, minLength)

        result2 = float(Match_count) / minLength * 100
        print "\t\t >> Percent: %.2f%%" % (result2)
        if Match_count > 5 and result2 > 75.00:
            return True, result2, matched_nested_if
        else:
            return False, result2, matched_nested_if


def match_string(binary_string, source_string, library_name, use_score=True, record_details=False):
    if len(binary_string) and len(source_string):
        binary_string = [item['string'] for item in binary_string]
        [source_str_dict, binary_string] = pretreat_str(source_string, binary_string)
        if not len(source_str_dict):
            return 0, 0, 0, []
        [string_found_count, source_total_count, weights, source_total_weights, match_fts] = get_string(source_str_dict, binary_string, library_name, use_score=use_score, record_details=record_details)
        if record_details:
            ret_matched_ft = match_fts
        else:
            ret_matched_ft = None
        string_percent = float(string_found_count)/source_total_count
        weight_percent = float(weights)/source_total_weights
        print "\t\t >> string: bin_len:", len(binary_string), "src_len:", len(source_str_dict), "matched_len:", string_found_count
        print "\t\t >> string_percent:", string_percent, "weights:", weights, "weight%:", weight_percent
        return string_percent, weights, weight_percent, ret_matched_ft
    return 0, 0, 0, []


def match_export(bin_export, src_export, record_details=False):
    bin_export = [item[1] for item in bin_export]
    src_export = [item['feature_value'] for item in src_export]
    matched_export = set(bin_export) & set(src_export)
    export_similarity = float(len(matched_export)) / len(src_export)
    if record_details:
        ret_matched_export = matched_export
    else:
        ret_matched_export = None

    if len(src_export) > 5 and export_similarity >= 0.8:
        return True, export_similarity, len(matched_export), ret_matched_export
    elif len(matched_export) > 20:
        return True, export_similarity, len(matched_export), ret_matched_export
    elif len(src_export) > 10 and float(len(matched_export)) / len(bin_export) + export_similarity >= 1.2:
        return True, export_similarity, len(matched_export), ret_matched_export
    elif float(len(matched_export)) / len(bin_export) + export_similarity >= 1.5:
        return True, export_similarity, len(matched_export), ret_matched_export
    else:
        return False, export_similarity, len(matched_export), ret_matched_export


def match_funcname(bin_export, source_func, record_details=False):
    if len(bin_export) > 10 and len(source_func):
        bin_export = [item[1] for item in bin_export]
        source_func = [item['feature_value'] for item in source_func]
        [source_func, bin_export, flag] = pretreat_func(source_func, bin_export)
        func_found = get_export_func(source_func, bin_export, flag)
        if record_details:
            ret_matched_ft = func_found
        else:
            ret_matched_ft = None
        print "\t\t >> func_found:", func_found
        print "\t\t >> funcname: bin_len:", len(bin_export), "src_len:", len(source_func), "matched_len:", len(func_found)
        func_percent = float(len(func_found)) / len(bin_export)
        print "\t\t >> func_percent:", func_percent
        if func_percent > 0.8:
            return True, func_percent, len(func_found), ret_matched_ft
    return False, 0, 0, []


def match_string_array(source_strings, binary_strings, use_score=True, record_details=False):
    binary_strings = [item['string'] for item in binary_strings]
    source_strings_dict = [{"value": item['feature_value'], "score": item["score"]} for item in source_strings]

    matched_array_percent, matched_string_percent, matched_char_percent, matched_strings_count, matched_fts = compare_strarr2dll(source_strings_dict, binary_strings, use_score=use_score, record_details=record_details)
    if record_details:
        ret_matched_ft = matched_fts
    else:
        ret_matched_ft = None
    return matched_array_percent, matched_string_percent, matched_char_percent, matched_strings_count, ret_matched_ft


def match_enum_array(bin_file, const_enum_arrays, lib_name, use_score=True, record_details=False):
    [hex_search_list, unrepeat_num_arr] = get_hex_search_list(const_enum_arrays, lib_name, bin_file)
    if not len(unrepeat_num_arr):
        return 0, 0, 0, []

    with open(bin_file, "rb") as f:
        content = f.read()
        enum_hex_file = binascii.b2a_hex(content)

    success_match, total_count, matched_fts = compare_arr2dll(enum_hex_file, unrepeat_num_arr, use_score=use_score, record_details=False)
    if record_details:
        ret_matched_ft = matched_fts
    else:
        ret_matched_ft = None
    num_match_percent = float(success_match) / total_count
    return num_match_percent, success_match, total_count, ret_matched_ft


def match_const_num_array(bin_file, num_arrays, lib_name, use_score=True, record_details=False):
    [hex_search_list, unrepeat_num_arr] = get_hex_search_list(num_arrays, lib_name, bin_file)
    if not len(unrepeat_num_arr):
        return 0, 0, []

    with open(bin_file, "rb") as f:
        content = f.read()
        num_hex_file = binascii.b2a_hex(content)
    success_match, total_count, matched_fts = compare_arr2dll(num_hex_file, unrepeat_num_arr, use_score=use_score, record_details=False)
    if record_details:
        ret_matched_ft = matched_fts
    else:
        ret_matched_ft = None
    return success_match, total_count, ret_matched_ft


def load_source_feature_from_db(cassandramanager, library_row, cmp_features):
    cassandramanager = cassandra_manager.SourceFeatureCassandraManager()

    if not library_row[0]:
        return {}
    source_features = {}
    dynamic_ids = json.loads(library_row[1])

    for dynamic_id in dynamic_ids:
        dynamic_name = cassandramanager.get_dynamic_name_of_src_dynamics(dynamic_id)
        src_source_ids = json.loads(cassandramanager.get_src_source_ids_from_src_dynamics(dynamic_id))
        source_features[dynamic_name] = {}

        if "export" in cmp_features:
            feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_export(dynamic_id)
            source_features[dynamic_name]['export'] = [{'feature_value': f_row[1], 'feature_len': f_row[2], 'src_dynamic': f_row[3], 'score': 1} for f_row in feature_rows]

        if "string" in cmp_features:
            source_features[dynamic_name]['string'] = []
        if 'export' in cmp_features:
            source_features[dynamic_name]['func_name'] = []
        if 'const_num_array' in cmp_features:
            source_features[dynamic_name]['const_num_array'] = []
        if 'const_enum_array' in cmp_features:
            source_features[dynamic_name]['const_enum_array'] = []
        if 'string_array' in cmp_features:
            source_features[dynamic_name]['string_array'] = []
        if 'switch_case' in cmp_features:
            source_features[dynamic_name]['switch_case'] = []
        if 'nested_if' in cmp_features:
            source_features[dynamic_name]['nested_if'] = []

        for src_source_id in src_source_ids:
            if "string" in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_strings", src_source_id)
                source_features[dynamic_name]['string'] += [{'feature_value': f_row[2], 'feature_len': f_row[3], 'src_file': f_row[1], 'score': 1} for f_row in feature_rows]

            if 'export' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_function_names", src_source_id)
                source_features[dynamic_name]['func_name'] += [{'feature_value': f_row[1], 'feature_len': f_row[2], 'src_file': f_row[3], 'score': 1} for f_row in feature_rows]

            if 'const_num_array' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_const_number_arrays", src_source_id)
                source_features[dynamic_name]['const_num_array'] += [{'feature_value': json.loads(f_row[1]), 'feature_len': f_row[2], 'element_type': f_row[3], 'var_name': f_row[5], 'src_file': f_row[4], 'score': 1} for f_row in feature_rows]

            if 'const_enum_array' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_const_enum_arrays", src_source_id)
                source_features[dynamic_name]['const_enum_array'] += [{'feature_value': json.loads(f_row[1]), 'feature_len': f_row[2], 'element_type': f_row[3], 'var_name': f_row[5], 'src_file': f_row[4], 'score': 1} for f_row in feature_rows]

            if 'string_array' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_string_arrays", src_source_id)
                source_features[dynamic_name]['string_array'] += [{'feature_value': json.loads(f_row[2]), 'feature_len': f_row[3], 'var_name': f_row[4], 'src_file': f_row[1], 'score': 1} for f_row in feature_rows]

            if 'switch_case' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_switch_cases", src_source_id)
                source_features[dynamic_name]['switch_case'] += [{'feature_value': json.loads(f_row[6]), 'feature_len': f_row[7], 'case_pool': json.loads(f_row[1]), 'ncases': f_row[3], 'ntargets': f_row[4], 'function_name': f_row[2], 'src_file': f_row[5], 'score': 1} for f_row in feature_rows]

            if 'nested_if' in cmp_features:
                feature_rows = cassandramanager.get_all_lines_of_src_ori_feature_table("src_ori_feature_if_elses", src_source_id)
                source_features[dynamic_name]['nested_if'] += [{'feature_value': json.loads(f_row[2]), 'feature_len': f_row[3], 'function_name': f_row[1], 'src_file': f_row[4], 'score': 1} for f_row in feature_rows]
    return source_features


# core module of feature match
def library_match(software_dir, binary_features, source_features, library_name, compare_feature_types, use_score=True, record_details=False):
    matched_pairs = []
    feature_match_dict = {}
    all_matched_features = {}
    for dynamic in source_features:
        all_matched_features[dynamic] = {}
        feature_match_dict[dynamic] = {}
        for bin_file in binary_features:
            if record_details:
                all_matched_features[dynamic][bin_file] = {}
            else:
                all_matched_features[dynamic][bin_file] = None
            feature_match_dict[dynamic][bin_file] = {"match": {}, "similarity": {}, "score": {}}
            print "  [-]", library_name, "-", dynamic, " vs. ", bin_file

            if "export" in compare_feature_types:
                print "\tcompare export ...", len(binary_features[bin_file]['export_func']), len(source_features[dynamic]['export'])
                export_matched = False
                if len(source_features[dynamic]['export']):
                    if len(binary_features[bin_file]['export_func']):
                        export_matched, export_similarity, export_score, matched_feature = match_export(binary_features[bin_file]['export_func'], source_features[dynamic]['export'], record_details)
                        print "\t\texport_matched:", export_matched, "export_similarity:", export_similarity
                        if export_matched:
                            matched_pairs.append((bin_file, library_name, dynamic, 'export'))
                        feature_match_dict[dynamic][bin_file]['match']['export'] = export_matched
                        feature_match_dict[dynamic][bin_file]['similarity']['export'] = export_similarity
                        feature_match_dict[dynamic][bin_file]['score']['export'] = export_score
                        if record_details:
                            all_matched_features[dynamic][bin_file]["export"] = list(matched_feature)
                if not len(source_features[dynamic]['export']) or (not export_matched and len(source_features[dynamic]['export']) <= 5):
                    if len(binary_features[bin_file]['export_func']) and len(source_features[dynamic]['func_name']):
                        print "\tcompare function name ...", len(binary_features[bin_file]['export_func']), len(source_features[dynamic]['func_name'])
                        funcname_matched, func_percent, funcname_score, matched_feature = match_funcname(binary_features[bin_file]['export_func'], source_features[dynamic]['func_name'], record_details)
                        print "\t\tfuncname_matched:", funcname_matched
                        if funcname_matched:
                            matched_pairs.append((bin_file, library_name, dynamic, 'function'))
                        feature_match_dict[dynamic][bin_file]['match']['func_name'] = funcname_matched
                        feature_match_dict[dynamic][bin_file]['similarity']['func_name'] = func_percent
                        feature_match_dict[dynamic][bin_file]['score']['func_name'] = funcname_score
                        if record_details:
                            all_matched_features[dynamic][bin_file]["func_name"] = matched_feature


            if "string" in compare_feature_types:
                if len(binary_features[bin_file]['hard_string']) and len(source_features[dynamic]['string']):
                    print "\tcompare string ...", len(binary_features[bin_file]['hard_string']), len(source_features[dynamic]['string'])
                    string_percent, weights, weight_percent, matched_feature = match_string(binary_features[bin_file]['hard_string'], source_features[dynamic]['string'], library_name, use_score=use_score, record_details=record_details)
                    string_matched = (string_percent > 0.5) or (weights > 100 and weight_percent > 0.1)
                    print "\t\tstring_matched:", string_matched
                    if string_matched:
                        matched_pairs.append((bin_file, library_name, dynamic, 'string'))
                    feature_match_dict[dynamic][bin_file]['match']['string'] = string_matched
                    feature_match_dict[dynamic][bin_file]['similarity']['string'] = string_percent
                    feature_match_dict[dynamic][bin_file]['score']['string'] = weights
                    if record_details:
                        all_matched_features[dynamic][bin_file]["string"] = matched_feature

            if "string_array" in compare_feature_types:
                if len(source_features[dynamic]['string_array']):
                    print "\tcompare string array ...", len(source_features[dynamic]['string_array'])
                    matched_array_percent, matched_string_percent, matched_char_percent, matched_strings_count, matched_feature = match_string_array(source_features[dynamic]['string_array'], binary_features[bin_file]['hard_string'], use_score=use_score, record_details=record_details)
                    string_array_matched = False
                    if matched_array_percent >= 0.5:
                        string_array_matched = True
                        matched_pairs.append((bin_file, library_name, dynamic, 'string_array'))
                    elif max(matched_string_percent, matched_char_percent) >= 0.6:
                        string_array_matched = True
                        matched_pairs.append((bin_file, library_name, dynamic, 'string_array'))
                    print "\t\tmatched_array_percent:", matched_array_percent, "string_array_matched:", string_array_matched
                    feature_match_dict[dynamic][bin_file]['match']['string_array'] = (string_array_matched)
                    feature_match_dict[dynamic][bin_file]['similarity']['string_array'] = matched_array_percent
                    feature_match_dict[dynamic][bin_file]['score']['string_array'] = matched_strings_count
                    if record_details:
                        all_matched_features[dynamic][bin_file]["string_array"] = matched_feature

            # enum array
            if "const_enum_array" in compare_feature_types:
                if len(source_features[dynamic]['const_enum_array']):
                    print "\tcompare enum array ...", len(source_features[dynamic]['const_enum_array'])
                    enum_array_similarity, enum_array_score, total_count, matched_feature = match_enum_array(software_dir + "\\" + bin_file, source_features[dynamic]['const_enum_array'], library_name, use_score=use_score, record_details=record_details)
                    const_enum_array_matched = False
                    if (total_count >= 50 and enum_array_similarity >= 0.5) or (total_count < 50 and total_count > 5 and enum_array_similarity >= 0.7):
                        matched_pairs.append((bin_file, library_name, dynamic, 'const_enum_array'))
                        const_enum_array_matched = True
                    print "\t\tenum_array_similarity:", enum_array_similarity, "enum_array_matched:", const_enum_array_matched
                    feature_match_dict[dynamic][bin_file]['match']['const_enum_array'] = (enum_array_similarity >= 0.5)
                    feature_match_dict[dynamic][bin_file]['similarity']['const_enum_array'] = enum_array_similarity
                    feature_match_dict[dynamic][bin_file]['score']['const_enum_array'] = enum_array_score
                    if record_details:
                        all_matched_features[dynamic][bin_file]["const_enum_array"] = matched_feature

            # const number array
            if "const_num_array" in compare_feature_types:
                if len(source_features[dynamic]['const_num_array']):
                    print "\tcompare const number array ...", len(source_features[dynamic]['const_num_array'])
                    success_match, total_count, matched_feature = match_const_num_array(software_dir + "\\" + bin_file, source_features[dynamic]['const_num_array'], library_name, use_score=use_score, record_details=record_details)
                    if total_count:
                        number_array_similarity = float(success_match)/total_count
                        const_num_array_matched = False
                        if (total_count >= 50 and number_array_similarity >= 0.5) or (total_count < 50 and total_count > 5 and number_array_similarity >= 0.7):
                            matched_pairs.append((bin_file, library_name, dynamic, 'const_num_array'))
                            const_num_array_matched = True
                        print "\t\tnumber_array_similarity:", number_array_similarity, "number_array_matched:", const_num_array_matched
                        feature_match_dict[dynamic][bin_file]['match']['const_num_array'] = const_num_array_matched
                        feature_match_dict[dynamic][bin_file]['similarity']['const_num_array'] = number_array_similarity
                        feature_match_dict[dynamic][bin_file]['score']['const_num_array'] = success_match
                        if record_details:
                            all_matched_features[dynamic][bin_file]["const_num_array"] = matched_feature

            # switch/case
            if "switch_case" in compare_feature_types:
                if len(binary_features[bin_file]['switch_case']) and len(source_features[dynamic]['switch_case']):
                    print "\tcompare switch/case ...", len(binary_features[bin_file]['switch_case']), len(source_features[dynamic]['switch_case'])
                    t_bin_switch_cases = pretreat_binary_switch_cases(binary_features[bin_file]['switch_case'])
                    t_src_switch_cases = pretreat_source_switch_cases(source_features[dynamic]['switch_case'])
                    switch_matched, switch_matched_count, matched_switch_cases = match_switch_case(t_bin_switch_cases, t_src_switch_cases)
                    print "\t\tswitch_matched:", switch_matched
                    if switch_matched:
                        matched_pairs.append((bin_file, library_name, dynamic, 'switch_case'))
                    feature_match_dict[dynamic][bin_file]['match']['switch_case'] = switch_matched
                    feature_match_dict[dynamic][bin_file]['similarity']['switch_case'] = switch_matched_count
                    feature_match_dict[dynamic][bin_file]['score']['switch_case'] = switch_matched_count
                    if record_details:
                        all_matched_features[dynamic][bin_file]["switch_case"] = matched_switch_cases

            # if/else
            if "nested_if" in compare_feature_types:
                if len(binary_features[bin_file]['nested_if']) and len(source_features[dynamic]['nested_if']):
                    print "\tcompare if/else ...", len(binary_features[bin_file]['nested_if']), len(source_features[dynamic]['nested_if'])
                    p_bin_if_else = pretreat_binary_if_else(binary_features[bin_file]['nested_if'])
                    p_src_if_else = pretreat_source_if_else(source_features[dynamic]['nested_if'])
                    if_else_matched, if_else_matched_count, matched_nested_if = match_if_else(p_bin_if_else, p_src_if_else)
                    print "\t\tif_else_matched:", if_else_matched
                    if if_else_matched:
                        matched_pairs.append((bin_file, library_name, dynamic, 'nested_if'))
                    feature_match_dict[dynamic][bin_file]['match']['nested_if'] = if_else_matched
                    feature_match_dict[dynamic][bin_file]['similarity']['nested_if'] = if_else_matched_count
                    if record_details:
                        all_matched_features[dynamic][bin_file]["nested_if"] = matched_nested_if

    return matched_pairs, feature_match_dict, all_matched_features


def match_software_with_libraries(cassandramanager, library_infos, soft_dir, binary_features, software_name, compare_feature_types, record_details=False, match_ver=2, trie_type=0):
    if match_ver == 1:
        return match_software_with_libraries_v1(cassandramanager, library_infos, soft_dir, binary_features, software_name, compare_feature_types, record_details)


def match_software_with_libraries_v1(cassandramanager, library_infos, soft_dir, binary_features, software_name, compare_feature_types, record_details=False):
    print "software_name:", software_name
    reused_libraries = []
    unreunsed_libraries = []
    all_matched_pairs = []
    all_feature_match_dict = {}
    if record_details:
        all_soft_matched_features = {}

    for library_row in library_infos:
        library_name_version = library_row[2]
        print "[-] compared with", library_row[2] + "-" + library_row[3]
        source_features = load_source_feature_from_db(cassandramanager, library_row, compare_feature_types)
        if source_features == {}:
            continue

        matched_pairs, feature_match_dict, matched_features = library_match(soft_dir, binary_features, source_features, library_name_version, compare_feature_types, record_details=record_details)
        if record_details:
            all_soft_matched_features[library_name_version] = matched_features

        try:
            all_feature_match_dict[library_name_version] = feature_match_dict
        except:
            all_feature_match_dict = {library_name_version: feature_match_dict}
        all_matched_pairs += matched_pairs

        if len(matched_pairs):
            reused_libraries.append(library_name_version)
            print "Matched", library_name_version, "\n\n"
        else:
            unreunsed_libraries.append(library_name_version)
            print "NotMatched", library_name_version, "\n\n"

    match_result = {"all_feature_match_dict": all_feature_match_dict, "all_matched_pairs": all_matched_pairs}
    print "\n\n[!] Software reuses", reused_libraries, ", doesn't reuse", unreunsed_libraries

    matched_dict = {}
    for bin_file, library_name, dynamic, feature in all_matched_pairs:
        if library_name not in matched_dict.keys():
            matched_dict[library_name] = {}
        if dynamic not in matched_dict[library_name].keys():
            matched_dict[library_name][dynamic] = {}
        if feature not in matched_dict[library_name][dynamic].keys():
            matched_dict[library_name][dynamic][feature] = []
        matched_dict[library_name][dynamic][feature].append(bin_file)

    return match_result, matched_dict


def get_binary_feature_type(compare_feature_types):
    # binary_feature_types = ["hard_string", "switch_case", "nested_if", "export_func"]
    # compare_feature_types = ["string", "switch_case", "nested_if", "const_enum_array", "const_num_array", "string_array"]
    binary_feature_types = []
    if "string" in compare_feature_types:
        binary_feature_types.append("hard_string")
        binary_feature_types.append("export_func")
    if "switch_case" in compare_feature_types:
        binary_feature_types.append("switch_case")
    if "nested_if" in compare_feature_types:
        binary_feature_types.append("nested_if")
    if "string_array" in compare_feature_types:
        binary_feature_types.append("hard_string")
    return list(set(binary_feature_types))


# an entry of benchmark
def compare_local_dll_with_libraries_benchmark(local_dll_path, lib_names, cmp_features, proj_src, unique=False, match_ver=2, trie_type=0):
    if not os.path.exists(local_dll_path):
        print "[ERROR] file not found:", local_dll_path
        return

    local_dll_paths = []
    if os.path.isfile(local_dll_path):
        local_dll_paths.append(local_dll_path)
    if os.path.isdir(local_dll_path):
        for dll_path in os.listdir(local_dll_path):
            if dll_path.endswith(".dll") or dll_path.endswith(".so") or dll_path.endswith(".exe"):
                local_dll_paths.append(local_dll_path + "\\" + dll_path)

    all_match_dict = {}
    for local_dll_path in local_dll_paths:
        print "\n\nlocal_dll_path:", local_dll_path
        if not os.path.exists(local_dll_path.replace(".", "_") + "\\" + os.path.basename(local_dll_path)):
            os.mkdir(local_dll_path.replace(".", "_"))
            shutil.copy(local_dll_path, local_dll_path.replace(".", "_") + "\\" + os.path.basename(local_dll_path))
        dll_dir =  local_dll_path.replace(".", "_")
        local_dll_path = local_dll_path.replace(".", "_") + "\\" + os.path.basename(local_dll_path)

        # get binary_features
        filename = os.path.basename(local_dll_path)
        binary_features = {filename: {}}
        start_time = datetime.datetime.now()
        #ret = extract_binary_feature_via_ida(filepath, "extract_switch_case_70.py", [], "7.0")
        bin_features = get_binary_feature_type(cmp_features)
        print "bin_features:", bin_features
        ret = local_binary_feature.extract_binary_feature_via_ida(local_dll_path, "new_ida_autoanalysis_entry_70.py", bin_features, "7.0")
        for feature_type in ret:
            print feature_type, len(ret[feature_type])
            binary_features[filename][feature_type] = ret[feature_type]
        end_time = datetime.datetime.now()
        delta_time = end_time - start_time
        print "[" + end_time.strftime("%Y-%m-%d %H:%M:%S") + "] parse_data_directories. Time cost:", delta_time.total_seconds(), "s"

        if "export_func" in bin_features:
            exports = local_binary_feature.extract_export_info_core(local_dll_path)
            binary_features[filename]['export_func'] = exports

        cassandramanager = cassandra_manager.CassandraManager()
        # get library_infos
        if match_ver == 1:
            sfcm = cassandra_manager.SourceFeatureCassandraManager()
            if lib_names:
                library_infos = sfcm.get_lines_of_specific_projects(lib_names, proj_src, unique=unique)
            else:
                library_infos = sfcm.get_lines_of_all_projects(proj_src, unique=unique)
        else:
            if lib_names:
                library_infos = cassandramanager.get_lines_of_specific_projects(lib_names, proj_src, unique=unique)
            else:
                library_infos = cassandramanager.get_lines_of_all_projects(proj_src, unique=unique)

        match_result, match_dict = match_software_with_libraries(cassandramanager, library_infos, dll_dir, binary_features, ".".join(os.path.basename(local_dll_path).split(".")[:-1]), cmp_features, match_ver=match_ver, trie_type=trie_type)
        if match_result == {} and match_dict == {}:  # v2
            continue

        all_match_dict[local_dll_path] = match_dict

    return all_match_dict


def benchmark_main():
    parser=argparse.ArgumentParser()

    parser.add_argument("-fs",action="store_const",const=["const_num_array", "string", "func_name", "string_array", "const_enum_array", "switch_case", "nested_if"],help="default choose all software feature",dest="feature_lib")
    parser.add_argument("-f-s",nargs="+",help="choose binary feature",dest="fea_source")
    parser.add_argument("-fb",action="store_const",const=["hard_string", "switch_case", "nested_if", "export_func"],help="default choose all binary features",dest="feature_binary")
    parser.add_argument("-f-b",nargs="+",help="choose software feature",dest="fea_binary")

    # usage example:
    # python featurematch.py -match soft_info.json -srcname expat libcurl zlib
    # python featurematch.py -match soft_info.json -srcjson lib_info.json
    # python featurematch.py -match soft_info.json -cmpfeature switch_case
    parser.add_argument("-match",help="MATCH SOFTWARES with libraries, input address of json stored softwares' info", dest="soft_json")
    parser.add_argument("-src_name" ,help="input the names of LIBRARIES for matching",nargs='+',dest="lib_names", default=[])
    parser.add_argument("-cmp_feature",help="only compare specific features",nargs='+',dest="cmp_features", default=["export", "string", "switch_case", "nested_if", "const_enum_array", "const_num_array", "string_array"])

    parser.add_argument("-unique",action="store_true", help="choose one lib info for each lib names", default=False)
    parser.add_argument("-cmp_only",action="store_true", help="only compare without evaluating accuracy", default=False)
    parser.add_argument("-proj_src", help="ManuallyAdd or Github", nargs='+',dest="proj_src", default=[]) # "ManuallyAdd", "Github"
    parser.add_argument("-match_ver",help="version of matching algorithm", dest="match_ver", default="2")  # "1", "2"

    parser.add_argument("-local_match", help="input file path of a local dll", dest="local_dll")

    parser.add_argument("-trie_type", help='trie number', dest='trie_type', default='0') # '0'(all), '1', '2', '3'

    args=parser.parse_args()

    all_match_dict = compare_local_dll_with_libraries_benchmark(args.local_dll, args.lib_names, args.cmp_features, args.proj_src, args.unique, int(args.match_ver), int(args.trie_type))
    return all_match_dict


if __name__=='__main__':
    all_match_dict = benchmark_main()

    # -local_match <dll_path> -match_ver 1 -src_name <lib_name>
    # -local_match <dll_path> -match_ver 2 -cmp_feature string

    # -local_match <dll_path> -match_ver 2 -cmp_feature const_num_array
    # -local_match <dll_path> -match_ver 2 -cmp_feature const_num_array -trie_type 1


