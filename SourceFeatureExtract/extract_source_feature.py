# -*- coding: utf-8 -*-
import clang
#import ipdb
from clang.cindex import Config
from clang.cindex import Cursor
from clang.cindex import Index
from clang.cindex import CursorKind
from clang.cindex import TypeKind
#from clang.cindex import CompileCommand
from clang.cindex import TokenKind
from  exceptions import Exception
from copy import deepcopy
from backports import lzma
import os
import re
import commands
import subprocess
import hashlib
import threading
import json
import tarfile
import shutil
import parser

import __init__
from CommonManager import cassandra_manager, download_swift, zipfile
from src_proj_preprocessor import *

global global_file_feature
global_file_feature = { 'strings': [], 'func_names': [], 'string_arrays': [], 'switch_cases': [], 'nested_ifs': [],
                        'ori_const_num_arrays': [], 'const_num_array_typedefs': {}, 'const_num_arrays': [], 
                        'const_enum_arrays': [], 'ori_const_enum_arrays': [], 'const_enum_typedefs': {},
                        'errors': set()}

type_dict_32 = {'byte': 2, 'char': 2, 'int': 8, 'short': 4, 'long': 8, 'unsigned int': 8,
                'unsigned short': 4, 'unsigned long': 8, 'long long': 16, 'bool': 2,
                'unsigned char': 2, 'float': 8, 'double': 16, '__int8': 2, '__int16': 4, '__int32': 8, '__int64': 16,
                'long double': 16, 'wchar_t': 4}
global analyzed_header
analyzed_header = []


def clean_global_file_feature():
    global global_file_feature
    global_file_feature = { 'strings': [], 'func_names': [], 'string_arrays': [], 'switch_cases': [], 'nested_ifs': [],
                            'ori_const_num_arrays': [], 'const_num_array_typedefs': {}, 'const_num_arrays': [], 
                            'const_enum_arrays': [], 'ori_const_enum_arrays': [], 'const_enum_typedefs': {},
                            'errors': set()}


def sync_configure_path(libclangPath):
    mutex2 = threading.Lock()
    if Config.loaded==False:
        mutex2.acquire()
        if Config.loaded==False:
            Config.set_library_file(libclangPath)
        mutex2.release()


def construct_AST(file_path, compile_options=[]):
    index = Index.create()
    tu = index.parse(file_path, compile_options)
    return tu.cursor


def extract_hard_coded_strings(cursor):
    global global_file_feature
    for token in cursor.get_tokens():
        if token.kind.name == 'LITERAL':
            if token.spelling.endswith('\"') and len(token.spelling) > 2:
                if token.spelling[0] == '"' and token.spelling[-1] == '"':
                    global_file_feature['strings'].append(token.spelling[1:-1])
                elif token.spelling[0] == 'L"' and token.spelling[-1] == '"':
                    global_file_feature['strings'].append(token.spelling[2:-1])


def get_include_list(cursor):
    includes = cursor.translation_unit.get_includes()
    include_list = []
    if includes:
        for item in includes:
            if item.__dict__['include']:
                include_list.append(item.__dict__['include'].name)
    return include_list


def get_abs_filepath(path, base_path):
    if path[0] == "/":
        new_path = os.path.abspath(path) 
    else:
        new_path = os.path.abspath(os.path.join(base_path, path))
    return new_path


def extract_func_names_core(cursor, project_root, base_path):
    global global_file_feature
    for cur in cursor.get_children():
        if cur.kind == CursorKind.FUNCTION_DECL or cur.kind == CursorKind.CXX_METHOD:
            if len(cur.spelling) and cur.is_definition() and project_root in get_abs_filepath(cur.location.file.name, base_path) and not cur.spelling.startswith("operator"):
                global_file_feature["func_names"].append(cur.spelling)
        elif cur.kind == CursorKind.CLASS_DECL or cur.kind == CursorKind.CLASS_TEMPLATE:
            for sub_cur in cur.get_children():
                if sub_cur.kind == CursorKind.FUNCTION_DECL or sub_cur.kind == CursorKind.CXX_METHOD:
                    if len(sub_cur.spelling) and sub_cur.is_definition() and project_root in get_abs_filepath(cur.location.file.name, base_path) and not sub_cur.spelling.startswith("operator"):
                        global_file_feature["func_names"].append(sub_cur.spelling)
        elif cur.kind == CursorKind.NAMESPACE:
            extract_func_names_core(cur, project_root, base_path)


def iter_cursor_content(cur):
    cursor_content=""
    for token in cur.get_tokens():
        if token.kind != TokenKind.COMMENT:
            str_token = token.spelling+" "
            cursor_content = cursor_content+str_token
    return cursor_content


def analyze_INIT_LIST_EXPR(cursor):
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            is_const_num_array = analyze_INIT_LIST_EXPR(cur_sub)
            if not is_const_num_array:
                return False
        if cur_sub.kind not in [CursorKind.INTEGER_LITERAL, CursorKind.UNEXPOSED_EXPR, CursorKind.INIT_LIST_EXPR, CursorKind.BINARY_OPERATOR, CursorKind.UNARY_OPERATOR, CursorKind.COMPOUND_ASSIGNMENT_OPERATOR]:
            return False
        if cur_sub.kind == CursorKind.UNEXPOSED_EXPR:
            for cur_subsub in cur_sub.get_children():
                if cur_subsub.kind not in [CursorKind.INTEGER_LITERAL, CursorKind.UNARY_OPERATOR, CursorKind.COMPOUND_ASSIGNMENT_OPERATOR]:
                    return False
    return True


def get_array_value(cursor, large_list=False):
    cursor_content = ""
    if not large_list:
        for token in cursor.get_tokens():
            if token.cursor.kind == CursorKind.INTEGER_LITERAL or token.cursor.kind == CursorKind.UNARY_OPERATOR:
                str_token = token.spelling+""
                cursor_content=cursor_content+str_token
            elif token.cursor.kind == CursorKind.INVALID_FILE:
                print "[ERROR] CursorKind.INVALID_FILE in get_array_value"
                break
    else:
        value_str = iter_cursor_content(cursor)
        cursor_content = value_str.replace(",", " ").replace("{", " ").replace("}", " ")
    return cursor_content


def convert_str_to_int(value_str):
    if 'h' in value_str or 'H' in value_str:
        value_str = value_str.replace('h', ' ').replace('H', ' ')
        return int(value_str, 16)
    if 'u' in value_str or 'U' in value_str or 'l' in value_str or 'L' in value_str:
        value_str = value_str.replace('u', ' ').replace('U', ' ').replace('l', ' ').replace('L', ' ')
    try:
        return int(value_str)
    except:
        try:
            return int(value_str, 16)
        except:
            print "[ERROR] cannot convert str to int:", value_str
            return None


def get_const_num_arr_value(cursor,num_array, large_list=False):
    children_count = sum([1 for _ in cursor.get_children()])
    for cur in cursor.get_children():
        if cur.kind == CursorKind.INTEGER_LITERAL or cur.kind == CursorKind.UNARY_OPERATOR:
            value_str=get_array_value(cur, large_list)
            if value_str == "":
                return None
            value = convert_str_to_int(value_str)
            num_array.append(value)
        else:
            num_array = get_const_num_arr_value(cur,num_array, large_list) 
            if num_array is None:
                return None
    return num_array


def get_const_number_array_value(cursor):
    num_arr=[]
    num_array=[]
    get_num_arr=[]
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            list_length = sum([1 for _ in cur_sub.get_children()])
            if list_length > 1000:
                num_arr = get_const_num_arr_value(cur_sub,get_num_arr, True)
            else:
                num_arr = get_const_num_arr_value(cur_sub,get_num_arr, False)
    return num_arr


def extract_const_number_array(root_cursor):
    global global_file_feature
    for cur in root_cursor.get_children():
        if cur.kind == CursorKind.TYPEDEF_DECL:
             global_file_feature['const_num_array_typedefs'][cur.spelling]=cur.underlying_typedef_type.spelling

    # global const number array
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.VAR_DECL and cursor.spelling != "":
            addit=False
            for cur_sub in cursor.get_children():
                if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
                    addit = analyze_INIT_LIST_EXPR(cur_sub)
                    if cursor.type.get_array_element_type().spelling == "":
                        addit = False
            if addit:
                num_array=get_const_number_array_value(cursor)
                if num_array and None not in num_array:
                    global_file_feature['ori_const_num_arrays'].append({"array": num_array, "type": cursor.type.element_type.spelling, "var_name": cursor.spelling})

    # local but static
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.FUNCTION_DECL or cursor.kind == CursorKind.CXX_METHOD:
            find_INIT_LIST_EXPR_from_function(cursor)
        elif cursor.kind == CursorKind.CLASS_DECL or cursor.kind == CursorKind.CLASS_TEMPLATE:
            for sub_cur in cur.get_children():
                if sub_cur.kind == CursorKind.FUNCTION_DECL or sub_cur.kind == CursorKind.CXX_METHOD:
                    find_INIT_LIST_EXPR_from_function(sub_cur)


def find_INIT_LIST_EXPR_from_function(func_cursor):
    for cursor in func_cursor.get_children():
        if cursor.kind == CursorKind.COMPOUND_STMT:
            for cur_sub in cursor.get_children():
                find_INIT_LIST_EXPR(cur_sub)


def find_INIT_LIST_EXPR(cursor):
    for cur_sub in cursor.get_children():
        if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
            addit=False
            addit = analyze_INIT_LIST_EXPR(cur_sub)
            
            if cursor.type.get_array_element_type().spelling == "":
                addit = False

            if addit:
                num_array=get_const_number_array_value(cursor)
                if num_array and None not in num_array:
                    global_file_feature['ori_const_num_arrays'].append({"array": num_array, "type": cursor.type.element_type.spelling, "var_name": cursor.spelling})
        else:
            find_INIT_LIST_EXPR(cur_sub)


def extract_string_array(cursor):
    global global_file_feature
    if cursor.kind == CursorKind.VAR_DECL:
        string_array_list=[]
        addit=False
        for cur_sub in cursor.get_children():
            if cur_sub.kind == CursorKind.INIT_LIST_EXPR:
                for cur_subsub in cur_sub.get_children():
                    if cur_subsub.kind == CursorKind.STRING_LITERAL:
                        string_array_list.append(cur_subsub.spelling)
                        addit = True
        if addit:
            global_file_feature['string_arrays'].append({"array": string_array_list, "var_name": cursor.spelling})

    for kid_cursor in cursor.get_children():
        extract_string_array(kid_cursor)


def extract_const_enum_array(root_cursor):
    global global_file_feature
    for cursor in root_cursor.get_children():
        if cursor.kind == CursorKind.TYPEDEF_DECL:
            global_file_feature['const_enum_typedefs'][cursor.spelling]=cursor.underlying_typedef_type.spelling
            
        if cursor.kind == CursorKind.VAR_DECL:
            for cur in cursor.get_children():
                if cur.kind == CursorKind.INIT_LIST_EXPR:
                    item_list = []
                    for member in cur.get_children():
                        if member.kind == CursorKind.DECL_REF_EXPR:
                            ref = member.referenced
                            if ref.kind == CursorKind.ENUM_CONSTANT_DECL:
                                item_list.append(ref.enum_value)
                    if len(item_list)>0:
                        global_file_feature['ori_const_enum_arrays'].append({"array": item_list, "type": cursor.type.element_type.spelling, "var_name": cursor.spelling})


def extract_switch_cases(file_name, project_root, options):
    if file_name.endswith(".h") or file_name.endswith(".hpp"):
        return

    cmd = clang_path + ' -emit-llvm -c '
    if options:
        for option in options:
            cmd += ' ' + option + ' '
    cmd += '"' + file_name + '" -o "' + file_name + '.bc" '
    (status, output) = commands.getstatusoutput(cmd)
    if status:
        global_file_feature["errors"].add("switch_case")
        return False, output

    cmd = py_cwd+'/switch-case-extractor "' + file_name + '.bc" --'
    (status, result) = commands.getstatusoutput(cmd)
    if status:
        global_file_feature["errors"].add("switch_case")
        return False, result 

    cmd = 'rm ' + file_name + '.bc'
    (status, output) = commands.getstatusoutput(cmd)
    
    if len(result):
        get_switch_info(result, file_name, project_root)
    return True, None

def get_case_pool(cur_cases):
    case_value = []
    for atarget in cur_cases:
        if atarget != ['default']:
            acase_value = []
            for acase in atarget:
                acase_value.append(int(acase))
                acase_value.sort()
            case_value.append(acase_value)
    case_value.sort()
    case_pool = [len(atarget) for atarget in case_value]
    return case_value, case_pool


def get_switch_info(content, file_name, project_root):
    global global_file_feature
    function_name = None
    ncases = None
    targets = None
    cur_cases = None
    for line in content.split('\n'):
        if line.startswith("Function:"):
            # push previous one
            if function_name:
                switkh = {}
                switkh["function_name"] = function_name
                switkh["ncases"] = ncases
                switkh["targets"] = targets
                switkh["case_value"], switkh["case_pool"] = get_case_pool(cur_cases)
                global_file_feature['switch_cases'].append(switkh)
            function_name = line[10:]
            ncases = 0
            targets = None
            cur_cases = []
        elif line.startswith("ncases:"):
            targets = int(line[8:])
        elif line.startswith("Cur_Case:"):
            index = line[10:].find("Target:")
            cur_case_line = line[10: 9 + index]
            cur_case = cur_case_line.split()
            ncases += len(cur_case)
            cur_cases.append(cur_case)
    # push last one
    if function_name:
        switkh = {}
        switkh["function_name"] = function_name
        switkh["ncases"] = ncases
        switkh["targets"] = targets
        switkh["case_value"], switkh["case_pool"] = get_case_pool(cur_cases)
        global_file_feature['switch_cases'].append(switkh)


def extract_nested_if(file_name, options):
    if file_name.endswith(".h") or file_name.endswith(".hpp"):
        return

    cmd = clang_path + ' -emit-llvm -c '
    if options:
        for option in options:
            cmd += ' ' + option + ' '
    cmd += '"' + file_name + '" -o "' + file_name + '.bc" '
    (status, output) = commands.getstatusoutput(cmd)
    if status:
        global_file_feature["errors"].add("nested_if")
        return False, output

    cmd = py_cwd+'/if-else-extractor "' + file_name + '.bc" --'
    (status, result) = commands.getstatusoutput(cmd)
    if status:
        global_file_feature["errors"].add("nested_if")
        return False, result

    cmd = 'rm ' + file_name + '.bc'
    (status, output) = commands.getstatusoutput(cmd)
    
    if len(result):
        get_nested_if_info(result)
    return True, None


def extract_exports(dynamic_filepath):
    (status, output) = commands.getstatusoutput('objdump -tT "' + dynamic_filepath + '"')
    analyze_flag = False
    exports = []
    for line in output.split("\n"):
        if "SYMBOL TABLE:" in line or "DYNAMIC SYMBOL TABLE:" in line:
            analyze_flag = True
        if analyze_flag:
            if ".hidden" in line:
                continue
            tokens = line.split(" ")
            if len(tokens) > 2 and tokens[1] == "g":
                exports.append(tokens[-1])
    return exports

def get_nested_if_info(content):
    global global_file_feature
    function_name = None
    cmp_info = None
    a_if = {'value': [], 'function_name': None}
    function_name_now = None
    for line in content.split('\n'):
        if line.startswith("Function:"):
            function_name = line[10:]
            a_if['function_name'] = function_name
        elif line.startswith("CMP_INFOS:"):
            cmp_info = line[11:]
            cmp_num = cmp_info.split(',')[0]
            cmp_mark = cmp_info.split(',')[1][1:]
            if function_name_now != function_name:
                if len(a_if['value']) > 2:
                    global_file_feature['nested_ifs'].append(a_if)
                a_if = {'value': [], 'function_name': None}
                function_name_now = function_name
                if cmp_info != "0, 0" and cmp_info not in a_if['value'] and cmp_num != "" and cmp_num != "-1":
                    a_if['value'].append(cmp_info)
            elif cmp_info != "0, 0" and cmp_info not in a_if['value'] and cmp_num != "" and cmp_num != "-1":
                a_if['value'].append(cmp_info)


def strip_static_const(type):
    type_list = type.split(' ')
    type_l = []
    for i in type_list:
        if i == 'const':
            continue
        if i == 'static':
            continue
        type_l.append(i)
    new_type = ' '.join(type_l)
    return new_type


def generate_const_enum_array():
    global global_file_feature
    for item in global_file_feature['ori_const_enum_arrays']:
        long_type = strip_static_const(item['type'])
        if long_type in global_file_feature['const_enum_typedefs']:
            num_type = global_file_feature['const_enum_typedefs'][long_type]
        elif long_type in type_dict_32:
            num_type = long_type
        else:
            num_type = None
        global_file_feature['const_enum_arrays'].append({'array': item['array'], 'element_type': num_type, 'var_name': item['var_name']})


def generate_const_number_array():
    global global_file_feature
    for item in global_file_feature['ori_const_num_arrays']:
        long_type = strip_static_const(item['type'])
        if long_type in global_file_feature['const_num_array_typedefs']:
            num_type = global_file_feature['const_num_array_typedefs'][long_type]
        elif long_type in type_dict_32:
            num_type = long_type
        else:
            num_type = None
        global_file_feature['const_num_arrays'].append({'array': item['array'], 'element_type': num_type, 'var_name': item['var_name']})


def analysefile(file_path, file_compile_dir, compile_root, project_root, compile_options=[], feature_types=[]):
    global global_file_feature
    print "---------------------------------------------------------"
    print "[+] analyze file:", file_path, feature_types, compile_options
    pyscript_dir = os.getcwd() # save the working path ,after ananlyse we restore it
    clean_global_file_feature()

    # get compilation base path
    base_path = file_compile_dir
    if base_path is not None and compile_options is not None:
        for compile_option in compile_options:
            if compile_option.startswith("-I"):
                short_option = compile_option[2:].replace("/", " ").replace("\\", " ").replace(".", "").replace(" ", "")
                if not len(short_option):
                    continue
                if compile_root and os.path.exists(os.path.join(compile_root, compile_option[2:])):
                    base_path = compile_root
                    break
                elif project_root and os.path.exists(os.path.join(project_root, compile_option[2:])): 
                    base_path = project_root
                    break
                elif os.path.exists(os.path.join(os.path.dirname(file_path), compile_option[2:])):
                    base_path = os.path.dirname(file_path)
                    break

    if base_path is None:
        base_path = compile_root
    if base_path is None:
        base_path = os.path.dirname(file_path)
    os.chdir(base_path)

    # test preprocessor
    pp_file_path = ".".join(file_path.split(".")[:-1]) + "_pp." +  file_path.split(".")[-1]
    pp_cmd = clang_path + " -E " + " ".join(compile_options) + ' "' + file_path + '" > "' + pp_file_path + '"'
    try:
        (status, output) = commands.getstatusoutput(pp_cmd)
    except:
        status = -1
    if status and status != -1:
        pp_file_path = file_path
        global_file_feature["errors"].add("preprocess")
    else:
        with open(pp_file_path, "r") as f:
            content = f.read().split("\n")
        new_content = []
        for line in content:
            if len(line) and line[0] != "#":
                new_content.append(line)
        with open(pp_file_path, "w") as f:
            f.write("\n".join(new_content))

    # non-preprocessor, to get include infos
    try:
        tmp_cursor = construct_AST(file_path, compile_options)
    except Exception, e:
        print "[construct_AST ERROR]", e
        return None
    include_list = get_include_list(tmp_cursor)

    # analyze source file via libclang
    try:
        cursor = construct_AST(pp_file_path, compile_options)
    except Exception, e:
        print "[construct_AST ERROR]", e
        return None
    
    for feature in feature_types:
        print "[-] extract " + feature, ":", 
        try:
            if feature == "strings":
                extract_hard_coded_strings(cursor)
            elif feature == "func_names":
                global analyzed_header
                analyzed_header = []
                extract_func_names_core(tmp_cursor, project_root, base_path)
            elif feature == "const_num_arrays":
                extract_const_number_array(cursor)
                generate_const_number_array()
            elif feature == "string_arrays":
                extract_string_array(cursor)
            elif feature == "const_enum_arrays":
                extract_const_enum_array(cursor)
                generate_const_enum_array()
            elif feature == "switch_cases":
                status, msg = extract_switch_cases(file_path, project_root, compile_options)
                if not status and base_path == compile_root:
                    os.chdir(os.path.dirname(file_path))
                    status, msg = extract_switch_cases(file_path, project_root, compile_options)
                elif not status and base_path == os.path.dirname(file_path):
                    os.chdir(compile_root)
                    status, msg = extract_switch_cases(file_path, project_root, compile_options)
                if not status:
                    print "[ERROR]", msg,
                
            elif feature == "nested_ifs":
                status, msg = extract_nested_if(file_path, compile_options)
                if not status and base_path == compile_root:
                    os.chdir(os.path.dirname(file_path))
                    status, msg = extract_nested_if(file_path, compile_options)
                if not status:
                    print "[ERROR]", msg,
        except Exception, e:
            print "[ERROR]", e

    os.chdir(pyscript_dir)
    return global_file_feature
    

def get_source_file_of_dir(project_root):
    c_files = []
    for parent, dirnames, filenames in os.walk(project_root):
        for filename in filenames:
            if filename.endswith(".c") or filename.endswith(".cpp") or filename.endswith(".cc") or filename.endswith(".cxx"):
                c_files.append(os.path.join(parent, filename))
    return c_files

def get_header_file_of_dir(project_root):
    h_files = []
    for parent, dirnames, filenames in os.walk(project_root):
        for filename in filenames:
            if filename.endswith(".h") or filename.endswith(".hpp"):
                h_files.append(os.path.join(parent, filename))
    return h_files

def analyze_project(project_root, feature_types):
    pre = Preprocessor(project_root)
    command_dict, need_to_compile_files, ori_bin_src_map, status, files_compile_dir = pre.get_make_info()

    # delete duplicate dynamic
    bin_src_map = {}
    for item in ori_bin_src_map:
        if not len(ori_bin_src_map[item]):
            continue
        if not len(bin_src_map):
            bin_src_map[item] = ori_bin_src_map[item]
            continue
        flag = True
        for bs_item in bin_src_map:
            if len(bin_src_map[bs_item]) != len(ori_bin_src_map[item]):
                continue
            u_len = len(set(bin_src_map[bs_item]) & set(ori_bin_src_map[item]))
            if u_len == len(bin_src_map[bs_item]):
                flag = False
                break
        if flag:
            bin_src_map[item] = ori_bin_src_map[item]

    if not len(need_to_compile_files) or not status:
        need_to_compile_files = get_source_file_of_dir(project_root)
        if not len(need_to_compile_files):  # all files are header file
            need_to_compile_files = get_header_file_of_dir(project_root)
        bin_src_map = {"fake_dynamic": need_to_compile_files}

    print "\nstart analyze files..."
    proj_features = {}
    for filepath in need_to_compile_files:
        filename = os.path.basename(filepath)

        file_compile_dir = None
        if filepath in files_compile_dir:
            file_compile_dir = files_compile_dir[filepath]
            
        compile_options = command_dict.get(filepath[len(project_root)+1:])
        if compile_options is None:
            compile_options = command_dict.get("-" + filename)
        if compile_options is None:
            compile_options = ["-I."]
        needed_feature_types = []
        for ft in feature_types:
            if ft not in ["exports"]:
                needed_feature_types.append(ft)
        global_file_feature = analysefile(filepath, file_compile_dir, pre.compile_root, pre.path, compile_options, needed_feature_types)
        proj_features[filename] = global_file_feature
    return proj_features


py_cwd = os.getcwd()
clang_path = '/root/llvm/build/bin/clang-3.7'
libclang_path = '/root/llvm/build/lib/libclang.so.3.7'
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument("-pj_root", help="input root directory of an OSS project", dest="pj_root")
    args=parser.parse_args()

    feature_types = ["strings", "exports", "func_names", "const_num_arrays", "const_enum_arrays", "string_arrays", "switch_cases", "nested_ifs"]
    sync_configure_path(libclang_path)  
    proj_features = analyze_project(args.pj_root, feature_types) 
    

    
