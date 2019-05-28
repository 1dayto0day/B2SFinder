import os
import re
import commands
import copy

global parsed_cmds
parsed_cmds = {}
global needed_so
needed_so = []
global cur_dir
cur_dir = ''
global files_compile_dir
files_compile_dir = {}


def remove_useless_tokens(ori_short_cmd):
    real_tokens = []
    part = " ".join(ori_short_cmd)
    i = 0
    while i in range(len(ori_short_cmd)):
        if "=\\\"" in ori_short_cmd[i]:
            index1 = ori_short_cmd[i].find("\\\"")
            if "\\\"" in ori_short_cmd[i][index1 + 1:]:
                real_tokens.append(ori_short_cmd[i].replace("\\\"", ""))
                i += 1
                continue
            for j in range(i + 1, len(ori_short_cmd)):
                if "\\\"" in ori_short_cmd[j]:
                    real_tokens.append(" ".join(ori_short_cmd[i:j + 1]).replace("\\\"", ""))
                    i = j + 1
                    break
        else:
            real_tokens.append(ori_short_cmd[i])
            i += 1

    ori_short_cmd = real_tokens
    real_tokens = []
    i = 0
    while i in range(len(ori_short_cmd)):
        if ori_short_cmd[i][0] == '"':
            for j in range(i, len(ori_short_cmd)):
                if j == i and len(ori_short_cmd[j]) == 1:
                    continue
                if ori_short_cmd[j][-1] == '"':
                    real_tokens.append(" ".join(ori_short_cmd[i:j + 1])[1:-1])
                    i = j + 1
                    break
        else:
            real_tokens.append(ori_short_cmd[i])
            i += 1

    ori_short_cmd = real_tokens
    real_tokens = []
    i = 0
    while i in range(len(ori_short_cmd)):
        if ori_short_cmd[i][-1] == '=':
            real_tokens.append(" ".join(ori_short_cmd[i:i + 2]))
            i += 2
        else:
            real_tokens.append(ori_short_cmd[i])
            i += 1

    short_cmd = []
    i = 0
    while i in range(len(real_tokens)):
        if not len(real_tokens[i]):
            i += 1
            continue
        if len(real_tokens[i]) >= 2 and real_tokens[i][0] == '"':
            real_tokens[i] = real_tokens[i][1:-1]

        if real_tokens[i].startswith("-I") or real_tokens[i].startswith("-l") \
                or real_tokens[i].startswith("-L") or real_tokens[i].startswith("-O") or real_tokens[i].startswith("-f") \
                or real_tokens[i].startswith("-g") or real_tokens[i].startswith("-p") or real_tokens[i].startswith(
                "-std"):
            i += 1
            continue
        elif real_tokens[i].startswith("-W") and not real_tokens[i].startswith("-Wl"):
            i += 1
            continue
        elif real_tokens[i].startswith("-D") and not real_tokens[i].startswith("-DLT_OBJDIR="):
            i += 1
            continue
        elif real_tokens[i] in ['-rpath', '-version-info', '-export-symbols', '-MF', '-MT', '-version-number']:
            i += 2
            continue
        short_cmd.append(real_tokens[i])
        i += 1
    return short_cmd


def is_make_cmd(short_cmd):
    for word in re.split('[/\\\\]', short_cmd[0]):
        if word in ["cc", "gcc", "g++", "c++"]:
            return True
    return False


def is_ar_cmd(short_cmd):
    for word in re.split('[/\\\\]', short_cmd[0]):
        if word in ["ar"]:
            return True
    return False


def is_cd_cmd(short_cmd):
    if short_cmd[0] == "cd":
        return True
    return False


def is_libtool_cmd(short_cmd):
    for word in re.split('[/\\\\]', short_cmd[0]):
        if word in ["libtool"]:
            return True
    return False


def is_ld_cmd(short_cmd):
    if short_cmd[0] == "ld":
        return True
    return False


def is_make_entering_directory(short_cmd):
    if short_cmd[0].startswith("make") and "Entering directory" in " ".join(short_cmd):
        return True
    return False


def init_short_cmd(part):
    short_cmd = []
    for token in part.split(" "):
        if len(token):
            short_cmd.append(token)
    if len(short_cmd):
        for word in re.split('[/\\\\]', short_cmd[0]):
            if word in ["bash", "if", "then"]:
                short_cmd = short_cmd[1:]
    return short_cmd


def get_abs_filepath(path, source_root=None, is_libtool_link=False, is_cd=False, is_libtool=False):
    if path[0] == "/":
        new_path = os.path.abspath(path)
    else:
        new_path = os.path.abspath(os.path.join(cur_dir, path))

    if is_libtool:
        if new_path[-3:] in [".la", ".lo"]:
            new_path = new_path[:-2] + new_path[-1]
    new_path = new_path.replace("/.libs/.libs", "/.libs")
    if not os.path.exists(new_path):
        if is_cd:
            return None
        if not source_root:
            return new_path
        tmp_name = try_to_find_file(os.path.basename(new_path), source_root)
        if tmp_name:
            new_path = tmp_name
    return new_path


def is_c_file(filename):
    if (filename.endswith(".c") or filename.endswith(".cpp") \
                or filename.endswith(".cc")) or filename.endswith(".cxx"):
        return True
    return False


def parse_ld_cmd(short_cmd, source_root):
    global parsed_cmds
    global needed_so
    global files_compile_dir

    parsed_cmd = {'output': '', 'dependency': [], "is_elf": True, 'needed': True}
    i = 1
    while i in range(1, len(short_cmd)):
        if short_cmd[i] == "-T":
            i += 1
        elif short_cmd[i] == "-o":
            parsed_cmd['output'] = get_abs_filepath(short_cmd[i + 1], source_root)
            i += 1
        elif short_cmd[i][0] != '-':
            parsed_cmd['dependency'].append(get_abs_filepath(short_cmd[i], source_root))
            files_compile_dir[get_abs_filepath(short_cmd[i], source_root)] = cur_dir
        i += 1
    parsed_cmds[parsed_cmd['output']] = {'dependency': parsed_cmd['dependency'], 'is_elf': parsed_cmd['is_elf'],
                                         'is_analyzed': not parsed_cmd['is_elf']}
    needed_so.append(parsed_cmd['output'])


def parse_make_cmd(short_cmd, source_root, is_libtool_link=False, is_libtool=True):
    global parsed_cmds
    global needed_so
    global files_compile_dir
    short_cmd = remove_useless_tokens(short_cmd)

    parsed_cmd = {'output': '', 'dependency': [], "is_elf": None, 'needed': False}
    i = 1
    while i in range(1, len(short_cmd)):
        if short_cmd[i] == "-o":
            parsed_cmd['output'] = get_abs_filepath(short_cmd[i + 1], source_root, is_libtool_link=is_libtool_link,
                                                    is_libtool=is_libtool)
            i += 1
        elif short_cmd[i] == "-c" or short_cmd[i] == "-S" or short_cmd[i] == "-E":
            parsed_cmd['is_elf'] = False
        elif short_cmd[i].startswith("-Wl"):
            parsed_cmd['is_elf'] = True
            if '-soname' in short_cmd[i]:
                parsed_cmd['needed'] = True
        elif short_cmd[i][0] != '-':
            if short_cmd[i].endswith(".s"):
                temp_filepaths = {short_cmd[i][:-1] + "c",
                                  short_cmd[i][:-1] + "cpp",
                                  short_cmd[i][:-1] + "cc",
                                  short_cmd[i][:-1] + "cxx"}
                for t_file in temp_filepaths:
                    if os.path.exists(get_abs_filepath(t_file, source_root)):
                        parsed_cmd['dependency'].append(get_abs_filepath(t_file, source_root))
                        break
            if not short_cmd[i].endswith(".s") and not short_cmd[i].endswith(".asm"):
                depend = get_abs_filepath(short_cmd[i], source_root, is_libtool=is_libtool)
                parsed_cmd['dependency'].append(depend)
                files_compile_dir[depend] = cur_dir
        i += 1

    # remove dir in parsed_cmd['dependency']
    for item in parsed_cmd['dependency']:
        if os.path.isdir(item):
            parsed_cmd['dependency'].remove(item)

    if parsed_cmd['output'] == '' and len(parsed_cmd['dependency']):
        parsed_cmd['output'] = get_abs_filepath(os.path.basename(parsed_cmd['dependency'][0]).split(".")[0] + ".o",
                                                source_root)
    if not len(parsed_cmd['dependency']):
        return None

    if is_libtool_link and parsed_cmd['output'][-2:] == ".a":
        parsed_cmd['needed'] = True

    if not parsed_cmd['is_elf']:
        if is_c_file(parsed_cmd['dependency'][0]) and len(parsed_cmd['dependency']) == 1:
            parsed_cmd['is_elf'] = False
        else:
            parsed_cmd['is_elf'] = True

    if parsed_cmd['needed']:
        needed_so.append(parsed_cmd['output'])
    parsed_cmds[parsed_cmd['output']] = {'dependency': parsed_cmd['dependency'], 'is_elf': parsed_cmd['is_elf'],
                                         'is_analyzed': not parsed_cmd['is_elf']}
    return parsed_cmd['output']


def split_cmd_from_line(line):
    if "`" in line and "Entering directory" not in line:
        index1 = line.find("`")
        index2 = line[index1 + 1:].find("`")
        line = line[:index1] + line[index1 + index2 + 2:]

    content = []
    line_split = line.split("&&")
    for ls in line_split:
        for cmd in ls.split(";"):
            if len(cmd):
                content.append(cmd)
    line_split = content
    content = []
    for ls in line_split:
        for cmd in ls.split("|"):
            if len(cmd):
                cmd = cmd.split("1>&2")[0]
                cmd = cmd.split(" >")[0]
                content.append(cmd)

    return content


def try_to_find_file(target_name, soft_dir):
    count = 0
    tmp_path = None
    for parent, dirnames, filenames in os.walk(soft_dir):
        for filename in filenames:
            if filename == target_name:
                if count:
                    return None
                count += 1
                tmp_path = os.path.join(parent, filename)
    if count:
        return tmp_path
    return None


def get_dependency_from_make(line, source_root, is_make_n=False):
    global parsed_cmds
    global needed_so
    global cur_dir
    content = split_cmd_from_line(line)

    for part in content:
        if "`" in part and "Entering directory" not in part:
            continue

        short_cmd = init_short_cmd(part)
        if not len(short_cmd):
            continue

        if is_make_cmd(short_cmd):
            parse_make_cmd(short_cmd, source_root)

        elif is_ar_cmd(short_cmd):
            if short_cmd[2][0] == '"' and short_cmd[2][-1] != '"':
                continue
            output_name = get_abs_filepath(short_cmd[2], source_root)
            if 'r' in short_cmd[1]:
                if output_name not in parsed_cmds.keys():
                    parsed_cmds[output_name] = {'dependency': [], 'is_elf': True, 'is_analyzed': False}
            elif 'x' in short_cmd[1]:
                continue
            else:
                parsed_cmds[output_name] = {'dependency': [], 'is_elf': True, 'is_analyzed': False}
            for i in range(3, len(short_cmd)):
                abs_filepath = get_abs_filepath(short_cmd[i], source_root)
                if abs_filepath not in parsed_cmds[output_name]['dependency']:
                    parsed_cmds[output_name]['dependency'].append(abs_filepath)
            if output_name not in needed_so:
                needed_so.append(output_name)

        elif is_cd_cmd(short_cmd):
            if not is_make_n:
                abs_dir = get_abs_filepath(short_cmd[1], source_root, is_cd=True)
            if abs_dir:
                cur_dir = abs_dir

        elif is_libtool_cmd(short_cmd):
            for i in range(len(short_cmd)):
                if short_cmd[i] == "--mode=compile":
                    for j in range(i + 1, len(short_cmd)):
                        if is_make_cmd(short_cmd[j:]):
                            parse_make_cmd(short_cmd[j:], source_root, is_libtool=True)
                            break
                elif short_cmd[i] == "--mode=link":
                    for j in range(i + 1, len(short_cmd)):
                        if is_make_cmd(short_cmd[j:]):
                            cur_elf = parse_make_cmd(short_cmd[j:], source_root, is_libtool_link=True)
                            break

        elif is_make_entering_directory(short_cmd):
            cur_dir = short_cmd[3][1:-1]

        elif is_ld_cmd(short_cmd):
            parse_ld_cmd(short_cmd, source_root)


def try_to_fix_elf_lacking(filepath):
    global parsed_cmds
    if filepath.endswith(".o") or filepath.endswith(".lo"):
        c_filepaths = [".".join(filepath.split(".")[:-1]) + ".c",
                       ".".join(filepath.split(".")[:-1]) + ".cpp",
                       ".".join(filepath.split(".")[:-1]) + ".cc",
                       ".".join(filepath.split(".")[:-1]) + ".cxx"]

        if "/.libs/" in filepath:
            c_filepaths.append((".".join(filepath.split(".")[:-1]) + ".c").replace("/.libs/", "/"))
            c_filepaths.append((".".join(filepath.split(".")[:-1]) + ".cpp").replace("/.libs/", "/"))
            c_filepaths.append((".".join(filepath.split(".")[:-1]) + ".cc").replace("/.libs/", "/"))
            c_filepaths.append((".".join(filepath.split(".")[:-1]) + ".cxx").replace("/.libs/", "/"))

        fix_c_name = None
        count = 0
        for c_filepath in c_filepaths:
            if os.path.exists(c_filepath):
                parsed_cmds[filepath] = {'dependency': [c_filepath], 'is_elf': False, 'is_analyzed': True}
                return True
            for parent, dirnames, filenames in os.walk(os.path.dirname(c_filepath)):
                if os.path.basename(c_filepath) in filenames:
                    count += 1
                    fix_c_name = os.path.join(parent, os.path.basename(c_filepath))
        if count == 1:
            parsed_cmds[filepath] = {'dependency': [fix_c_name], 'is_elf': False, 'is_analyzed': True}
            return True
    if filepath.endswith(".so"):
        for item in parsed_cmds:
            if os.path.basename(item).startswith(os.path.basename(filepath)):
                parsed_cmds[filepath] = copy.deepcopy(parsed_cmds[item])
                parsed_cmds[filepath]['is_analyzed'] = False
                return True
    return False


def get_elf_dependencies():
    global parsed_cmds
    elf_dependencies = {}
    pre_sum = None
    pre_parsed_cmds_count = len(parsed_cmds)
    while (sum([not parsed_cmds[item]['is_analyzed'] for item in parsed_cmds])):
        if pre_sum and pre_sum == sum(
                [not parsed_cmds[item]['is_analyzed'] for item in parsed_cmds]) and pre_parsed_cmds_count == len(
                parsed_cmds):
            break
        pre_sum = sum([not parsed_cmds[item]['is_analyzed'] for item in parsed_cmds])

        i = 0
        while i in range(len(parsed_cmds)):
            item = parsed_cmds.keys()[i]
            if parsed_cmds[item]['is_analyzed']:
                i += 1
                continue

            can_analyse = True
            for depend in parsed_cmds[item]['dependency']:
                if depend not in parsed_cmds.keys():
                    state = try_to_fix_elf_lacking(depend)
                    if state:
                        can_analyse = False
                    break
                if not parsed_cmds[depend]['is_analyzed']:
                    can_analyse = False
                    i += 1
                    break

            if can_analyse:
                elf_dependencies[item] = []
                for depend in parsed_cmds[item]['dependency']:
                    if depend not in parsed_cmds.keys():
                        continue
                    if parsed_cmds[depend]['is_elf'] and depend in elf_dependencies:
                        elf_dependencies[item] += elf_dependencies[depend]
                    else:
                        elf_dependencies[item] += (parsed_cmds[depend]['dependency'])
                elf_dependencies[item] = list(set(elf_dependencies[item]))
                if not len(elf_dependencies[item]):
                    parsed_cmds[item]['is_analyzed'] = True
                elif is_c_file(elf_dependencies[item][0]):
                    parsed_cmds[item]['is_analyzed'] = True
                i += 1
    return elf_dependencies


def is_line_ends_with_slash(line):
    line_tokens = line.split(" ")
    for i in range(len(line_tokens) - 1, -1, -1):
        if not len(line_tokens[i]):
            continue
        if line_tokens[i].endswith("\\"):
            return True
        else:
            break
    return False


def merge_split_line(ori_content):
    content = []
    i = 0
    cur_line = ""
    while i in range(len(ori_content)):
        if not is_line_ends_with_slash(ori_content[i]):
            content.append(ori_content[i])
            i += 1
            continue
        j = i + 1
        for j in range(i + 1, len(ori_content)):
            if not is_line_ends_with_slash(ori_content[j]):
                break
        content.append(" ".join(ori_content[i:j + 1]).replace("\\", " "))
        i = j + 1
    return content


def check_needed_so():
    global parsed_cmds
    global needed_so

    if not len(needed_so):
        for item in parsed_cmds:
            if parsed_cmds[item]['is_elf']:
                needed_so.append(item)
    return needed_so


def init_global_vars():
    global parsed_cmds
    parsed_cmds = {}
    global needed_so
    needed_so = []
    global cur_dir
    cur_dir = ''
    global files_compile_dir
    files_compile_dir = {}


def get_need_to_compile_files(info_make_file, source_root, is_make_n=False):
    global cur_dir
    global files_compile_dir
    init_global_vars()
    with open(info_make_file) as f:
        content = f.read().replace("\t", "    ").split("\n")

    content = merge_split_line(content)

    cur_dir = os.path.dirname(info_make_file)

    for line in content:
        if not len(line):
            continue
        if line[0] == "[":
            continue
        if line.startswith("Scanning") or line.startswith("Dependee"):
            continue
        if line[0] == "(" and line[-1] == ")":
            line = line[1:-1]

        get_dependency_from_make(line, source_root, is_make_n=is_make_n)

    elf_dependencies = get_elf_dependencies()
    new_needed_so = check_needed_so()

    need_to_compile_files = []
    bin_src_map = {}
    count = 0
    status = True
    for item in new_needed_so:
        count += 1
        if item not in elf_dependencies:
            status = False
            continue
        bin_src_map[item] = elf_dependencies[item]
        print "\n[*" + str(count) + "]", item + ":", len(elf_dependencies[item])
        print "\n".join(elf_dependencies[item])
        for f in elf_dependencies[item]:
            if f not in need_to_compile_files:
                need_to_compile_files.append(f)

    if not len(new_needed_so) and len(elf_dependencies):
        for item in elf_dependencies:
            need_to_compile_files += elf_dependencies[item]
        need_to_compile_files = list(set(need_to_compile_files))
        bin_src_map = elf_dependencies
    return bin_src_map, need_to_compile_files, status, files_compile_dir

	