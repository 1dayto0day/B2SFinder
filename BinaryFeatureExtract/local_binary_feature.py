import os
import subprocess
import json
import time
import datetime
import pefile


# ------------------ Extract Export Info ------------------
def extract_export_info_core(binary_path):
    start_time = datetime.datetime.now()
    print "[" + start_time.strftime("%Y-%m-%d %H:%M:%S") + "] start parsing data"

    try:
        pe = pefile.PE(binary_path)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    except:
        return []

    exports = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print "[DEBUG] This pefile doesn't has a DIRECTORY_ENTRY_EXPORT attribute", binary_path
        return []

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name is None:
            print "[DEBUG] export.name = None (order =", exp.ordinal, ")"
        exports.append((exp.ordinal, str(exp.name)))
    return exports


def is_PE_file(filename):
    if len(filename) > 4 and filename[-4:] in [".exe", ".dll", ".lib"]:
        return True
    return False

def prepare_for_running_ida(binary_path, result_file_names):
    for post in ["id0", "id1", "id2", "nam"]:
        ida_file_path = binary_path[:-3] + post
        if os.path.exists(ida_file_path):
            try:
                os.remove(ida_file_path)
            except:
                pass

    for result_file_name in result_file_names:
        index = binary_path.rfind("\\")
        binary_dir = binary_path[:index]

        for parent, dirnames, filenames in os.walk(binary_dir):
            for filename in filenames:
                if filename.endswith(result_file_name):
                    os.remove(parent + "\\" + filename)

def is_pe32_or_pe64(target_file_path, default_x86=True):
    try:
        cmd = 'Exe64bitDetector -f "' + target_file_path.encode("gb2312") + '"'
    except:
        cmd = 'Exe64bitDetector -f "' + target_file_path.decode("gb2312").encode("gb2312") + '"'
    pfile = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE)
    ret = pfile.stdout.read().split("\n")
    for line in ret:
        if "File Type" not in line:
            continue
        if "64-bit" in line:
            return False, True  # return flag_x86, is_valid
        elif "32-bit" in line:
            return True, True  # return flag_x86, is_valid
    return default_x86, False  # return fake_flag, is_valid

def run_ida_to_autoanalysis(target_file_path, script="ida_autoanalysis_entry.py", ida_version="6.8", default_x86=True):
    flag_x86, is_valid = is_pe32_or_pe64(target_file_path, default_x86=default_x86)

    if ida_version == "7.0":
        ida32_path = "C:\\IDA_Pro_v7.0\\ida.exe"
        ida64_path = "C:\\IDA_Pro_v7.0\\ida64.exe"
    else:
        ida32_path = "C:\\IDA_Pro_v6.8\\idaq.exe"
        ida64_path = "C:\\IDA_Pro_v6.8\\idaq64.exe"
    script_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) + "\\tools\\" + script
    model = 1
    if flag_x86:
        cmd = '"' + ida32_path + '"  -A -OIDAPython:' + str(model) + ';"' + script_path + '" "'
    else:
        cmd = '"' + ida64_path + '"  -A -OIDAPython:' + str(model) + ';"' + script_path + '" "'
    try:
        cmd += target_file_path.encode("gb2312") + '"'
    except:
        cmd += target_file_path.decode("gb2312").encode("gb2312") + '"'
    print cmd
    subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE)
    return is_valid

def wait_for_ida_result(binary_path, result_file_name, time_out=2000):
    index = binary_path.rfind("\\")
    binary_dir = binary_path[:index]
    result_file_path = binary_dir + "\\" + result_file_name
    close_flag_file_path = binary_dir + "\\ida_closed.txt"

    count = 0
    while True:
        try:
            with open(result_file_path, "r") as result_file:
                results = json.load(result_file)
            print ""
            return results, True
        except:
            if count > time_out:
                print ""
                print "[ERROR] cannot open ida within " + str(time_out) + "s"
                return None, False
        print ".",
        time.sleep(1)
        count += 1
        if count % 60 == 0:
            print ""

        if count % 100 == 30:
            try:
                with open(close_flag_file_path, "r") as close_flag:
                    return [], True
            except:
                if not check_if_ida_is_running():
                    print "[ERROR] ida is not running..."
                    return [], False

def check_if_ida_is_running():
    p = os.popen('tasklist')
    ret = p.read()
    ret = ret.split("\n")
    for line in ret:
        # print line
        if "idaq.exe" in line:
            return True
        if "idaq64.exe" in line:
            return True
        if "ida.exe" in line:
            return True
        if "ida64.exe" in line:
            return True
    return False

def clean_ida_temp_files(root_dir):
    print "root_dir:", root_dir
    root_dir = root_dir.decode("utf8")
    for parent, dirnames, filenames in os.walk(root_dir):
        if len(filenames) > 0:
            for filename in filenames:
                if filename[-4:] not in [".dll", ".lib", ".exe"]:
                    try:
                        os.remove(parent + "\\" + filename)
                    except:
                        pass


def clean_sqlite_files():
    sqlite_root = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "tools", "diaphora_custom")
    for parent, dirnames, filenames in os.walk(sqlite_root):
        for filename in filenames:
            if filename.find(".sqlite") != -1:
                try:
                    os.remove(os.path.join(parent, filename))
                except:
                    pass

def extract_binary_feature_via_ida(binary_path, script_name, feature_types, ida_version="6.8"):
    result_file_names = ["ida_closed.txt",  # ida_autoanalysis_entry
                         "hard_strings.json",  # extract_hard_strings.py
                         "nested_if.json", # extract_nested_if.py
                         "switch_case.json"] # extract_switch_case.py

    prepare_for_running_ida(binary_path, result_file_names)

    # run IDA, generating .idb and other analysis result files
    # IDA runs only once
    is_valid_x86 = run_ida_to_autoanalysis(binary_path, script_name, ida_version, default_x86=False)

    ret = {}
    is_valid_result = True
    for feature_type in feature_types:
        if feature_type == "export_func":
            continue
        features, is_valid_result = wait_for_ida_result(binary_path, feature_type+".json", time_out=2000)
        if not is_valid_result:
            break
        ret[feature_type] = features

    if not is_valid_result and not is_valid_x86:
        run_ida_to_autoanalysis(binary_path, script_name, ida_version, default_x86=False)
        for feature_type in feature_types:
            if feature_type == "export_func":
                continue
            features, is_valid = wait_for_ida_result(binary_path, feature_type+".json", time_out=2000)
            if is_valid:
                ret[feature_type] = features

    clean_sqlite_files()
    return ret

def local_binary_feature_extractor(software_dir, feature_types=[]):
    binary_features = {}
    for parent, dirnames, filenames in os.walk(software_dir):
        for filename in filenames:
            filepath = parent + "\\" + filename
            if is_PE_file(filepath):
                binary_feature = {}
                relative_path = filepath[len(software_dir)+1:]

                ret_features = extract_binary_feature_via_ida(filepath, "ida_autoanalysis_70.py", feature_types, "7.0")
                for feature_type in ret_features:
                    binary_feature[feature_type] = ret_features[feature_type]
                if "export_func" in feature_types:
                    exports = extract_export_info_core(filepath)
                    binary_feature['export_func'] = exports

                binary_features[relative_path] = binary_feature

    clean_ida_temp_files(software_dir)
    return binary_features



if __name__ == "__main__":
    feature_types = ["export", "string", "switch_case", "nested_if", "const_enum_array", "const_num_array", "string_array"]
    binary_features = local_binary_feature_extractor(software_dir, feature_types)




