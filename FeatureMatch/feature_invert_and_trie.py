__author__ = 'installer'

import __init__
from CommonManager import cassandra_manager, mysql_manager, download_swift, zipfile
from cassandra.query import SimpleStatement
import feature_match
import time, datetime, json, multiprocessing, os, struct, pefile, pickle, math, gc, shutil


# ----------------------  Trie Class  ----------------------

class ArrayTrie:
    def __init__(self):
        self.trie1 = {"nodes": {}, "size": 0}
        self.trie2 = {"nodes": {}, "size": 0}
        self.trie3 = {"nodes": {}, "size": 0}
        self.search_result = None

    def count(self):
        return self.trie1["size"] + self.trie2["size"] + self.trie3["size"]

    def add(self, arr, rel_projs, rel_proj_dyns, rel_proj_vers, rel_proj_count, entropy):
        if len(arr) < 4:
            return
        if entropy < 10 or rel_proj_count >= 10 or is_continuous_array(arr):
            print "remove:", arr
            return
        '''
        try:
            entropy = cal_bit_stream_entropy(BitArray("0x" + binascii.b2a_hex(array_to_hex(arr)[0])).bin)
        except Exception, e:
            print "[ERROR]", e
            print arr
            print array_to_hex(arr)
            entropy = None
        '''
        # first 50 numbers
        if len(arr) > 50:
            arr = arr[:50] + [json.dumps(arr[50:])]
        #print "aft:", arr

        if arr[1] <= 3:
            trie = self.trie1
        elif arr[1] <= 100:
            trie = self.trie2
        else:
            trie = self.trie3
        p = trie
        index = 0
        for num in arr:
            index += 1
            if not num in p["nodes"]:
                #p["nodes"][num] = {"nodes": {}, "attr": {"rel_projs": [], "rel_proj_dyns": {}, "rel_proj_vers": {}}, "passby": {"rel_pjs": [], "rel_vers": []}, "score_map": {}}
                p["nodes"][num] = {"nodes": {}, "attr": {"rel_projs": [], "rel_proj_dyns": {}, "rel_proj_vers": {}}, "score_map": {}}
            p = p["nodes"][num]
            #if index>=4:
            #    p["passby"] = self.__add_passby(p["passby"], rel_projs, rel_proj_dyns, rel_proj_vers)
        p["attr"] = self.__add_attr(p["attr"], rel_projs, rel_proj_dyns, rel_proj_vers)
        if arr != []:
            p["nodes"][''] = ''
            p["pf_hex"] = array_to_hex(arr[:50])
            p["entropy"] = entropy
            trie["size"] += 1

    def __add_passby(self, passby, rel_projs, rel_proj_dyns, rel_proj_vers):
        passby["rel_pjs"] += rel_projs
        for rel_pj in rel_projs:
            for dyn_name in rel_proj_dyns[rel_pj]:
                for rel_ver in rel_proj_vers:
                    full_ver = dyn_name + ":" + rel_ver
                    passby["rel_vers"].append(full_ver)
        passby["rel_vers"] = list(set(passby["rel_vers"]))
        passby["rel_pjs"] = list(set(passby["rel_pjs"]))
        return passby

    def __add_attr(self, attr, rel_projs, rel_proj_dyns, rel_proj_vers):
        attr["rel_projs"] += rel_projs
        attr["rel_projs"] = list(set(attr["rel_projs"]))
        for rel_pj in rel_proj_dyns:
            if rel_pj not in attr["rel_proj_dyns"]:
                attr["rel_proj_dyns"][rel_pj] = []
            attr["rel_proj_dyns"][rel_pj] += json.loads(rel_proj_dyns[rel_pj])
            attr["rel_proj_dyns"][rel_pj] = list(set(attr["rel_proj_dyns"][rel_pj]))
        for dyn_name in rel_proj_vers:
            if dyn_name not in attr["rel_proj_vers"]:
                attr["rel_proj_vers"][dyn_name] = []
            attr["rel_proj_vers"][dyn_name] += json.loads(rel_proj_vers[dyn_name])
            attr["rel_proj_vers"][dyn_name] = list(set(attr["rel_proj_vers"][dyn_name]))
        return attr

    def add_without_zero_prefix(self, arr, rel_projs, rel_proj_dyns, rel_proj_vers, rel_proj_count, entropy):
        i = 0
        while i < len(arr) and not arr[i]:
            i += 1
        arr = arr[i:]
        i = len(arr) - 1
        while i >= 0 and not arr[i]:
            i -= 1
        arr = arr[:i+1]

        self.add(arr, rel_projs, rel_proj_dyns, rel_proj_vers, rel_proj_count, entropy)

    def output(self):
        print "\n\n[Traverse the array trie]"
        self.__print_item(self.trie1, [])
        self.__print_item(self.trie2, [])
        self.__print_item(self.trie3, [])

    def __print_item(self, p, cur_stat):
        if p:
            for num in p["nodes"]:
                if num == '':
                    print cur_stat[:30], len(p["attr"]["rel_projs"])#, len(p["passby"]["rel_pjs"])
                elif type(num) == str:
                    print (cur_stat + json.loads(num))[:30], len(p["nodes"][num]["attr"]["rel_projs"])#, len(p["nodes"][num]["passby"]["rel_pjs"])
                else:
                    self.__print_item(p["nodes"][num], cur_stat + [num])

    def cal_array_score(self):
        self.fcm = cassandra_manager.FeatureCassandraManager()
        self.cm = cassandra_manager.CassandraManager()
        self.distinct_pj_count = reset_controller(self.cm, self.fcm, False)
        self.pj_ver_count_map = self.fcm.get_all_pj_ver_count()

        self.__traverse_array_score(self.trie1, [])
        self.__traverse_array_score(self.trie2, [])
        self.__traverse_array_score(self.trie3, [])

        self.distinct_pj_count = None
        self.pj_ver_count_map = None
        self.fcm.shutdown()
        self.cm.shutdown()

    def __traverse_array_score(self, p, cur_stat):
        if p:
            for num in p["nodes"]:
                if num == '':
                    #print cur_stat, p["occur"]
                    self.__cal_array_score(p, cur_stat)
                elif type(num) == str:
                    #print cur_stat + json.loads(num), p["nodes"][num]["occur"]
                    self.__cal_array_score(p["nodes"][num], cur_stat + json.loads(num))
                else:
                    self.__traverse_array_score(p["nodes"][num], cur_stat + [num])

    def __cal_array_score(self, p, cur_stat):
        if p:
            length = len(cur_stat)
            rel_pj_len = len(p["attr"]["rel_projs"])
            #pj_score = cal_score(length, self.distinct_pj_count, rel_pj_len)
            pj_score = cal_score(math.log(length), self.distinct_pj_count, rel_pj_len) # todo: algorithm

            for rel_pj in p["attr"]["rel_projs"]:
                pj_ver_count = self.pj_ver_count_map[rel_pj]
                for rel_dyn in p["attr"]["rel_proj_dyns"][rel_pj]:
                    t_dyn = rel_dyn.split(":")[-1]
                    rel_ver_len = len(p["attr"]["rel_proj_vers"][rel_dyn])
                    #ver_score = cal_score(length, pj_ver_count, rel_ver_len)
                    ver_score = cal_score(math.log(length), pj_ver_count, rel_ver_len) # todo: algorithm
                    for rel_ver in p["attr"]["rel_proj_vers"][rel_dyn]:
                        full_ver = rel_pj + ":" + t_dyn + ":" + rel_ver
                        p["score_map"][full_ver] = (pj_score, ver_score)
                        #print rel_pj, "|", t_dyn, "|", rel_ver, "|", rel_pj_len, "/", self.distinct_pj_count, "|", rel_ver_len, "/", pj_ver_count, "|", pj_score, "|", ver_score

    def cal_score_sum_db(self):
        self.fcm = cassandra_manager.FeatureCassandraManager()
        self.fcm.clean_array_score3()
        print "cal trie1..."
        self.__traverse_array_score_sum(self.trie1, [])
        print "cal trie2..."
        self.__traverse_array_score_sum(self.trie2, [])
        print "cal trie3..."
        self.__traverse_array_score_sum(self.trie3, [])
        self.fcm.shutdown()

    def __traverse_array_score_sum(self, p, cur_stat):
        if p:
            for num in p["nodes"]:
                if num == '':
                    self.__cal_score_sum_db(p, cur_stat)
                elif type(num) == str:
                    self.__cal_score_sum_db(p["nodes"][num], cur_stat + json.loads(num))
                else:
                    self.__traverse_array_score_sum(p["nodes"][num], cur_stat + [num])

    def __cal_score_sum_db(self, p, cur_stat):
        for rel_pj in p["attr"]["rel_projs"]:
            for rel_dyn in p["attr"]["rel_proj_dyns"][rel_pj]:
                t_dyn = rel_dyn.split(":")[-1]
                for rel_ver in p["attr"]["rel_proj_vers"][rel_dyn]:
                    full_ver = rel_pj + ":" + t_dyn + ":" + rel_ver
                    pj_score, ver_score = p["score_map"][full_ver]
                    self.fcm.add_array_score3(rel_pj, t_dyn, rel_ver, pj_score, ver_score, len(cur_stat))
                    #print rel_pj, "|", t_dyn, "|", rel_ver, "|", pj_score, "|", ver_score, "|", len(cur_stat)


    def search_in_trie(self, binary_data):
        #print "\n\n[Search in trie]"
        self.search_result = []
        self.__search_item(self.trie1, [], binary_data)
        self.__search_item(self.trie2, [], binary_data)
        self.__search_item(self.trie3, [], binary_data)
        result = self.search_result
        self.search_result = None
        return result


    def __search_item(self, p, cur_stat, binary_data):
        if p:
            for num in p["nodes"]:
                if num == '':
                    if search_for_arr(cur_stat, p["pf_hex"], binary_data):
                        self.search_result.append((cur_stat, p["attr"], p["entropy"]))
                        #print "Find:", cur_stat, p["attr"]
                    else:
                        return
                elif type(num) == str:
                    num_array = cur_stat + json.loads(num)
                    if search_for_arr(num_array, p["nodes"][num]["pf_hex"], binary_data):
                        self.search_result.append((num_array, p["nodes"][num]["attr"], p["nodes"][num]["entropy"]))
                        #print "Find:", num_array, p["nodes"][num]["attr"]
                else:
                    self.__search_item(p["nodes"][num], cur_stat + [num], binary_data)


    def cal_passby_count(self):
        self.fcm = cassandra_manager.FeatureCassandraManager()
        self.cal_count = 0
        self.__traverse_cal_passby_count(self.trie1, [])
        self.__traverse_cal_passby_count(self.trie2, [])
        self.__traverse_cal_passby_count(self.trie3, [])
        self.fcm.shutdown()
        self.cal_count = None

    def __traverse_cal_passby_count(self, p, cur_stat):
        if p:
            for num in p["nodes"]:
                if num == '':
                    self.cal_count += 1
                    print "[" + str(self.cal_count) + "]", len(cur_stat)
                    self.__cal_passby_count(self.trie1, cur_stat)
                    self.__cal_passby_count(self.trie2, cur_stat)
                    self.__cal_passby_count(self.trie3, cur_stat)

                elif type(num) == str:
                    self.cal_count += 1
                    t_cur_stat = cur_stat + json.loads(num)

                    if True:
                    #if len(t_cur_stat) > 256:
                        print "[" + str(self.cal_count) + "]", len(t_cur_stat), "Skip..."
                        self.__add_passby_to_db(p["nodes"][num]["attr"], t_cur_stat)
                    #else:
                    #    print "[" + str(self.cal_count) + "]", len(t_cur_stat)
                    #    self.__cal_passby_count(self.trie1, t_cur_stat)
                    #    self.__cal_passby_count(self.trie2, t_cur_stat)
                    #    self.__cal_passby_count(self.trie3, t_cur_stat)
                else:
                    self.__traverse_cal_passby_count(p["nodes"][num], cur_stat + [num])


    def __cal_passby_count(self, trie, cur_stat):
        for i in range(len(cur_stat)):
            p = trie
            t_cur_stat = cur_stat[i:]
            if len(t_cur_stat) > 50:
                t_cur_stat = t_cur_stat[:50] + [json.dumps(t_cur_stat[50:])]
            index = 0

            for num in t_cur_stat:
                index += 1
                if num not in p["nodes"]:
                    break
                p = p["nodes"][num]
                if index < 4:
                    continue
                if '' in p["nodes"]:  # is an array
                    self.__add_passby_to_db(p["attr"], t_cur_stat[:index])

    def __add_passby_to_db(self, attr, cur_stat):
        for rel_pj in attr["rel_projs"]:
            for rel_dyn in attr["rel_proj_dyns"][rel_pj]:
                t_dyn = rel_dyn.split(":")[-1]
                for rel_ver in attr["rel_proj_vers"][rel_dyn]:
                    #print "\t\tadd:", cur_stat, rel_pj, t_dyn, rel_ver
                    self.fcm.insert_into_sf_num_array_distinct_passby(cur_stat, rel_pj, t_dyn, rel_ver)


    def get_array_score(self, array):
        res = self.__get_array_score(self.trie1, array)
        if res is None:
            res = self.__get_array_score(self.trie2, array)
        if res is None:
            res = self.__get_array_score(self.trie3, array)
        return res

    def __get_array_score(self, trie, array):
        if len(array) > 50:
            array = array[:50] + [json.dumps(array[50:])]
        p = trie
        for num in array:
            if num not in p["nodes"]:
                return None
            p = p["nodes"][num]
        return p["score_map"]



# ---------------------- Trie Utility  ----------------------

def is_continuous_array(array):
    flag = True
    for i in range(len(array)-1):
        if array[i+1] != array[i] + 1:
            flag = False
            break
    if flag:
        return flag
    flag = True
    for i in range(len(array)-1):
        if array[i+1] != array[i]:
            flag = False
            break
    if flag:
        return flag
    flag = True
    for i in range(len(array)-1):
        if array[i+1] != array[i] - 1:
            flag = False
            break
    return flag

def cal_each_len_of_bit_stream(bin_str):
    i = 0
    len_list = []
    while i < len(bin_str):
        if bin_str[i] == '0':
            i2 = bin_str[i:].find("1")
        else:
            i2 = bin_str[i:].find("0")
        if i2 != -1:
            len_list.append(i2)
            i += i2
        else:
            len_list.append(len(bin_str) - i)
            break
    return len_list

def cal_bit_stream_entropy(bin_str):
    len_list = cal_each_len_of_bit_stream(bin_str)
    #print "\t", len(bin_str), bin_str
    #print "\tlen_list:", len(len_list), len_list

    entropy = 0
    for l in len_list:
        if l > 10:
            continue
        entropy += (float(1) / (2 ** l)) * l
    #print "\tentropy:", entropy
    return entropy


def get_pe_str_value(value, length):
    if length == 2:
        try:
            return struct.pack("<b", value)
        except:
            return struct.pack("<B", value)
    elif length == 4:
        try:
            return struct.pack("<h", value)
        except:
            return struct.pack("<H", value)
    elif length == 8:
        try:
            return struct.pack("<i", value)
        except:
            return struct.pack("<I", value)
    elif length == 16:
        try:
            return struct.pack("<q", value)
        except:
            return struct.pack("<Q", value)
    else:
        try:
            return struct.pack("<q", value)
        except:
            return struct.pack("<Q", value)


def array_to_hex(num_array):
    hex_list = []
    max_item = max(num_array)
    min_item = min(num_array)

    waiting_potential_len = [2, 4, 8, 16]
    potential_len = []
    for plen in waiting_potential_len:
        max_int = 16 ** plen
        if max_int <= max_item or max_int / 2 <= -min_item:
            continue
        potential_len.append(plen)

    for length in potential_len:
        hex_search_str = ''
        for array_item in num_array:
            cur_num = array_item
            hex_search_str += get_pe_str_value(cur_num, length)
        hex_list.append(hex_search_str)

    #print num_array
    #print "\n".join([binascii.b2a_hex(h) for h in hex_list])
    #print "\n".join(hex_list)
    return hex_list

def search_for_arr(num_array, pf_hex, binary_data):
    if len(num_array) > 1000:
        if not search_for_arr(num_array[:1000], pf_hex, binary_data):
            return False
    if len(num_array) > 50:
        if not search_for_arr(num_array[:50], pf_hex, binary_data):
            return False

    if len(num_array) <= 50:
        hex_list = pf_hex
    else:
        hex_list = array_to_hex(num_array)
    #print "len:", len(num_array), "time cost:", datetime.datetime.now() - start_time
    #print num_array, hex_list
    #print len(num_array)
    for h in hex_list:
        #print h
        if binary_data.find(h) != -1:
            #print "Find!", len(num_array), num_array[:20]
            return True
    #print "Not Find...", len(num_array), num_array[:50]
    return False


def get_binary_data_segments(bin_file_path):
    data_segments = []
    pe = pefile.PE(bin_file_path)
    #print pe
    for st in pe.__structures__:
        if "Name" in st.__dict__.keys() and type(st.Name) == str:
            if st.Name.replace("\x00", "") in [".rdata", ".data"]:
                data_segments.append({"Name": st.Name, "PointerToRawData": st.PointerToRawData, "SizeOfRawData": st.SizeOfRawData})
    return data_segments


# ----------------------  Match String  ----------------------

def analysis_binfile_string_core(bin_string_feature):
    fcm = cassandra_manager.FeatureCassandraManager()
    pj_score_table, ver_score_table, count_table, match_string_table = match_string_binfile2lib(fcm, bin_string_feature)  # result -> DB
    match_string_result = {"pj_score_table": pj_score_table, "ver_score_table": ver_score_table, "count_table": count_table, "match_string_table": match_string_table}
    handle_string_score(pj_score_table, count_table, match_string_table)
    fcm.shutdown()
    return  match_string_result


def handle_string_score(pj_score_table, count_table, match_string_table):
    fcm = cassandra_manager.FeatureCassandraManager()
    all_string_score_map = fcm.get_all_string_score2()
    count = 0
    valid_results = []
    for rel_pj in pj_score_table:
        count += 1
        for dyn_name in pj_score_table[rel_pj]:
            for pj_ver in pj_score_table[rel_pj][dyn_name]:
                string_pj_score = None
                try:
                    string_pj_score, string_ver_score, string_count = all_string_score_map[rel_pj][dyn_name][pj_ver]
                except:
                    pass
                if not string_pj_score:
                    continue
                matched_count = count_table[rel_pj][dyn_name][pj_ver]
                count_sim = float(matched_count)/string_count
                cur_str_pj_score = pj_score_table[rel_pj][dyn_name][pj_ver]
                str_pj_sim = cur_str_pj_score / string_pj_score
                if string_count > 20 and (count_sim >= 0.5 or str_pj_sim >= 0.5 or (count_sim >= 0.3 and str_pj_sim >= 0.3) or  (string_count > 500 and count_sim + str_pj_sim >= 0.5)):
                    valid_results.append({"rel_pj": rel_pj, "dyn_name": dyn_name, "pj_ver": pj_ver, "matched_count": matched_count, "string_count": string_count, "count_sim": count_sim,
                                          "cur_str_pj_score": cur_str_pj_score, "string_pj_score": string_pj_score, "str_pj_sim": str_pj_sim})
    rel_pjs, reuse_type_map = cal_valid_reuse_in_string(fcm, valid_results, match_string_table)
    fcm.shutdown()
    return rel_pjs, reuse_type_map


def cal_valid_reuse_in_string(fcm, valid_results, match_string_table):
    reuse_type_map = {"SimpleR": [], # Simple Reuse
                      "PartialR": [], # Partial Reuse
                      "InterCR": []} # Inter-Component Reuse

    psb_pj_infos = [(item["rel_pj"], item["dyn_name"], item["pj_ver"], item["matched_count"], item["string_count"]) for item in valid_results]
    psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=True)

    valid_pj_infos = []
    while len(psb_pj_infos):
        new_psb_pj_infos = []
        pat_len = psb_pj_infos[0][3]
        valid_pj_infos.append(psb_pj_infos[0])
        for item in psb_pj_infos[1:]:
            item_len = item[3]
            sim_len = len(set(match_string_table[item[0]][item[1]][item[2]]) & set(match_string_table[psb_pj_infos[0][0]][psb_pj_infos[0][1]][psb_pj_infos[0][2]]))
            sim = float(sim_len)/item_len
            if sim < 0.85 or sim_len * 1.3 > pat_len:
                new_psb_pj_infos.append(item)
        psb_pj_infos = new_psb_pj_infos
        psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=True)

    psb_pj_infos = valid_pj_infos
    psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=False)
    valid_pj_infos = []
    while len(psb_pj_infos):
        new_psb_pj_infos = []
        pat_len = psb_pj_infos[0][4]
        pat_matchted_len = psb_pj_infos[0][3]
        valid_pj_infos.append(psb_pj_infos[0])
        for item in psb_pj_infos[1:]:
            item_len = item[4]
            item_matched_len = item[3]
            sim_len = len(set(match_string_table[item[0]][item[1]][item[2]]) & set(match_string_table[psb_pj_infos[0][0]][psb_pj_infos[0][1]][psb_pj_infos[0][2]]))
            sim = float(sim_len)/min(item_matched_len, pat_matchted_len)
            if sim < 0.85 or float(item_len)/pat_len < 1.3:
                new_psb_pj_infos.append(item)
        psb_pj_infos = new_psb_pj_infos
        psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=False)


    rel_pjs = set()
    for item in valid_results:
        if (item["rel_pj"], item["dyn_name"], item["pj_ver"], item["matched_count"], item["string_count"]) not in valid_pj_infos:
            continue
        alias_pj_name, alias_dyn_name = fcm.find_alias(item["rel_pj"], item["dyn_name"])
        if alias_pj_name:
            rel_pjs.add(alias_pj_name)
        else:
            alias_pj_name, alias_dyn_name = fcm.find_alias(item["rel_pj"], "")
            if alias_pj_name == '':
                continue
            if alias_pj_name:
                rel_pjs.add(alias_pj_name)
            else:
                rel_pjs.add(item["rel_pj"])
    return rel_pjs, reuse_type_map


def match_string_binfile2lib(fcm, string_list):
    string_list = set([item["string"] for item in string_list])
    cm = cassandra_manager.CassandraManager()
    distinct_pj_count = reset_controller(cm, fcm, False)
    pj_score_table = {}
    ver_score_table = {}
    count_table = {}
    match_string_table = {}

    pj_ver_count_map = fcm.get_all_pj_ver_count()

    index = 0
    for string in string_list:
        if len(string) > 65535 or len(string) <= 0:
            continue
        res = fcm.get_string_from_sf_string2(string)

        if len(res.current_rows):
            row = json.loads(res.current_rows[0][0])
            rel_proj_dyns = row["rel_proj_dyns"]
            rel_proj_vers = row["rel_proj_vers"]
            rel_projs = row["rel_projs"]
            weight = row["weight"]
            rel_pj_len = len(rel_projs)
            pj_score = cal_score(weight, distinct_pj_count, rel_pj_len)

            index += 1
            for rel_pj in rel_projs:
                if rel_pj not in pj_ver_count_map:
                    continue
                pj_ver_count = pj_ver_count_map[rel_pj]

                if rel_pj not in pj_score_table:
                    pj_score_table[rel_pj] = {}
                    ver_score_table[rel_pj] = {}
                    count_table[rel_pj] = {}
                    match_string_table[rel_pj] = {}
                for rel_dyn in json.loads(rel_proj_dyns[rel_pj]):
                    t_dyn = rel_dyn.split(":")[-1]
                    if t_dyn not in pj_score_table[rel_pj]:
                        pj_score_table[rel_pj][t_dyn] = {}
                        ver_score_table[rel_pj][t_dyn] = {}
                        count_table[rel_pj][t_dyn] = {}
                        match_string_table[rel_pj][t_dyn] = {}

                    rel_ver_len = len(json.loads(rel_proj_vers[rel_dyn]))
                    ver_score = cal_score(weight, pj_ver_count, rel_ver_len)
                    for rel_ver in json.loads(rel_proj_vers[rel_dyn]):
                        if rel_ver not in pj_score_table[rel_pj][t_dyn]:
                            pj_score_table[rel_pj][t_dyn][rel_ver] = 0
                            ver_score_table[rel_pj][t_dyn][rel_ver] = 0
                            count_table[rel_pj][t_dyn][rel_ver] = 0
                            match_string_table[rel_pj][t_dyn][rel_ver] = []
                        pj_score_table[rel_pj][t_dyn][rel_ver] += pj_score
                        ver_score_table[rel_pj][t_dyn][rel_ver] += ver_score
                        count_table[rel_pj][t_dyn][rel_ver] += 1
                        match_string_table[rel_pj][t_dyn][rel_ver].append(index)

    return pj_score_table, ver_score_table, count_table, match_string_table



# ----------------------  Calculate String Score  ----------------------

def get_word_key_value(word):
    weight = 0
    if word.isalpha():
        weight = 0.1
    #if word.find(library_name) != -1:
    #    weight = weight + 5
    if word.islower():
        weight = weight + 0.1
    if word[1:].isupper():
        weight = weight + 0.25
    if feature_match.hasNumbers(word):
        weight = weight + 0.25
    if feature_match.has_special_char(word):
        weight = weight + 0.5
    if feature_match.is_func_name(word[1:]):
        weight = weight + 0.5
    if feature_match.is_web_name(word):
        weight = weight + 1
    return weight


def get_string_weight(string):
    if string.find(' ') != -1:
        weight = 0
        for string in string.split(' '):
            weight += get_word_key_value(string)
        return weight * (1 + len(string.split(' ')) * 0.1)
    else:
        return get_word_key_value(string)


def reset_controller(cm, fcm, update_controller=False):
    if update_controller:
        query = "select project_name, project_version from src_projects where analyse_status=1 allow filtering"
        statement = SimpleStatement(query, fetch_size=100)
        pj_ver_map = {}
        for row in cm.session.execute(statement):
            if row[0] not in pj_ver_map:
                pj_ver_map[row[0]] = 0
            pj_ver_map[row[0]] += 1
        for pj_name in pj_ver_map:
            fcm.update_controller_line(pj_name, pj_ver_map[pj_name])
    distinct_pj_count = fcm.get_distinct_pj_count()
    return distinct_pj_count


def cal_score(weight, total_count, rel_count):
    return float(weight) * math.log10(float(total_count)/ rel_count)



# ----------------------  Match Array  ----------------------

def download_and_unzip(swift_path):
    zip_whole_path = os.path.join(download_dir, swift_path).replace("\\", "\\\\").decode("utf8", "replace")
    if os.path.exists(zip_whole_path[:-4]):
        return zip_whole_path[:-4]

    localpath = os.path.join(download_dir, swift_path)
    if not download_swift.swift_download_file(localpath, swift_path):
        print "[ERROR] download_and_unzip swift_path not exists:", swift_path
        return None

    f = zipfile.ZipFile(zip_whole_path, 'r')
    print "extractall:", zip_whole_path[:-4]
    try:
        f.extractall(zip_whole_path[:-4])
    except Exception, e:
        print "[ERROR] download_and_unzip:", e
        return None
    f.close()
    os.remove(zip_whole_path)
    return zip_whole_path[:-4]


def analysis_binfile_array_core(bin_file_path, array_tries, trie_type=0):
    global array_trie
    load_array_trie(array_tries, trie_type)
    pj_score_table, ver_score_table, count_table, match_array_table, match_len_table = match_array_binfile2lib(bin_file_path, array_trie)  # result -> DB
    handle_array_score(pj_score_table, count_table, match_array_table, match_len_table)
    gc.collect()

def handle_array_score(pj_score_table, count_table, match_array_table, match_len_table):
    fcm = cassandra_manager.FeatureCassandraManager()
    count = 0
    valid_results = []
    all_array_score_map = fcm.get_all_array_score3()
    for rel_pj in pj_score_table:
        count += 1
        for dyn_name in pj_score_table[rel_pj]:
            for pj_ver in pj_score_table[rel_pj][dyn_name]:
                while True:
                    try:
                        array_pj_score, array_ver_score, array_count, array_len_count = all_array_score_map[rel_pj][dyn_name][pj_ver]
                        break
                    except Exception, e:
                        print e
                if not array_pj_score:
                    continue
                matched_count = count_table[rel_pj][dyn_name][pj_ver]
                matched_len = match_len_table[rel_pj][dyn_name][pj_ver]
                count_sim = float(matched_count)/array_count
                len_sim = float(matched_len)/array_len_count
                cur_arr_pj_score = pj_score_table[rel_pj][dyn_name][pj_ver]
                arr_pj_sim = cur_arr_pj_score / array_pj_score

                if ((array_count > 5 or array_len_count > 50 or array_pj_score > 50) and cur_arr_pj_score > 15)  \
                        and (count_sim >= 0.7 or (count_sim >= 0.5 and len_sim > 0.7) or (count_sim >= 0.5 and arr_pj_sim >= 0.7) or (count_sim >= 0.5 and len_sim > 0.5 and arr_pj_sim >= 0.5) or (len_sim + arr_pj_sim >= 1.5)\
                                or (cur_arr_pj_score > 50 and count_sim >= 0.5)):
                    if fcm.check_invalid(rel_pj, "", "array") or fcm.check_invalid(rel_pj, dyn_name, "array") or fcm.check_invalid(rel_pj, "", "") or fcm.check_invalid(rel_pj, dyn_name, ""):
                        continue
                    valid_results.append({"rel_pj": rel_pj, "dyn_name": dyn_name, "pj_ver": pj_ver, "matched_count": matched_count, "array_count": array_count, "count_sim": count_sim,
                                          "cur_arr_pj_score": cur_arr_pj_score, "array_pj_score": array_pj_score, "str_pj_sim": arr_pj_sim, "matched_len": matched_len, "array_len_count": array_len_count})

    print "\n"
    rel_pjs = cal_valid_reuse_in_array(fcm, valid_results, match_array_table)
    fcm.shutdown()
    return rel_pjs

def cal_valid_reuse_in_array(fcm, valid_results, match_array_table):
    psb_pj_infos = [(item["rel_pj"], item["dyn_name"], item["pj_ver"], item["matched_count"], item["array_count"], item["matched_len"], item["array_len_count"]) for item in valid_results]
    psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=True)

    valid_pj_infos = []
    while len(psb_pj_infos):
        new_psb_pj_infos = []
        pat_len = psb_pj_infos[0][3]
        valid_pj_infos.append(psb_pj_infos[0])
        #print psb_pj_infos[0], pat_len
        for item in psb_pj_infos[1:]:
            item_len = item[3]
            sim_len = len(set(match_array_table[item[0]][item[1]][item[2]]) & set(match_array_table[psb_pj_infos[0][0]][psb_pj_infos[0][1]][psb_pj_infos[0][2]]))
            sim = float(sim_len)/item_len
            str_sim = None
            str_sim_len = None
            pat_str_len = None
            if sim > 0.85:
                if sim_len * 1.3 < pat_len:
                    continue
                if str_sim_len and str_sim_len * 1.3 > pat_str_len:
                    continue
            new_psb_pj_infos.append(item)

        psb_pj_infos = new_psb_pj_infos
        psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=True)

    psb_pj_infos = valid_pj_infos
    psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=False)
    valid_pj_infos = []
    while len(psb_pj_infos):
        new_psb_pj_infos = []
        pat_len = psb_pj_infos[0][4]
        pat_matchted_len = psb_pj_infos[0][3]
        valid_pj_infos.append(psb_pj_infos[0])
        for item in psb_pj_infos[1:]:
            item_len = item[4]
            item_matched_len = item[3]
            sim_len = len(set(match_array_table[item[0]][item[1]][item[2]]) & set(match_array_table[psb_pj_infos[0][0]][psb_pj_infos[0][1]][psb_pj_infos[0][2]]))
            sim = float(sim_len)/min(item_matched_len, pat_matchted_len)
            str_sim_len = None
            if sim > 0.85:
                if float(item_len)/pat_len < 1.3:
                    continue
                if str_sim_len and float(str_sim_len)/pat_str_len < 1.3:
                    continue
            new_psb_pj_infos.append(item)

        psb_pj_infos = new_psb_pj_infos
        psb_pj_infos = sorted(psb_pj_infos, lambda x,y:cmp(x[3],y[3]), reverse=False)

    rel_pjs = set()
    for item in valid_results:
        if (item["rel_pj"], item["dyn_name"], item["pj_ver"], item["matched_count"], item["array_count"], item["matched_len"], item["array_len_count"]) not in valid_pj_infos:
            continue
        alias_pj_name, alias_dyn_name = fcm.find_alias(item["rel_pj"], item["dyn_name"])
        if alias_pj_name:
            rel_pjs.add(alias_pj_name)
        else:
            alias_pj_name, alias_dyn_name = fcm.find_alias(item["rel_pj"], "")
            if alias_pj_name == '':
                continue
            if alias_pj_name:
                rel_pjs.add(alias_pj_name)
            else:
                rel_pjs.add(item["rel_pj"])
    return rel_pjs

def match_array_binfile2lib(bin_file_path, array_trie):
    data_segments = get_binary_data_segments(bin_file_path)
    pj_score_table = {}
    ver_score_table = {}
    count_table = {}
    match_len_table = {}
    match_array_table = {}
    index = 0
    for seg in data_segments:
        with open(bin_file_path, "rb") as f:
            print "\tName:", seg["Name"]
            print "\tPointerToRawData:", hex(seg["PointerToRawData"])
            print "\tSizeOfRawData:", hex(seg["SizeOfRawData"])
            f.seek(seg["PointerToRawData"])
            binary_data = f.read(seg["SizeOfRawData"])

            search_result = array_trie.search_in_trie(binary_data)
            print "\tsearch_result len:", len(search_result)
            for item in search_result:
                index += 1
                array = item[0]
                rel_projs = item[1]["rel_projs"]
                rel_proj_dyns = item[1]["rel_proj_dyns"]
                rel_proj_vers = item[1]["rel_proj_vers"]
                entropy = item[2]
                score_map = array_trie.get_array_score(array)

                for rel_pj in rel_projs:
                    if rel_pj not in pj_score_table:
                        pj_score_table[rel_pj] = {}
                        ver_score_table[rel_pj] = {}
                        count_table[rel_pj] = {}
                        match_len_table[rel_pj] = {}
                        match_array_table[rel_pj] = {}
                    for dyn_name in rel_proj_dyns[rel_pj]:
                        t_dyn = dyn_name.split(":")[-1]
                        if t_dyn not in pj_score_table[rel_pj]:
                            pj_score_table[rel_pj][t_dyn] = {}
                            ver_score_table[rel_pj][t_dyn] = {}
                            count_table[rel_pj][t_dyn] = {}
                            match_len_table[rel_pj][t_dyn] = {}
                            match_array_table[rel_pj][t_dyn] = {}
                        for rel_ver in rel_proj_vers[dyn_name]:
                            if rel_ver not in pj_score_table[rel_pj][t_dyn]:
                                pj_score_table[rel_pj][t_dyn][rel_ver] = 0
                                ver_score_table[rel_pj][t_dyn][rel_ver] = 0
                                count_table[rel_pj][t_dyn][rel_ver] = 0
                                match_len_table[rel_pj][t_dyn][rel_ver] = 0
                                match_array_table[rel_pj][t_dyn][rel_ver] = []
                            full_ver = dyn_name + ":" + rel_ver
                            pj_score, ver_score = score_map[full_ver]
                            pj_score_table[rel_pj][t_dyn][rel_ver] += pj_score
                            ver_score_table[rel_pj][t_dyn][rel_ver] += ver_score
                            count_table[rel_pj][t_dyn][rel_ver] += 1
                            match_len_table[rel_pj][t_dyn][rel_ver] += len(array)
                            match_array_table[rel_pj][t_dyn][rel_ver].append(index)

    return pj_score_table, ver_score_table, count_table, match_array_table, match_len_table


def load_array_trie(array_tries, trie_type):
    if trie_type == 0:
        filename1 = array_tries[0]
        filename2 = array_tries[1]
        filename3 = array_tries[2]
    else:
        filename1 = array_tries[trie_type-1]
        filename2 = None
        filename3 = None
    global array_trie
    global trie_files
    try:
        array_trie
        if trie_files != [filename1, filename2, filename3]:
            1/0
    except:
        print "> Loading array_trie..."
        array_trie = ArrayTrie()
        input_file = open(filename1, "rb")
        array_trie.trie1 = pickle.load(input_file)
        input_file.close()
        if filename2 is not None:
            input_file = open(filename2, "rb")
            array_trie.trie2 = pickle.load(input_file)
            input_file.close()
        if filename3 is not None:
            input_file = open(filename3, "rb")
            array_trie.trie3 = pickle.load(input_file)
            input_file.close()
        print "> array_trie is loaded."
        trie_files = [filename1, filename2, filename3]
    print "> Size of array_trie:", array_trie.count()


def merge_dict(dict1, dict2, i):
    for main_key in dict2:  # "pj_score_table", "ver_score_table", "count_table", "match_array_table", "match_len_table"
        if main_key not in dict1:
            dict1[main_key] = {}
        for rel_pj in dict2[main_key]:
            if rel_pj not in dict1[main_key]:
                dict1[main_key][rel_pj] = {}
            for dyn_name in dict2[main_key][rel_pj]:
                if dyn_name not in dict1[main_key][rel_pj]:
                    dict1[main_key][rel_pj][dyn_name] = {}
                for rel_ver in dict2[main_key][rel_pj][dyn_name]:
                    if rel_ver not in dict1[main_key][rel_pj][dyn_name]:
                        if type(dict2[main_key][rel_pj][dyn_name][rel_ver]) is not list:
                            dict1[main_key][rel_pj][dyn_name][rel_ver] = 0.0
                        else:
                            dict1[main_key][rel_pj][dyn_name][rel_ver] = []
                    if type(dict2[main_key][rel_pj][dyn_name][rel_ver]) is not list:
                        dict1[main_key][rel_pj][dyn_name][rel_ver] += dict2[main_key][rel_pj][dyn_name][rel_ver]
                    else:
                        for item in dict2[main_key][rel_pj][dyn_name][rel_ver]:
                            dict1[main_key][rel_pj][dyn_name][rel_ver].append(str(i) + ":" + str(item))
    return dict1



download_dir = r'C:\Users\installer\Desktop\downloadfiles'
root_dir = "C:" + os.environ["HOMEPATH"] + "\\Desktop\\swift_local\\"
root_dir = "E:\\swift_local\\"
MAX_CASSANDRA_READ = 12
global array_trie
if __name__ == "__main__":
    bin_string_feature = get_string_features(binary_file)
    analysis_binfile_string_core(bin_string_feature)

    array_trie_files = ["array_trie1.pickle", "array_trie2.pickle", "array_trie3.pickle"]
    load_array_trie(array_trie_files, trie_type=0)
    analysis_binfile_array_core(bin_file_path, array_trie_files)












