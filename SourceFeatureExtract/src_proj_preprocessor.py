# coding: utf8

import os
import sys
import re
import commands
import json

import get_file_dependency

class Preprocessor(object):
    def __init__(self,path):
        self.path = path
        self.source_root = self.find_source_root()
        self.cmake = self.is_cmake_pj(self.source_root)
        self.make = self.is_make_pj(self.source_root)
        self.autogen = self.is_autogen(self.source_root)
        self.custom_makefile = None
        self.custom_make = self.is_custom_make(self.source_root)
        self.compile_root = None
        self.log_for_make = None
        self.log_for_make_n = None
        self.do_compile = False

    def is_source_root(self, path):
        count = 0
        for f in os.listdir(path):
            if f.lower() in ["install", "readme", "readme.md", "makefile", "configure", "config", "copying", "cmakelist.txt", "changelog"]:
                count += 1
        return count

    def find_source_root(self):
        if self.is_cmake_pj(self.path) or self.is_make_pj(self.path) or self.is_autogen(self.path) or self.is_custom_make(self.path):
            return self.path
        
        file_list = os.listdir(self.path) 
        for f in file_list:
            temp_path = self.path + "/" + f
            if not os.path.isdir(temp_path):
                continue 
            if f.lower() in ["src", "source"]:
                if self.is_cmake_pj(temp_path) or self.is_make_pj(temp_path) or self.is_autogen(temp_path) or self.is_custom_make(temp_path):
                    return temp_path

        possible_source_root = []
        for f in file_list:
            temp_path = self.path + "/" + f
            if not os.path.isdir(temp_path):
                continue 
            score = self.is_source_root(temp_path)
            if score > 0:   
                possible_source_root.append((temp_path, score))
        if len(possible_source_root) == 0:
            return self.path
        elif len(possible_source_root) == 1:
            return possible_source_root[0][0]
        else:
            max_score = 0
            max_i = 0
            for i in range(len(possible_source_root)):
                if max_score < possible_source_root[i][1]:
                    max_score = possible_source_root[i][1]
                    max_i = i
            return possible_source_root[max_i][0]
        return self.path

    def is_custom_make(self, directory):
        file_list = os.listdir(directory)
        flag = False
        makefile_list = []
        for _file in file_list:
            if _file.lower().startswith("makefile."):
                flag = True
                makefile_list.append(_file)
        if not flag:
            return False
        if len(makefile_list) == 1:
            self.custom_makefile = _file
            return True
        for _file in makefile_list:
            if "linux" in _file.lower():
                self.custom_makefile = _file
                return True
            if "unix" in _file.lower():
                self.custom_makefile = _file
                return True
        return False

    def is_autogen(self, directory):
        file_list = os.listdir(directory)
        flag = False
        for _file in file_list:
            if _file==r"autogen.sh":
                flag = True
        if not flag:
            return False
        for _file in file_list:
            if _file==r"configure.ac":
                flag = True
        if not flag:
            return False
        return True

    def is_cmake_pj(self, directory):
        file_list = os.listdir(directory)
        for _file in file_list:
            if _file==r"CMakeLists.txt":
                return True
        return False

    def is_make_pj(self, directory):
        file_list = os.listdir(directory)
        #if "CMakeLists.txt" in file_list:
        #    return False
        if "configure" in file_list:
            return True
        if "Makefile" in file_list or "makefile" in file_list:
            return True
        if "config" in file_list:
            return True
        return False

    def __extract_commands(self,commandline):
        command_list = []
        command_ori_list = str(commandline).split(' ')
        i = 0
        while i in range(len(command_ori_list)):
            token = command_ori_list[i]
            if str(token).startswith("-D") or str(token).startswith("-L"): # or str(token).startswith("-std="):
                command_list.append(token)

            if str(token).startswith("-I"):
                if token == "-I":
                    token += command_ori_list[i+1]
                    command_list.append(token)
                    i += 1
                else:
                    command_list.append(token)

            if str(token).startswith("-i"):
                if os.path.isdir(command_ori_list[i+1]):
                    token += " "
                    token += command_ori_list[i+1]
                    command_list.append(token)
                    i += 1
                
            # REF: https://gcc.gnu.org/onlinedocs/gcc/C-Dialect-Options.html
            if str(token).startswith("-std"):
                if token[5:] in ["c99", "c9x", "iso9899:1999", "iso9899:199x"]:
                    command_list.append("-std=c99")
                elif token[5:] in ["c11", "c1x", "iso9899:2011"]:
                    command_list.append("-std=c11")
                elif token[5:] in ["gnu99", "gnu9x"]:
                    command_list.append("-std=gnu99")
                elif token[5:] in ["gnu11", "gnu1x"]:
                    command_list.append("-std=gnu11")
                elif token[5:] in ["c++11", "c++0x"]:
                    command_list.append("-std=c++11")
                elif token[5:] in ["gnu++11", "gnu++0x"]:
                    command_list.append("-std=gnu++11")
                elif token[5:] in ["c++14", "c++1y"]:
                    command_list.append("-std=c++14")
                elif token[5:] in ["gnu++14", "gnu++1y"]:
                    command_list.append("-std=gnu++14")
                elif token[5:] in ["c++17", "c++1z"]:
                    command_list.append("-std=c++17")
                elif token[5:] in ["gnu++17", "gnu++1z"]:
                    command_list.append("-std=gnu++17")
                else:
                    command_list.append(token)
            i += 1
        return command_list

    def read_make_info_file(self,info_file,source_file_list=[]):
        command_dict={}
        if self.autogen or self.cmake or self.make or self.custom_make:
            for source in source_file_list:
                source_pattern = source.replace("+", "\+").replace("*", "\*")
                flag = False
                with open(info_file,"r") as f:
                    for line in f.readlines():
                        if re.search('\\b' + source_pattern + '\\b', str(line)):
                            command_list = self.__extract_commands(line)
                            if len(command_list):
                                command_dict[source]=command_list
                                flag = True
                if not flag:
                    with open(info_file,"r") as f:
                        for line in f.readlines():
                            if re.search('\\b' + source_pattern.split("/")[-1] + '\\b', str(line)):
                                command_list = self.__extract_commands(line)
                                if len(command_list):
                                    command_dict["-" + source.split("/")[-1]]=command_list
        return command_dict

    def auto_compile(self):
        #if the project is cmake project:
        if self.autogen:
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && chmod u+x autogen.sh && ./autogen.sh")
            if status != 0:
                (status, output) = commands.getstatusoutput("cd " + self.source_root + " && dos2unix autogen.sh && ./autogen.sh")
            
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && chmod u+x configure && ./configure")
            if status != 0:
                (status, output) = commands.getstatusoutput("cd " + self.source_root + " && dos2unix configure && ./configure")
            
            (status, output) = commands.getstatusoutput("cd "+self.source_root+" && make VERBOSE=1 V=1 > __info_make")
            if status!=0:
                raise Exception("autogen error in the project") 
            return self.source_root+"/__info_make"

        elif self.make:
            #if not a cmake project:
            if os.path.exists(os.path.join(self.source_root, "configure")):
                (status, output) = commands.getstatusoutput("cd "+self.source_root+" && chmod u+x configure && ./configure") 
                if status != 0:
                    (status, output) = commands.getstatusoutput("cd "+self.source_root+" && dos2unix configure && ./configure") 
            elif os.path.exists(os.path.join(self.source_root, "config")):
                (status, output) = commands.getstatusoutput("cd "+self.source_root+" && chmod u+x config && ./config") 
                if status != 0:
                    (status, output) = commands.getstatusoutput("cd "+self.source_root+" && dos2unix config && ./config") 
            (status, output) = commands.getstatusoutput("cd "+self.source_root+" && make VERBOSE=1 V=1 > __info_make")
            if status!=0:
                raise Exception("make error in the project")
            return self.source_root+"/__info_make"
        
        elif self.cmake:
            with open(self.source_root+"/CMakeLists.txt","r+") as f:
                old = f.read()
                f.seek(0)
                f.write(r"set(CMAKE_VERBOSE_MAKEFILE on)")
                f.write('\n')
                f.write(old)

            if os.path.exists(self.source_root + "/build_path"):
                os.system("cd "+self.source_root+"&& rm -r build_path")
            os.system("cd "+self.source_root+"&& mkdir build_path")
            
            (status, output) = commands.getstatusoutput("cd "+self.source_root+"/build_path && cmake --debug-output --build -Wno-dev -D CMAKE_BUILD_TYPE=Debug ..")
            if status!=0:
                raise Exception("cmake error in the project")
            
            (status, output) = commands.getstatusoutput("cd "+self.source_root+"/build_path && make VERBOSE=1 V=1 > __info_cmake")
            if status!=0:
                raise Exception("cmake error in the project")
            return self.source_root+"/build_path/__info_cmake"

        elif self.custom_make:
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && make VERBOSE=1 V=1 -f " + self.custom_makefile + " > __info_make")
            if status!=0:
                raise Exception("custom_make error in the project")
            return self.source_root+"/__info_make"
        else:
            raise Exception("unhandled type of compilation")
            

    def auto_make_n(self):
        #if the project is cmake project:
        if self.autogen:
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && chmod u+x autogen.sh && ./autogen.sh")
            if status != 0:
                (status, output) = commands.getstatusoutput("cd " + self.source_root + " && dos2unix autogen.sh && ./autogen.sh")
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && chmod u+x configure && ./configure")
            if status != 0:
                (status, output) = commands.getstatusoutput("cd " + self.source_root + " && dos2unix configure && ./configure")
            (status, output) = commands.getstatusoutput("cd "+self.source_root+" && make -n > __info_make_n")
            if status!=0:
                raise Exception("autogen error in the project") 
            return self.source_root+"/__info_make_n"

        elif self.make:
            #if not a cmake project:
            if os.path.exists(os.path.join(self.source_root, "configure")):
                (status, output) = commands.getstatusoutput("cd "+self.source_root+" && chmod u+x configure && ./configure") 
                if status != 0:
                    (status, output) = commands.getstatusoutput("cd "+self.source_root+" && dos2unix configure && ./configure") 
            elif os.path.exists(os.path.join(self.source_root, "config")):
                (status, output) = commands.getstatusoutput("cd "+self.source_root+" && chmod u+x config && ./config") 
                if status != 0:
                    (status, output) = commands.getstatusoutput("cd "+self.source_root+" && dos2unix config && ./config") 
            (status, output) = commands.getstatusoutput("cd "+self.source_root+" && make -n > __info_make_n")
            if status!=0:
                raise Exception("make error in the project")
            return self.source_root+"/__info_make_n"
        
        elif self.cmake:
            with open(self.source_root+"/CMakeLists.txt","r+") as f:
                old = f.read()
                f.seek(0)
             
                f.write(r"set(CMAKE_VERBOSE_MAKEFILE on)")
                f.write('\n')
                f.write(old)

            if os.path.exists(self.source_root + "/build_path"):
                os.system("cd "+self.source_root+"&& rm -r build_path")
            os.system("cd "+self.source_root+"&& mkdir build_path")
            
            (status, output) = commands.getstatusoutput("cd "+self.source_root+"/build_path && cmake --debug-output --build -Wno-dev -D CMAKE_BUILD_TYPE=Debug ..")
            if status!=0:
                raise Exception("cmake error in the project")
            
            (status, output) = commands.getstatusoutput("cd "+self.source_root+"/build_path && make -n > __info_make_n")
            if status!=0:
                raise Exception("cmake error in the project")
            return self.source_root+"/build_path/__info_make_n"

        elif self.custom_make:
            (status, output) = commands.getstatusoutput("cd " + self.source_root + " && make -n -f " + self.custom_makefile + " > __info_make_n")
            if status!=0:
                raise Exception("custom_make error in the project")
            return self.source_root+"/__info_make_n"
        else:
            raise Exception("unhandled type of compilation")
            

    def get_make_info(self, force_make=False):
        all_make_info_filename = os.path.join(self.path, "__all_make_n_info.json")
        if not force_make and os.path.exists(all_make_info_filename):
            with open(all_make_info_filename) as f:
                content = json.load(f)
            command_dict = content['command_dict']
            need_to_compile_files = content['need_to_compile_files']
            bin_src_map = content['bin_src_map']
            files_compile_dir = content['files_compile_dir']
            
            for parent, dirnames, filenames in os.walk(self.path):
                for filename in filenames:
                    if filename == '__info_make_n':
                        self.compile_root = parent
            status = True
        else:
            source_files_list = []
            for parent, dirnames, filenames in os.walk(self.path):
                for filename in filenames:
                    if filename.endswith('.c') or filename.endswith('.cc') or filename.endswith('.cpp'):
                        source_files_list.append(os.path.join(parent, filename)[len(self.path)+1:])
            is_make_n = False 
            self.do_compile = True   
            try:
                makeresult_path=self.auto_compile()
            except Exception, e:
                self.log_for_make = str(e)   
                try: 
                    makeresult_path=self.auto_make_n()
                    is_make_n = True
                except Exception, e:
                    self.log_for_make_n = str(e)
                makeresult_path = ""
            
            if makeresult_path == "":
                command_dict = {}
                need_to_compile_files = []
                bin_src_map = {}
                files_compile_dir = {}
                status = True
            else:
                self.compile_root = os.path.dirname(makeresult_path)
                command_dict  = self.read_make_info_file(makeresult_path,source_files_list)
                bin_src_map, need_to_compile_files, status, files_compile_dir = get_file_dependency.get_need_to_compile_files(makeresult_path, self.source_root, is_make_n=is_make_n)

        return command_dict, need_to_compile_files, bin_src_map, status, files_compile_dir

if __name__=='__main__':
    project_root = '/root/libs/libtiff'
    pre = Preprocessor(project_root)
    command_dict, need_to_compile_files, bin_src_map, status, files_compile_dir = pre.get_make_info(force_make=True)
    

