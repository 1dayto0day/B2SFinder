# B2SFinder

---

B2SFinder is a binary-to-source matching tool for OSS reuse detection on COTS software. This project contains the core code of B2SFinder without implementation about database and pipeline. 

### Requirements

A Windows server with python 2.7 (64-bit) and IDA 7.0.

A Linux server with python.


### Quickstart

**Step 0: Download the source code packages of candidate OSS projects.**

**Step 1: Extract code features of OSS projects.**

```shell 
$ cd SourceFeatureExtract
$ python extract_source_feature.py -pj_root <OSS_project_root>
```

**Step2: Compare targeted COTS software with all candidate OSS projects.**

```shell 
$ cd FeatureMatch
$ python feature_match.py -local_match <bin_path/bin_dir>
```



### Code Structure

| dir | file | function |
| :----  | :--- | :------- |
| - | COTS_list.txt | MD5 list of installers of COTS software products. |
| BinaryFeatureExtract  |  local_binary_feature.py | Extracting code features of a binary file. |
| FeatureMatch  |  feature_inverted_and_trie.py | Building and searching in inverted index and Trie without implementation of database. |
| | feature_match.py | Matching code feature instances between binary code and source code. |
| | feature_preprocessor.py | Preprocessing feature instances to unify their represantations. |
| SourceFeatureExtract | extract_source_feature.py | Extracting code features of an OSS project. |
| | get_file_dependency.py | Building Compilation Dependency Layered Graph. |
| | src_proj_preprocessor.py | Parsing compilation arguments. |
| | if-else-extractor | An llvm-based tool to extract if/else features. |
| | switch-case-extractor | An llvm-based tool to extract switch/case features. |
| tools | ida_autoanalysis_70.py | An IDAPython script for extracting binary features. |
 

---------

### Setup

A Windows server with python 2.7 (64-bit) and IDA 7.0, and a Linux server with python are required.

---------

#### For Windows Server
1. install python 2.7 64-bit and add it to the PATH (IDA 7.0 need 64-bit python)

2. Install IDA 7.0 after pre-installed the VS2015 runtime library (need Win7 SP1+ or Win10)

3. Install the dependencies in python
    ```
    pefile, shutil, re
    ```

---------

#### For Linux Server

1. install python 2.7 and add it to the PATH

2. install clang-3.7

3. install the dependencies by apt-get
    ```
    python-pip build-essential python-dev liblzma-dev libev4 libev-dev dos2unix cmake
    ```

4. Install the dependencies in python
    ```
    pip install backports.lzma clang==3.7
    ```






