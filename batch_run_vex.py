#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2020-12-08 16:49:44
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2020-12-08 16:53:03

import os
import sys
import subprocess
import glob
import time
from  multiprocessing import Pool

from functools import partial

import argparse


def list_split(items, n):
    nums = len(items)
    res = []
    step = nums // n
    if nums % n == 0:
        return [items[i:i+step] for i in range(0, len(items), step)]
    else:
        for i in range(n - 1):
            res.append(items[i*step: (i+1) * step])
        #res = [items[i:i+step] for i in range(0, len(items) - step, step)]
        res.append(items[(n-1)*step:])
        return res


def launch_ida(ELF_PATH, SCRIPT):
    IDA_PATH = "idat.exe"
    #print(SCRIPT)
    i = 0
    for elf in ELF_PATH:
        if elf.endswith(".idb") or elf.endswith(".id0") or elf.endswith(".id1") or elf.endswith(".id2") \
            or elf.endswith(".nam") or  elf.endswith(".til"):
            continue
        CMD = IDA_PATH + ' -A -S' + SCRIPT + ' ' + elf
        print("IDA CMD: %s" % CMD)
        print("[+] Analyzing %dth: %s" % (i, elf))
        os.system(CMD)
        i = i + 1
    #if i > 10:
    #    break



if __name__ == "__main__":
    #freeze_support()
    parser = argparse.ArgumentParser()


    parser.add_argument('--lib', type=str, default='SSL',
    help='library {SSL, Bin, Core, SSL_vex, Bin_vex, Core_vex} for training')
    parser.add_argument('--dele', type=int, default=1,
    help='0 or 1 for deling target path')
    parser.add_argument('--fea_dim', type=int, default=7, help='feature dimension')

    args = parser.parse_args()
    LIB = args.lib
    NODE_FEATURE_DIM = args.fea_dim
    PARENT_PATH = ''
    DST_PATH = ''
    SCRIPT_PATH = ''
    ELF_PATH = []
    type_in = open('type.temp', 'w')
    print(LIB + '_{}'.format(NODE_FEATURE_DIM), file = type_in)
    type_in.close()
    if LIB == 'SSL':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\openssl\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\openssl_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida.py"

    elif LIB == 'SSL_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\openssl\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\openssl_vex_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida_vex.py"

    elif LIB == 'Bin':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\binutils\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\binutils_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida.py"

    elif LIB == 'Bin_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\binutils\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\binutils_vex_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida_vex.py"

    elif LIB == 'Core':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\coreutils\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\coreutils_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida.py"

    elif LIB == 'Core_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\coreutils\\*")
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\coreutils_vex_feas_{}\\".format(NODE_FEATURE_DIM)
        SCRIPT_PATH = "preprocessing_ida_vex.py"

    for PATH in PARENT_PATH:
        ELF_PATH = ELF_PATH + glob.glob(PATH +'\\*')

    core_num = 6
    start = 0
    i = 0
    #multi threads
    
    TARGET_PATH = glob.glob(DST_PATH + '*')
    #print(TARGET_PATH)
    #print(DST_PATH)
    #sys.exit(0)
    if args.dele != 0:
        for path in TARGET_PATH:
            #print(path)
            os.system("del /q " + path + '\\' + "*.json")
    
    #sys.exit(0)
    ELF_PATH_MUL = list_split(ELF_PATH, core_num)
    #print(len(ELF_PATH))
    #print(len(ELF_PATH_MUL))
    pool = Pool(core_num)
    #for i in range(core_num):
    pool.map(partial(launch_ida, SCRIPT = SCRIPT_PATH), ELF_PATH_MUL)
        
    pool.close()
    pool.join()
    
    '''
    for elf in ELF_PATH:
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\features_vex\\"
        if elf.endswith(".idb") or elf.endswith(".id0") or elf.endswith(".id1") or elf.endswith(".id2") \
            or elf.endswith(".nam") or  elf.endswith(".til"):
            continue
        CMD = IDA_PATH + ' -A -S' + SCRIPT_PATH + ' ' + elf
        print("IDA CMD: %s" % CMD)
        print("[+] Analyzing %dth: %s" % (start, elf))
        temp = elf.split('\\')
        path = temp[-3] + '-' + temp[-2]
        DST_PATH = DST_PATH + path + '\\'
        FLAG = False
        if start>=core_num:
            try:
                finish = len(os.listdir(DST_PATH))
                if finish == 0 and FLAG == True:
                    start = 0
                    FLAG = False
            except:
                os.mkdir(DST_PATH)
                start = 0
                finish = 0
            i = 0
            if finish > 0:
                FLAG = True
            while start - core_num >= finish:
                time.sleep(1)
                finish = len(os.listdir(DST_PATH))
                i += 1
                if i > 10:
                    start = finish
                    break

        subprocess.Popen(CMD, shell = True)
        start = start + 1
    '''
    '''
    #single thread
    IDA_PATH = "idat.exe"
    SCRIPT_PATH = "preprocessing_ida_vex.py"
    for elf in ELF_PATH:
        if elf.endswith(".idb") or elf.endswith(".id0") or elf.endswith(".id1") or elf.endswith(".id2") \
            or elf.endswith(".nam") or  elf.endswith(".til"):
            continue
        CMD = IDA_PATH + ' -A -S' + SCRIPT_PATH + ' ' + elf
        print("IDA CMD: %s" % CMD)
        print("[+] Analyzing %dth: %s" % (i, elf))
        os.system(CMD)
        i = i + 1
        break
        #if i > 10:
        #    break
    '''
    