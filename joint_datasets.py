#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-12 10:21:23
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-12 10:22:20

import os
import sys
import glob
import argparse
import json

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--lib', type=str, default='SSL',
    help='library {SSL, Bin, Core, SSL_vex, Bin_vex, Core_vex, Busybox, Busybox_vex} for training')
    parser.add_argument('--fea_dim', type=int, default=7, help='feature dimension')

    args = parser.parse_args()
    LIB = args.lib
    NODE_FEATURE_DIM = args.fea_dim
    PARENT_PATH = ''
    DST_PATH = ''
    if LIB == 'SSL':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\openssl_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgSSL_{}\\".format(NODE_FEATURE_DIM)

    elif LIB == 'SSL_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\openssl_vex_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgSSL_{}_vex\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Bin':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\binutils_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBin_{}\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Bin_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\binutils_vex_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBin_{}_vex\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Core':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\coreutils_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgCore_{}\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Core_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\coreutils_vex_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgCore_{}_vex\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Busybox':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\busybox_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBusybox_{}\\".format(NODE_FEATURE_DIM)

    elif LIB == 'Busybox_vex':
        PARENT_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\busybox_vex_feas_{}\\*".format(NODE_FEATURE_DIM))
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBusybox_{}_vex\\".format(NODE_FEATURE_DIM)


    for PATH in PARENT_PATH:
        FILE_PATH = glob.glob(PATH + '\\*')
        out_file_name = PATH.split('\\')[-1] + '.json'
        fullpath = os.path.join(DST_PATH, out_file_name)
        out = open(fullpath,"w")
        name_set = set()
        for f_name in FILE_PATH:
            with open(f_name) as inf:
                for line in inf:
                    g_info = json.loads(line.strip())
                    if g_info['fname'] not in name_set:
                        name_set.add(g_info['fname'])
                        if 'sub_' in line.strip():
                            continue
                        print(line.strip(), file = out)
                    else:
                        continue
        out.close()
