#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2020-12-08 16:44:19
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2020-12-08 16:44:45

from idc import *
from idaapi import *
from idautils import *
import json
import argparse
import sys
sys.path.append("G:\\Projects\\Similarity\\Gemini-IR\\")

import os
from features_get import *

import ida_pro

if __name__ == '__main__':
    # auto_wait()
    segstart = get_first_seg()
    segend = get_segm_end(segstart)
    
    while True:
        plan_and_wait(segstart, segend)
        segstart = get_next_seg(segstart)
        segend = get_segm_end(segstart)
        if segend == BADADDR:
            break
    type_in = open('type.temp', 'r')
    LIB = type_in.readline().strip()
    fea_dim = int(LIB.split('_')[-1])
    LIB = LIB.strip('_{}'.format(fea_dim))
    type_in.close()
    DST_PATH = ''
    if LIB == 'SSL':
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\openssl_feas_{}\\".format(fea_dim)

    elif LIB == 'Bin':
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\binutils_feas_{}\\".format(fea_dim)

    elif LIB == 'Core':
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\coreutils_feas_{}\\".format(fea_dim)

    elif LIB == 'Busybox':
        DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\busybox_feas_{}\\".format(fea_dim)


        # args = parse_command()
        # path = args.path
    # DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\binutils_feas\\"
    #DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\coreutils_feas\\"
    # DST_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\openssl_feas\\"

    analysis_flags = get_inf_attr(idc.INF_AF)  # 得到analysis_flags  INF_AF
    analysis_flags &= ~AF_IMMOFF  # AF_IMMOFF ：将32位的指令操作转换为偏移量
    # turn off "automatically make offset" heuristic
    idc.set_inf_attr(INF_AF, analysis_flags)  # 设置analysis_flags
    list_res = get_features()
    path = get_input_file_path()
    os.chdir(DST_PATH)
    outdir = path.split('\\')[-2]
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    DST_PATH = DST_PATH + outdir + '\\'
    binary_name = get_root_filename() + '.json'
    fullpath = os.path.join(DST_PATH, binary_name)
    out = open(fullpath, "w")
    for res in list_res:
        res = str(res).replace('\'', '\"')
        print(res, file=out)

    out.close()
    ida_pro.qexit(0)
