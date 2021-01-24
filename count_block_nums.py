#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-22 18:10:54
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-22 18:11:23

import glob
import sys
import json
import argparse
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.pyplot import plot,savefig


def read_graph(FILE_JSON):
    nums_dict = {}
    MAX_NUM = 0
    for f_name in FILE_JSON:
        with open(f_name) as inf:
            for line in inf:
                g_info = json.loads(line.strip())
                n_nums = g_info['n_num']
                if MAX_NUM < n_nums:
                    MAX_NUM = n_nums
                if n_nums not in nums_dict:
                    nums_dict[n_nums] = 1
                else:
                    nums_dict[n_nums] += 1

    np_nums = np.zeros((MAX_NUM), dtype = int)

    for i in range(MAX_NUM):
        if i in nums_dict:
            np_nums[i] = nums_dict[i]

    return MAX_NUM, np_nums

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    '''
    parser.add_argument('--lib', type=str, default='SSL',
    help='library {SSL, Bin, Core, SSL_vex, Bin_vex, Core_vex} for training')
    '''
    parser.add_argument('--fea_dim', type=int, default=7, help='feature dimension')

    args = parser.parse_args()
    LIB = args.lib
    NODE_FEATURE_DIM = args.fea_dim
    PARENT_PATH = ''
    SRC_PATH = ''

    '''
    if LIB == 'SSL':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgSSL_{}\\*".format(NODE_FEATURE_DIM)

    elif LIB == 'SSL_vex':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgSSL_{}_vex\\*".format(NODE_FEATURE_DIM)

    elif LIB == 'Bin':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBin_{}\\*".format(NODE_FEATURE_DIM)

    elif LIB == 'Bin_vex':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBin_{}_vex\\*".format(NODE_FEATURE_DIM)

    elif LIB == 'Core':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgCore_{}\\*".format(NODE_FEATURE_DIM)

    elif LIB == 'Core_vex':
        SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgCore_{}_vex\\*".format(NODE_FEATURE_DIM)
    '''

    SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgSSL_{}_vex\\*".format(NODE_FEATURE_DIM)
    
    FILE_JSON = glob.glob(SRC_PATH)
    MAX_NUM_SSL, ssl_np_nums = read_graph(FILE_JSON)

    
    

    SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgBin_{}_vex\\*".format(NODE_FEATURE_DIM)
    FILE_JSON = glob.glob(SRC_PATH)
    MAX_NUM_BIN, bin_np_nums = read_graph(FILE_JSON)

    SRC_PATH = "G:\\Projects\\Similarity\\Gemini-IR\\data\\acfgCore_{}_vex\\*".format(NODE_FEATURE_DIM)
    FILE_JSON = glob.glob(SRC_PATH)
    MAX_NUM_CORE, core_np_nums = read_graph(FILE_JSON)

    plt.figure(figsize=(8,8))
    #x_axis = np.arange(100)
    
    plt.axes(xscale = "log", yscale = "log")
    #plt.axes()
    plt.plot(np.arange(MAX_NUM_SSL), ssl_np_nums, color='red', label='{} basic-block numbers distributed'.format('openssl'), linestyle='-')
    plt.plot(np.arange(MAX_NUM_BIN), bin_np_nums, color='green', label='{} basic-block numbers distributed'.format('binutils'), linestyle='-')
    plt.plot(np.arange(MAX_NUM_CORE), core_np_nums, color='blue', label='{} basic-block numbers distributed'.format('coreutils'), linestyle='-')


    #plt.plot([0, 1], [0, 1], 'k--', lw=lw)
    plt.tick_params(labelsize=15)
    plt.xlim([1, MAX_NUM_SSL+20])
    plt.ylim([10, max(ssl_np_nums.max(), bin_np_nums.max(), core_np_nums.max()) + 100])
    plt.xlabel('Basic-block Number (log)', fontsize=20)
    plt.ylabel('Times (log)', fontsize=20)


    plt.rcParams.update({"font.size":15})
    plt.legend(loc="upper right")
    #plt.show()
    savefig('res/' + 'all' + '_distr.svg', format='svg', dpi = 600)


    
