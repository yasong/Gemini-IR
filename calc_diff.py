#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-26 20:14:46
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-26 20:15:02

import tensorflow as tf
print (tf.__version__)
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from graphnnSiamese import graphnn
from utils import *
#from plot_show import *
import os
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('--device', type=str, default='0',
        help='visible gpu device')
parser.add_argument('--fea_dim', type=int, default=7,
        help='feature dimension')
parser.add_argument('--embed_dim', type=int, default=64,
        help='embedding dimension')
parser.add_argument('--embed_depth', type=int, default=2,
        help='embedding network depth')
parser.add_argument('--output_dim', type=int, default=64,
        help='output layer dimension')
parser.add_argument('--iter_level', type=int, default=5,
        help='iteration times')
parser.add_argument('--lr', type=float, default=1e-4,
        help='learning rate')
parser.add_argument('--epoch', type=int, default=100,
        help='epoch number')
parser.add_argument('--batch_size', type=int, default=5,
        help='batch size')
parser.add_argument('--load_path', type=str,
        default='./saved_model/acfgBin_7_vex/graphnn-model_best',
        help='path for model loading, "#LATEST#" for the latest checkpoint')
parser.add_argument('--log_path', type=str, default=None,
        help='path for training log')
parser.add_argument('--lib', type=str, default='SSL',
        help='library {SSL, Bin, Core, SSL_vex, Bin_vex, Core_vex, Busybox, Busybox_vex} for training')



if __name__ == '__main__':
    args = parser.parse_args()
    args.dtype = tf.float32
    print("=================================")
    print(args)
    print("=================================")

    os.environ["CUDA_VISIBLE_DEVICES"]=args.device
    Dtype = args.dtype
    NODE_FEATURE_DIM = args.fea_dim
    EMBED_DIM = args.embed_dim
    EMBED_DEPTH = args.embed_depth
    OUTPUT_DIM = args.output_dim
    ITERATION_LEVEL = args.iter_level
    LEARNING_RATE = args.lr
    MAX_EPOCH = args.epoch
    BATCH_SIZE = args.batch_size
    LOAD_PATH = args.load_path
    LOG_PATH = args.log_path
    LIB = args.lib

    SHOW_FREQ = 1
    TEST_FREQ = 1
    SAVE_FREQ = 5
    DATA_FILE_NAME = None
    npy_name = None
    res_name = None
    SOFTWARE = None
    COMPILER = None
    #FILE_NAME = "test_diff.json"
    FILE_NAME = "test_diff_vex.json"
    Gs= read_two_graph(FILE_NAME)
    print ("{} functions".format(Gs[0].label))


    # Model
    gnn = graphnn(
            N_x = NODE_FEATURE_DIM,
            Dtype = Dtype, 
            N_embed = EMBED_DIM,
            depth_embed = EMBED_DEPTH,
            N_o = OUTPUT_DIM,
            ITER_LEVEL = ITERATION_LEVEL,
            lr = LEARNING_RATE
        )
    gnn.init(LOAD_PATH, LOG_PATH)
    total_simi = 0
    total_diff = 0
    test = []
    # Pairwise comparison
    for i in range(len(Gs)):
        for j in range(i+1, len(Gs)):
            test = []
            test.append(Gs[i])
            test.append(Gs[j])
            simi, diff = get_diff(gnn, test)
            total_simi += simi
            total_diff += diff
    print(total_simi, total_diff)
