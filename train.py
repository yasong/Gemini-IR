# -*- coding: utf-8 -*-
import tensorflow as tf
print (tf.__version__)
#import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from graphnnSiamese import graphnn
from utils import *
import os
import argparse
import json
import sys

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
parser.add_argument('--load_path', type=str, default=None,
        help='path for model loading, "#LATEST#" for the latest checkpoint')
parser.add_argument('--save_path', type=str,
        default='./saved_model/graphnn-model', help='path for model saving')
parser.add_argument('--log_path', type=str, default=None,
        help='path for training log')
parser.add_argument('--lib', type=str, default='SSL',
        help='library {SSL, Bin, Core} for training')




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
    SAVE_PATH = args.save_path
    LOG_PATH = args.log_path
    LIB = args.lib

    SHOW_FREQ = 1
    TEST_FREQ = 1
    SAVE_FREQ = 5
    DATA_FILE_NAME = None
    npy_name = None
    SOFTWARE = None
    COMPILER = None
    res_name = None
    if LIB == 'SSL':
        DATA_FILE_NAME = './data/acfgSSL_{}/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgSSL_{}_{}_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgSSL_{}_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgSSL_{}/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('openssl-1.0.1f-', 'openssl-1.0.1u-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux')

    elif LIB == 'SSL_vex':
        DATA_FILE_NAME = './data/acfgSSL_{}_vex/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgSSL_{}_vex_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgSSL_{}_vex_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgSSL_{}_vex/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('openssl-1.0.1f-', 'openssl-1.0.1u-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux')
    
    elif LIB == 'Bin':
        DATA_FILE_NAME = './data/acfgBin_{}/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgBin_{}_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgBin_{}_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgBin_{}/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('binutils-2.26-', 'binutils-2.28-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    elif LIB == 'Bin_vex':
        DATA_FILE_NAME = './data/acfgBin_{}_vex/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgBin_{}_vex_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgBin_{}_vex_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgBin_{}_vex/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('binutils-2.26-', 'binutils-2.28-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    elif LIB == 'Core':
        DATA_FILE_NAME = './data/acfgCore_{}/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgCore_{}_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgCore_{}_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgCore_{}/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('coreutils-8.29-', 'coreutils-8.31-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    elif LIB == 'Core_vex':
        DATA_FILE_NAME = './data/acfgCore_{}_vex/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgCore_{}_{}_vex_'.format(NODE_FEATURE_DIM,BATCH_SIZE)
        res_name = 'res/acfgCore_{}_{}_vex_'.format(NODE_FEATURE_DIM,BATCH_SIZE)
        SAVE_PATH = './saved_model/acfgCore_{}_{}_vex/graphnn-model'.format(NODE_FEATURE_DIM, BATCH_SIZE)
        SOFTWARE=('coreutils-8.29-', 'coreutils-8.31-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    elif LIB == 'Busybox':
        DATA_FILE_NAME = './data/acfgBusybox_{}/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgBusybox_{}_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgBusybox_{}_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgBusybox_{}/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('busybox-1.23.2-', 'busybox-1.28.3-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    elif LIB == 'Busybox_vex':
        DATA_FILE_NAME = './data/acfgBusybox_{}_vex/'.format(NODE_FEATURE_DIM)
        npy_name = 'data/acfgBusybox_{}_vex_'.format(NODE_FEATURE_DIM)
        res_name = 'res/acfgBusybox_{}_vex_'.format(NODE_FEATURE_DIM)
        SAVE_PATH = './saved_model/acfgBusybox_{}_vex/graphnn-model'.format(NODE_FEATURE_DIM)
        SOFTWARE=('busybox-1.23.2-', 'busybox-1.28.3-')
        COMPILER=('armeb-linux', 'i586-linux', 'mips-linux', 'powerpc-linux')

    OPTIMIZATION=('-O0', '-O1','-O2','-O3')
 
    
    VERSION=('v54',)

    FUNC_NAME_DICT = {}

    # Process the input graphs
    F_NAME = get_f_name(DATA_FILE_NAME, SOFTWARE, COMPILER,
            OPTIMIZATION, VERSION) #根据参数拼接形成文件的完整路径及文件名
    FUNC_NAME_DICT = get_f_dict(F_NAME) #{'fname': index}
    #print(len(FUNC_NAME_DICT))

    
    Gs, classes = read_graph(F_NAME, FUNC_NAME_DICT, NODE_FEATURE_DIM)
    print ("{} graphs, {} functions".format(len(Gs), len(classes)))

    
    if os.path.isfile(npy_name + 'class_perm.npy'):
        perm = np.load(npy_name + 'class_perm.npy')
    else:
        perm = np.random.permutation(len(classes)) #随机排列一个序列，或者数组。
        np.save(npy_name + 'class_perm.npy', perm)
    if len(perm) < len(classes):
        perm = np.random.permutation(len(classes))
        np.save(npy_name + 'class_perm.npy', perm)

    Gs_train, classes_train, Gs_dev, classes_dev, Gs_test, classes_test =\
            partition_data(Gs,classes,[0.8,0.1,0.1],perm)

    print ("Train: {} graphs, {} functions".format(
            len(Gs_train), len(classes_train)))
    print ("Dev: {} graphs, {} functions".format(
            len(Gs_dev), len(classes_dev)))
    print ("Test: {} graphs, {} functions".format(
            len(Gs_test), len(classes_test)))
    #sys.exit(0)
    # Fix the pairs for validation
    if os.path.isfile(npy_name + 'valid.json'):
        with open(npy_name + 'valid.json') as inf:
            valid_ids = json.load(inf)
        valid_epoch = generate_epoch_pair(
                Gs_dev, classes_dev, BATCH_SIZE, load_id=valid_ids)
    else:
        valid_epoch, valid_ids = generate_epoch_pair(
                Gs_dev, classes_dev, BATCH_SIZE, output_id=True)
        with open(npy_name + 'valid.json', 'w') as outf:
            json.dump(valid_ids, outf)

    if os.path.isfile(npy_name + 'train.json'):
        with open(npy_name + 'train.json') as inf:
            train_ids = json.load(inf)
        train_epochs = generate_epoch_pair(
                Gs_train, classes_train, BATCH_SIZE, load_id=train_ids)
    else:
        train_epochs, train_ids = generate_epoch_pair(
                Gs_train, classes_train, BATCH_SIZE, output_id=True)
        with open(npy_name + 'train.json', 'w') as outf:
            json.dump(train_ids, outf)

    # Model
    gnn = graphnn(
            N_x = NODE_FEATURE_DIM,     # 7
            Dtype = Dtype,              #tf.float32
            N_embed = EMBED_DIM,        # 64
            depth_embed = EMBED_DEPTH,  # 2
            N_o = OUTPUT_DIM,           # 64
            ITER_LEVEL = ITERATION_LEVEL,       # 5
            lr = LEARNING_RATE          # 1e-4
        )
    gnn.init(LOAD_PATH, LOG_PATH)

    # Train
    train_auc_array = np.array([])
    valid_auc_array = np.array([])
    auc0, fpr, tpr, thres = get_auc_epoch(gnn, Gs_train, classes_train,
            BATCH_SIZE, load_data=train_epochs)
    gnn.say("Initial training auc = {0} @ {1}".format(auc0, datetime.now()))
    train_auc_array = np.append(train_auc_array, auc0)
    auc0, fpr, tpr, thres = get_auc_epoch(gnn, Gs_dev, classes_dev,
            BATCH_SIZE, load_data=valid_epoch)
    valid_auc_array = np.append(valid_auc_array, auc0)
    gnn.say("Initial validation auc = {0} @ {1}".format(auc0, datetime.now()))

    best_auc = 0
    loss = np.array([])
    train_auc_array = np.array([])
    valid_auc_array = np.array([])
    for i in range(1, MAX_EPOCH+1):
        l = train_epoch(gnn, Gs_train, classes_train, BATCH_SIZE, load_data=train_epochs)
        gnn.say("EPOCH {3}/{0}, loss = {1} @ {2}".format(
            MAX_EPOCH, l, datetime.now(), i))
        loss = np.append(loss, l)
        if (i % TEST_FREQ == 0):
            auc, fpr, tpr, thres = get_auc_epoch(gnn, Gs_train, classes_train,
                    BATCH_SIZE, load_data=train_epochs)
            gnn.say("Testing model: training auc = {0} @ {1}".format(
                auc, datetime.now()))
            train_auc_array = np.append(train_auc_array, auc)

            auc, fpr, tpr, thres = get_auc_epoch(gnn, Gs_dev, classes_dev,
                    BATCH_SIZE, load_data=valid_epoch)
            gnn.say("Testing model: validation auc = {0} @ {1}".format(
                auc, datetime.now()))
            
            valid_auc_array = np.append(valid_auc_array, auc)

            if auc > best_auc:
                path = gnn.save(SAVE_PATH+'_best')
                best_auc = auc
                gnn.say("Model saved in {}".format(path))

        if (i % SAVE_FREQ == 0):
            path = gnn.save(SAVE_PATH, i)
            gnn.say("Model saved in {}".format(path))
    
    np.save(res_name + 'loss.npy', loss)
    np.save(res_name + 'train_auc.npy', train_auc_array)
    np.save(res_name + 'valid_auc.npy', valid_auc_array)
    #np.save('res/vex_loss.npy', loss)
    #np.save('res/vex_train_auc.npy', train_auc_array)
    #np.save('res/vex_valid_auc.npy', valid_auc_array)