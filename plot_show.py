#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-14 09:02:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-14 09:03:48

import matplotlib.pyplot as plt
from matplotlib.pyplot import plot,savefig
import numpy as np
import argparse

def plot_roc(vex_test_fpr, vex_test_tpr, test_fpr, test_tpr, DIM_7, DIM_9 = 0, lib = 'SSL'):

    plt.figure(figsize=(8,8))
    if DIM_9 == 0:
        plt.plot(vex_test_fpr, vex_test_tpr, color='red', label='Gemini-IR (dim {}) ROC'.format(DIM_7), linestyle=':')
        plt.plot(test_fpr, test_tpr, color='green', label='Gemini (dim {}) ROC'.format(DIM_7), linestyle=':')
    else:
        plt.plot(vex_test_fpr, vex_test_tpr, color='red', label='Gemini-IR (dim {}) ROC'.format(DIM_9), linestyle=':')
        plt.plot(test_fpr, test_tpr, color='green', label='Gemini IR (dim {}) ROC'.format(DIM_7), linestyle=':')

    #plt.plot([0, 1], [0, 1], 'k--', lw=lw)
    plt.tick_params(labelsize=15)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.0])
    plt.xlabel('False Positive Rate', fontsize=20)
    plt.ylabel('True Positive Rate', fontsize=20)
    #plt.title('ROC curves of {}'.format(lib))
    plt.rcParams.update({"font.size":20})
    plt.legend(loc="lower right")
    if DIM_9 == 0:
        savefig('res/' + lib + '_{}_roc.svg'.format(DIM_7), format='svg', dpi = 600)
    else:
        savefig('res/' + lib + '_{}_roc.svg'.format(DIM_9), format='svg', dpi = 600)
    plt.close()



def plot_loss(vex_loss,loss, DIM_7, DIM_9 = 0,lib = 'SSL'):

    plt.figure(figsize=(8,8))
    #x_axis = np.arange(100)
    if DIM_9 == 0:
        plt.plot(np.arange(len(vex_loss)), vex_loss, color='red', label='Gemini-IR (dim {}) loss'.format(DIM_7), linestyle='-')
        plt.plot(np.arange(len(loss)), loss, color='green', label='Gemini (dim {}) loss'.format(DIM_7), linestyle='-')

    else:
        plt.plot(np.arange(len(vex_loss)), vex_loss, color='red', label='Gemini-IR (dim {}) loss'.format(DIM_9), linestyle='-')
        plt.plot(np.arange(len(loss)), loss, color='green', label='Gemini IR (dim {}) loss'.format(DIM_7), linestyle='-')
    #plt.plot([0, 1], [0, 1], 'k--', lw=lw)
    
    plt.tick_params(labelsize=15)
    plt.xlim([0.0, 110.0])
    plt.ylim([0.4, 0.8])
    plt.xlabel('Epoch', fontsize=20)
    plt.ylabel('Loss', fontsize=20)
    #plt.title('Loss curves of {}'.format(lib))
    plt.rcParams.update({"font.size":20})
    plt.legend(loc="lower right")
    
    if DIM_9 == 0:
        savefig('res/' + lib + '_{}_loss.svg'.format(DIM_7), format='svg', dpi = 600)
    else:
        savefig('res/' + lib + '_{}_loss.svg'.format(DIM_9), format='svg', dpi = 600)
    plt.close()
    #plt.show()

def plot_auc(vex_auc, auc, DIM_7, DIM_9 = 0, lib = 'SSL'):

    plt.figure(figsize=(8,8))
    #x_axis = np.arange(100)
    if DIM_9 == 0: 
        plt.plot(np.arange(len(vex_auc)), vex_auc, color='red', label='Gemini-IR (dim {}) auc'.format(DIM_7), linestyle='-')
        plt.plot(np.arange(len(auc)), auc, color='green', label='Gemini (dim {}) auc'.format(DIM_7), linestyle='-')

    else:
        plt.plot(np.arange(len(vex_auc)), vex_auc, color='red', label='Gemini-IR (dim {}) auc'.format(DIM_9), linestyle='-')
        plt.plot(np.arange(len(auc)), auc, color='green', label='Gemini IR (dim {}) auc'.format(DIM_7), linestyle='-')
    #plt.plot([0, 1], [0, 1], 'k--', lw=lw)
    plt.tick_params(labelsize=15)
    plt.xlim([0.0, 110.0])
    plt.ylim([0.7, 1.0])
    plt.xlabel('Epoch', fontsize=20)
    plt.ylabel('AUC', fontsize=20)
    #plt.title('AUC curves of {}'.format(lib))
    plt.rcParams.update({"font.size":20})
    plt.legend(loc="lower right")
    #plt.show()
    if DIM_9 == 0:
        savefig('res/' + lib + '_{}_auc.svg'.format(DIM_7), format='svg', dpi = 600)
    else:
        savefig('res/' + lib + '_{}_auc.svg'.format(DIM_9), format='svg', dpi = 600)
    
    plt.close()


def plot_orgi_ir_7(DIM_7):

    acfgSSL_vex_test_fpr = np.load('res/acfgSSL_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgSSL_vex_test_tpr = np.load('res/acfgSSL_{}_vex_test_tpr.npy'.format(DIM_7))
    acfgSSL_test_fpr = np.load('res/acfgSSL_{}_test_fpr.npy'.format(DIM_7))
    acfgSSL_test_tpr = np.load('res/acfgSSL_{}_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgSSL_vex_test_fpr, acfgSSL_vex_test_tpr, acfgSSL_test_fpr, acfgSSL_test_tpr, DIM_7, 0, 'SSL')

    acfgSSL_vex_loss = np.load('res/acfgSSL_{}_vex_loss.npy'.format(DIM_7))
    acfgSSL_loss = np.load('res/acfgSSL_{}_loss.npy'.format(DIM_7))
    plot_loss(acfgSSL_vex_loss, acfgSSL_loss, DIM_7, 0, 'SSL')
    
    acfgSSL_vex_auc = np.load('res/acfgSSL_{}_vex_valid_auc.npy'.format(DIM_7))
    acfgSSL_auc = np.load('res/acfgSSL_{}_valid_auc.npy'.format(DIM_7))
    plot_auc(acfgSSL_vex_auc, acfgSSL_auc, DIM_7, 0, 'SSL')
 
    acfgCore_vex_test_fpr = np.load('res/acfgCore_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgCore_vex_test_tpr = np.load('res/acfgCore_{}_vex_test_tpr.npy'.format(DIM_7))
    acfgCore_test_fpr = np.load('res/acfgCore_{}_test_fpr.npy'.format(DIM_7))
    acfgCore_test_tpr = np.load('res/acfgCore_{}_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgCore_vex_test_fpr, acfgCore_vex_test_tpr, acfgCore_test_fpr, acfgCore_test_tpr, DIM_7, 0, 'Core')

    acfgCore_vex_loss = np.load('res/acfgCore_{}_vex_loss.npy'.format(DIM_7))
    acfgCore_loss = np.load('res/acfgCore_{}_loss.npy'.format(DIM_7))
    plot_loss(acfgCore_vex_loss, acfgCore_loss, DIM_7, 0, 'Core')
    
    acfgCore_vex_auc = np.load('res/acfgCore_{}_vex_valid_auc.npy'.format(DIM_7))
    acfgCore_auc = np.load('res/acfgCore_{}_valid_auc.npy'.format(DIM_7))


    plot_auc(acfgCore_vex_auc, acfgCore_auc, DIM_7, 0, 'Core')



    acfgBin_vex_test_fpr = np.load('res/acfgBin_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgBin_vex_test_tpr = np.load('res/acfgBin_{}_vex_test_tpr.npy'.format(DIM_7))
    acfgBin_test_fpr = np.load('res/acfgBin_{}_test_fpr.npy'.format(DIM_7))
    acfgBin_test_tpr = np.load('res/acfgBin_{}_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgBin_vex_test_fpr, acfgBin_vex_test_tpr, acfgBin_test_fpr, acfgBin_test_tpr, DIM_7, 0, 'Bin')

    acfgBin_vex_loss = np.load('res/acfgBin_{}_vex_loss.npy'.format(DIM_7))
    acfgBin_loss = np.load('res/acfgBin_{}_loss.npy'.format(DIM_7))
    plot_loss(acfgBin_vex_loss, acfgBin_loss, DIM_7, 0, 'Bin')
    
    acfgBin_vex_auc = np.load('res/acfgBin_{}_vex_valid_auc.npy'.format(DIM_7))
    acfgBin_auc = np.load('res/acfgBin_{}_valid_auc.npy'.format(DIM_7))


    plot_auc(acfgBin_vex_auc, acfgBin_auc, DIM_7, 0, 'Bin')

    acfgBusybox_vex_test_fpr = np.load('res/acfgBusybox_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgBusybox_vex_test_tpr = np.load('res/acfgBusybox_{}_vex_test_tpr.npy'.format(DIM_7))
    acfgBusybox_test_fpr = np.load('res/acfgBusybox_{}_test_fpr.npy'.format(DIM_7))
    acfgBusybox_test_tpr = np.load('res/acfgBusybox_{}_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgBusybox_vex_test_fpr, acfgBusybox_vex_test_tpr, acfgBusybox_test_fpr, acfgBusybox_test_tpr, DIM_7, 0, 'Busybox')

    acfgBusybox_vex_loss = np.load('res/acfgBusybox_{}_vex_loss.npy'.format(DIM_7))
    acfgBusybox_loss = np.load('res/acfgBusybox_{}_loss.npy'.format(DIM_7))
    plot_loss(acfgBusybox_vex_loss, acfgBusybox_loss, DIM_7, 0, 'Busybox')
    
    acfgBusybox_vex_auc = np.load('res/acfgBusybox_{}_vex_valid_auc.npy'.format(DIM_7))
    acfgBusybox_auc = np.load('res/acfgBusybox_{}_valid_auc.npy'.format(DIM_7))


    plot_auc(acfgBusybox_vex_auc, acfgBusybox_auc, DIM_7, 0, 'Busybox')
    
    #plt.show()


def plot_ir_7_9(DIM_9):
    
    acfgSSL_vex_test_fpr = np.load('res/acfgSSL_{}_vex_test_fpr.npy'.format(DIM_9))
    acfgSSL_vex_test_tpr = np.load('res/acfgSSL_{}_vex_test_tpr.npy'.format(DIM_9))
    DIM_7 = 7

    acfgSSL_test_fpr = np.load('res/acfgSSL_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgSSL_test_tpr = np.load('res/acfgSSL_{}_vex_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgSSL_vex_test_fpr, acfgSSL_vex_test_tpr, acfgSSL_test_fpr, acfgSSL_test_tpr, DIM_7, DIM_9, 'SSL')

    acfgSSL_vex_loss = np.load('res/acfgSSL_{}_vex_loss.npy'.format(DIM_9))
    acfgSSL_loss = np.load('res/acfgSSL_{}_vex_loss.npy'.format(DIM_7))
    plot_loss(acfgSSL_vex_loss, acfgSSL_loss, DIM_7, DIM_9, 'SSL')
    
    acfgSSL_vex_auc = np.load('res/acfgSSL_{}_vex_valid_auc.npy'.format(DIM_9))
    acfgSSL_auc = np.load('res/acfgSSL_{}_vex_valid_auc.npy'.format(DIM_7))
    plot_auc(acfgSSL_vex_auc, acfgSSL_auc, DIM_7, DIM_9, 'SSL')
 
    acfgCore_vex_test_fpr = np.load('res/acfgCore_{}_vex_test_fpr.npy'.format(DIM_9))
    acfgCore_vex_test_tpr = np.load('res/acfgCore_{}_vex_test_tpr.npy'.format(DIM_9))
    acfgCore_test_fpr = np.load('res/acfgCore_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgCore_test_tpr = np.load('res/acfgCore_{}_vex_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgCore_vex_test_fpr, acfgCore_vex_test_tpr, acfgCore_test_fpr, acfgCore_test_tpr, DIM_7, DIM_9, 'Core')

    acfgCore_vex_loss = np.load('res/acfgCore_{}_vex_loss.npy'.format(DIM_9))
    acfgCore_loss = np.load('res/acfgCore_{}_vex_loss.npy'.format(DIM_7))
    plot_loss(acfgCore_vex_loss, acfgCore_loss, DIM_7, DIM_9, 'Core')
    
    acfgCore_vex_auc = np.load('res/acfgCore_{}_vex_valid_auc.npy'.format(DIM_9))
    acfgCore_auc = np.load('res/acfgCore_{}_vex_valid_auc.npy'.format(DIM_7))
    plot_auc(acfgCore_vex_auc, acfgCore_auc, DIM_7, DIM_9, 'Core')


    acfgBin_vex_test_fpr = np.load('res/acfgBin_{}_vex_test_fpr.npy'.format(DIM_9))
    acfgBin_vex_test_tpr = np.load('res/acfgBin_{}_vex_test_tpr.npy'.format(DIM_9))
    acfgBin_test_fpr = np.load('res/acfgBin_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgBin_test_tpr = np.load('res/acfgBin_{}_vex_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgBin_vex_test_fpr, acfgBin_vex_test_tpr, acfgBin_test_fpr, acfgBin_test_tpr, DIM_7, DIM_9, 'Bin')

    acfgBin_vex_loss = np.load('res/acfgBin_{}_vex_loss.npy'.format(DIM_9))
    acfgBin_loss = np.load('res/acfgBin_{}_vex_loss.npy'.format(DIM_7))
    plot_loss(acfgBin_vex_loss, acfgBin_loss, DIM_7, DIM_9, 'Bin')
    
    acfgBin_vex_auc = np.load('res/acfgBin_{}_vex_valid_auc.npy'.format(DIM_9))
    acfgBin_auc = np.load('res/acfgBin_{}_vex_valid_auc.npy'.format(DIM_7))
    plot_auc(acfgBin_vex_auc, acfgBin_auc, DIM_7, DIM_9, 'Bin')



    acfgBusybox_vex_test_fpr = np.load('res/acfgBusybox_{}_vex_test_fpr.npy'.format(DIM_9))
    acfgBusybox_vex_test_tpr = np.load('res/acfgBusybox_{}_vex_test_tpr.npy'.format(DIM_9))
    acfgBusybox_test_fpr = np.load('res/acfgBusybox_{}_vex_test_fpr.npy'.format(DIM_7))
    acfgBusybox_test_tpr = np.load('res/acfgBusybox_{}_vex_test_tpr.npy'.format(DIM_7))
    plot_roc(acfgBusybox_vex_test_fpr, acfgBusybox_vex_test_tpr, acfgBusybox_test_fpr, acfgBusybox_test_tpr, DIM_7, DIM_9, 'Busybox')

    acfgBusybox_vex_loss = np.load('res/acfgBusybox_{}_vex_loss.npy'.format(DIM_9))
    acfgBusybox_loss = np.load('res/acfgBusybox_{}_vex_loss.npy'.format(DIM_7))
    plot_loss(acfgBusybox_vex_loss, acfgBusybox_loss, DIM_7, DIM_9, 'Busybox')
    
    acfgBusybox_vex_auc = np.load('res/acfgBusybox_{}_vex_valid_auc.npy'.format(DIM_9))
    acfgBusybox_auc = np.load('res/acfgBusybox_{}_vex_valid_auc.npy'.format(DIM_7))
    plot_auc(acfgBusybox_vex_auc, acfgBusybox_auc, DIM_7, DIM_9, 'Busybox')

    #plt.show()


if __name__ == "__main__":
    #plt.figure()
    parser = argparse.ArgumentParser()

    parser.add_argument('--fea_dim', type=int, default=7, help='feature dimension')

    args = parser.parse_args()
    DIM_7 = args.fea_dim
    
    DIM_7 = 7
    plot_orgi_ir_7(DIM_7)

    DIM_9 = 9
    plot_ir_7_9(DIM_9)
    