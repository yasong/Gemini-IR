#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-05 19:45:37
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-05 20:10:05
from idautils import *
import idaapi
from idaapi import *
from idc import *

import os
import sys
import time
import copy
import archinfo
import pyvex
from archinfo import Endness
from elementals import Logger
import logging
import networkx as nx

from features_extract_vex import *



def get_vex_arch():
    inst_arch = None
    arch = idaapi.get_inf_structure().procName.lower()
    if arch in 'mipsb':
        inst_arch = archinfo.ArchMIPS32(Endness.BE) #"Iend_BE"
    elif arch in 'mipsl':
        inst_arch = archinfo.ArchMIPS32(Endness.LE) #Iend_LE
    elif arch in 'ppc':
        inst_arch = archinfo.ArchPPC32(Endness.BE)
    elif arch in 'ppcl':
        inst_arch = archinfo.ArchPPC32(Endness.LE)
    elif arch in 'arm':
        inst_arch = archinfo.ArchARM(Endness.LE)
    elif arch in 'armb':
        inst_arch = archinfo.ArchARM(Endness.BE)    
    elif arch in 'metapc':
        inst_arch = archinfo.ArchX86()
    return inst_arch

def is_inBlock(ea, start, end):
    if ea >= start and ea < end:
        return True
    else:
        return False

def get_block_succs(blocks):
    succs = []
    for i in range(len(blocks)):
        succs.append([])

    for i in range(len(blocks)):

        bb_start = blocks[i][0]
        refs = CodeRefsTo(bb_start, 1)      #1：include the normal flow
        for ref in refs:
            for j in range(len(blocks)):
                if is_inBlock(ref, blocks[j][0], blocks[j][1]):
                    succs[j].append(i)

    return succs
def get_func_vex_block(ea):
    '''
    @input: address
    @return: the list of function irsb
    '''
    func = idaapi.get_func(ea)
    func_name = get_func_name(ea)
    #show_log("getting function: '%s' ir..." % func_name)
    #func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
    blocks = [v for v in idaapi.FlowChart(func)]
    #print("0x%x - 0x%x" % (func.start_ea, func.end_ea))

    inst_arch = get_vex_arch()
    func_irsb = []
    for bb in blocks:
        bb_start = bb.start_ea
        bb_end = bb.end_ea
        while bb_start < bb_end:
            block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
            irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
            func_irsb.append(irsb)
            bb_start = bb_start + irsb.size
    return func_irsb

def get_func_vex_whole(ea):
    '''
    @input: address
    @return: the irsb of whole function
    '''
    func = idaapi.get_func(ea)
    func_name = get_func_name(ea)
    show_log("getting function: '%s' ir..." % func_name)
    #func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
    blocks = [v for v in idaapi.FlowChart(func)]
    print("0x%x - 0x%x" % (func.start_ea, func.end_ea))
    new_blocks = []

    for bb in blocks:
        if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
            new_blocks.append(bb)
    blocks = new_blocks
    
    inst_arch = get_vex_arch()
    func_irsb = pyvex.IRSB(None, func.start_ea, arch = inst_arch)
    for bb in blocks:
        bb_start = bb.start_ea
        bb_end = bb.end_ea
        while bb_start < bb_end:
            block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
            irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
            func_irsb.extend(irsb)
            bb_start = bb_start + irsb.size
    return func_irsb

def get_block_vex_list(bb_start, bb_end):
    '''
    @input: block start address, block end address
    @return: the list of block irsb
    '''

    #show_log("getting block: '0x%x - 0x%x' ir..." % (bb_start, bb_end))
    #func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)

    inst_arch = get_vex_arch()
    bb_irsb = []
    segm = idaapi.get_segm_by_name(".text")
    if bb_end > segm.end_ea:
        return bb_irsb

    #show_log("block vex : 0x%x - 0x%x" % (bb_start, bb_end))
    while bb_start < bb_end:
        block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
        irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
        bb_irsb.append(irsb)
        if irsb.size == 0:
            bb_start = next_head(bb_start)
        else:
            bb_start = bb_start + irsb.size
    return bb_irsb

#some instruction are implicit branch instruction, for example, in x86: rep movsb
def get_block_vex_whole(bb_start, bb_end):
    '''
    @input: block start address, block end address
    @return: the irsb of whole block
    '''

    show_log("getting block: '0x%x - 0x%x' ir..." % (bb_start, bb_end))
    #func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)

    inst_arch = get_vex_arch()
    bb_irsb = pyvex.IRSB(None, bb_start, arch = inst_arch)
    while bb_start < bb_end:
        block_bytes = ida_bytes.get_bytes(bb_start, bb_end - bb_start)
        irsb = pyvex.IRSB(block_bytes, mem_addr = bb_start, arch = inst_arch, opt_level = 1,strict_block_end= True)
        bb_irsb.extend(irsb)
        bb_start = bb_start + irsb.size
    return bb_irsb


def get_bin_features(dims):
    binary_name = get_root_filename()

    #print("binary name: %s" % binary_name)
    funcs_features = []
    segm = idaapi.get_segm_by_name(".text")
    for funcea in Functions(segm.start_ea,segm.end_ea):
        func = idaapi.get_func(funcea) # get function object
        funcname = get_func_name(funcea)
        if 'sub_' in funcname:
            continue
        #show_log("%s" % funcname)
        blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
        new_blocks = []

        #some function has tail function call.
        # clang-3.9.1-O0-arm.idb strcpy [(0x7969c, 0x796c4), (0x7afb0, 0x7afb0)]
        for bb in blocks:
            if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
                new_blocks.append(bb)
        blocks = new_blocks
        if len(blocks) > 200:
            continue
        try:
            features = get_func_features(func, blocks, dims)  # get function features and successor and so on.
            funcs_features.append(features)
        except:
            continue

    return funcs_features

def get_func_features(func, blocks, dims):
    #func_irsb = []
    #show_log("Getting function vex features...")
    func_feas = []
    features = {}
    funcname = get_func_name(func.start_ea)
    node = 0
    succs = get_block_succs(blocks)
    for bb in blocks:
        #show_log("Getting block vex features...")
        bb_irsb = get_block_vex_list(bb[0], bb[1])
        #func_feas.append(get_block_features(bb_irsb, node, succs))
        if dims == 7:
            func_feas.append(get_block_features_gemini(bb_irsb, node, succs))
        elif dims == 9:
            func_feas.append(get_block_features(bb_irsb, node, succs))
        node += 1
        #for irsb in bb_irsb:
        #    func_irsb.append(irsb)
    
    path = get_input_file_path()
    #outdir = path.split('\\')[-3] + '-' + path.split('\\')[-2]
    outdir = path.split('\\')[-2]
    binary_name = get_root_filename() + '.txt'

    features["src"] = outdir + '/' + binary_name
    features["n_num"] = len(blocks)
    features["succs"] = succs
    features["features"] = func_feas
    features["fname"] = funcname

    return features

def main():
    func_irsb = []
    ea = get_screen_ea()
    features = []
    '''
    func_irsb = get_func_vex_block(ea)
    for irsb in func_irsb:
        print(irsb)
    func_irsb = get_func_vex_whole(ea)
    print(func_irsb)
    '''

    func = idaapi.get_func(ea)
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    new_blocks = []
    for bb in blocks:
            if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
                new_blocks.append(bb)
    blocks = new_blocks
    node = 0
    succs = get_block_succs(blocks)
    for bb in blocks:
        bb_irsb = get_block_vex_list(bb[0], bb[1])
        #print(type(bb_irsb))
        features.append(get_block_features_gemini(bb_irsb, node, succs))
        node += 1
        for irsb in bb_irsb:
            func_irsb.append(irsb)
    for irsb in func_irsb:
        #irsb.pp()
        #print(irsb.statements)
        print(irsb)
    if len(blocks) < len(func_irsb):
        show_log("Found implicit 'branch' instruction...")
    print(features)
    '''
    func = idaapi.get_func(ea)
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    for bb in blocks:
        bb_irsb = get_block_vex_whole(bb[0], bb[1])
        func_irsb.append(bb_irsb)
    for irsb in func_irsb:
        #print(irsb.statements)
        print(irsb)
    '''
    
if __name__ == '__main__':
    main()