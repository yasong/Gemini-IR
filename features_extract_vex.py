#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-09 16:32:06
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-09 16:32:50


import os
import sys
import idaapi

from idaapi import *
from idc import *
from idautils import *
import pyvex.stmt
import pyvex.expr
import pyvex

def show_log(info, level = 'INFO'):
    timestr = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    msg = level + ': ' + timestr + ' ' + info
    print(msg)

def get_store_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        #irsb.pp()
        for _, stmt in enumerate(irsb.statements):
            if 'STle' in str(stmt) or 'STbe' in str(stmt):
                nums += 1
    return nums

def get_load_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        for _, stmt in enumerate(irsb.statements):
            if 'LDle' in str(stmt) or 'LDbe' in str(stmt):
                nums += 1

    return nums

def get_arith_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        for _, stmt in enumerate(irsb.statements):
            if 'Add32' in str(stmt) or 'Sub32' in str(stmt) or 'Shr32' in str(stmt) or 'Shl32' in str(stmt):
                nums += 1
    return nums

#extract this info for IDA Pro
def get_constant_nums(bb_irsb):
    num_list = []
    _, num_list = get_strings_contants(bb_irsb)
    nums = len(num_list)

    return nums

def get_strings_contants(bb_irsb):
    strings = []
    num_list = []
    #show_log("string constants")
    addr_set = set()
    for irsb in bb_irsb:
        for ea in irsb.constants:
            addr_set.add(ea)
    addr_list = list(addr_set)
    for ea in addr_list:
        func = idaapi.get_func(bb_irsb[0].addr)
        if func != None and func.start_ea <= ea._value and ea._value < func.end_ea:
            continue
        byte = ida_bytes.get_dword(ea._value)
        if get_str_type(ea._value) == 0x0:
            strings.append(get_strlit_contents(ea._value))
            #print(strings)
        elif get_str_type(byte) == 0x0:
            strings.append(get_strlit_contents(byte))
        else:
            num_list.append(ea)
    return strings, num_list

#extract this info for IDA Pro
def get_strings(bb_irsb):

    strings, _ = get_strings_contants(bb_irsb)

    return strings

def get_strings_nums(bb_irsb):
    strings = []
    strings, _ = get_strings_contants(bb_irsb)
    nums = len(strings)

    return nums

def get_calls_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        if 'Ijk_Call' in irsb.jumpkind:
            nums += 1

    return nums

def get_offspring(succs):
    nodes = [i for i in range(len(succs))]
    offspring_fea = []
    for node in nodes:
        offsprings = {}
        recu_offspring(succs, node, offsprings)
        offspring_fea.append(len(offsprings))
    return offspring_fea

def recu_offspring(succs, node, offsprings):
	node_offs = 0
	sucs = succs[node]
	for suc in sucs:
		if suc not in offsprings:
			offsprings[suc] = 1
			recu_offspring(succs, suc, offsprings)


def get_block_offspring_nums(node, succs):
    nums = 0
    offsprings = {}
    recu_offspring(succs, node, offsprings)
    nums = len(offsprings)
    return nums

def get_transfer_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        
        for _, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.stmt.Put):
                stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
                #print(str(stmt_str))
                if 'cc' not in stmt_str and 'ip' not in stmt_str and 'lr' not in stmt_str and \
                    'ia' not in stmt_str and 'pc' not in stmt_str and 'sp' not in stmt_str and \
                        'gpr0' not in stmt_str and '(gp)' not in stmt_str and 'ra' not in stmt_str and \
                            'gpr1' not in stmt_str:
                    nums += 1

    return nums

def get_inst_nums(bb_irsb):
    nums = 0
    for irsb in bb_irsb:
        for _, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.stmt.Put):
                stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
                if 'cc' not in stmt_str and 'ip' not in stmt_str  and 'gpr1' not in stmt_str and \
                    'ia' not in stmt_str and 'pc' not in stmt_str and 'sp' not in stmt_str and \
                        'gpr0' not in stmt_str and '(gp)' not in stmt_str and 'ra' not in stmt_str and \
                            'lr' not in stmt_str:
                    nums += 1
            elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
                stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
                if 'sp' not in stmt_str and 'gpr1' not in stmt_str:
                    nums += 1
            elif 'IMark' not in str(stmt) and 'calculate_flag' not in str(stmt) and 'to' not in str(stmt):
                nums += 1
    return nums

def get_block_features(bb_irsb, node, succs):
    features = []
    features.append(get_store_nums(bb_irsb))
    features.append(get_load_nums(bb_irsb))
    features.append(get_constant_nums(bb_irsb))
    features.append(get_strings_nums(bb_irsb))
    features.append(get_calls_nums(bb_irsb))
    features.append(get_block_offspring_nums(node, succs))
    features.append(get_transfer_nums(bb_irsb))
    features.append(get_inst_nums(bb_irsb))
    features.append(get_arith_nums(bb_irsb))

    return features

def get_block_features_gemini(bb_irsb, node, succs):
    features = []
    
    features.append(get_constant_nums(bb_irsb))
    features.append(get_strings_nums(bb_irsb))
    features.append(get_block_offspring_nums(node, succs))
    features.append(get_transfer_nums(bb_irsb))
    features.append(get_calls_nums(bb_irsb))
    features.append(get_inst_nums(bb_irsb))
    features.append(get_arith_nums(bb_irsb))

    return features
