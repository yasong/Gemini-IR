#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2020-12-08 17:21:45
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2020-12-08 17:22:17

from idautils import *
import idaapi
from idaapi import *
from idc import *
from opcodes import *


def get_unified_funcname(ea): # 得到统一形式的functionName
    funcname = get_func_name(ea)
    if len(funcname) > 0:
        if '.' == funcname[0]:
            funcname = funcname[1:]
    return funcname


def get_all_succs_func(funcea):
    func = idaapi.get_func(funcea)
    curr_name = get_func_name(funcea)
    ea = func.start_ea
    succs = []
    succs_name = []
    while ea < func.end_ea:
        for ref in CodeRefsFrom(ea, False):
            succs.append(ref)
        
        ea = next_head(ea)
    for ea in succs:

        func_name = get_func_name(ea)
        if func_name != curr_name:
            succs_name.append(func_name)
    #for name in succs_name:
    #    print(name)
    return succs_name


def get_features():
    binary_name = get_root_filename()
    '''
    if "clang" in binary_name:      #下列函数在clang编译后直接调用的memcpy
        copy_funcs_name.remove('strncpy')
        copy_funcs_name.remove('memccpy')
        copy_funcs_name.remove('strcat')
        copy_funcs_name.remove('strncat')
        copy_funcs_name.remove('strcpy')
        copy_funcs_name.remove('wmemcpy')
    '''
    print("binary name: %s" % binary_name)
    funcs_features = []
    segm = idaapi.get_segm_by_name(".text")
    for funcea in Functions(segm.start_ea,segm.end_ea):
        func = idaapi.get_func(funcea) # get function object
        funcname = get_func_name(funcea)

        if 'sub_' in funcname:
            continue

        #if funcname.startswith("_"):
        #    continue
        
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
        features = get_func_features(func, blocks)  # get function features and successor and so on.
        funcs_features.append(features)

    return funcs_features

def get_insts_set():

    loads = set()
    stores = set()
    branch = set()
    arithmetic = set()
    transfer = set()
    call = set()

    loads.update(mips_load)
    loads.update(arm_load)
    loads.update(ppc_load)

    stores.update(mips_store)
    stores.update(arm_store)
    stores.update(ppc_store)

    branch.update(mips_branch)
    branch.update(arm_branch)
    branch.update(ppc_branch)
    #branch.update(x86_branch)

    arithmetic.update(mips_arithmetic)
    arithmetic.update(ppc_arithmetic)
    arithmetic.update(arm_arithmetic)
    arithmetic.update(x86_arithmetic)

    transfer.update(mips_transfer)
    transfer.update(arm_transfer)
    transfer.update(ppc_transfer)
    transfer.update(x86_transfer)

    call.update(mips_call)
    call.update(arm_call)
    call.update(ppc_call)
    call.update(x86_call)

    return loads, stores, branch, arithmetic, transfer, call


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

def get_inst_num(ea):
    opcode = print_insn_mnem(ea)

    return opcode

def get_ea_constant_str_nums(ea):
    const_nums = 0
    str_nums = 0
    for i in range(3):
        
        if get_operand_type(ea, i) == idaapi.o_imm: #0x5
            addr = get_operand_value(ea, i)
            if get_segm_name(addr) == '.rodata':
                if get_str_type(addr) == 0x0 and i == 1:
                    str_nums = 1
                elif get_str_type(ida_bytes.get_dword(addr)) == 0x0 and i == 1:
                    str_nums = 1
            else:
                const_nums += 1
    disasm = generate_disasm_line(ea, 0)
    if 'esp' in disasm or 'SP' in disasm or 'sp' in disasm:
        const_nums = 0
        str_nums = 0

    return const_nums, str_nums

def get_func_features(func, blocks):
    #blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    features = {}
    succs = []
    func_feas = []
    feas = [0] * 7 #fea[0] lw, fea[1] st, fea[2] offsprings, fea[3] reg num, fea[4] add
    '''
    1. No. of Numeric Constants
    2. No. of String Constants
    3. No. of offspring
    4. No. of Arithmetic Instructions
    5. No. of Calls
    6. No. of Instructions
    7. No. of Transfer Instructions
    '''
    flag = 0
    arch = idaapi.get_inf_structure().procName.lower()
    loads = set()
    stores = set()
    branch = set()
    succs_name = []
    arithmetic = set()
    transfer = set()
    call = set()
    regs = set()

    loads, stores, branch, arithmetic, transfer, call = get_insts_set()

    funcname = get_func_name(func.start_ea)
    '''
    if funcname in copy_funcs_name:
        succs_name = get_all_succs_func(func.start_ea)
        if "memcpy" in succs_name or "strcpy" in succs_name:
            flag = 0
        else:
            flag = 1
    else:
        flag = 0
    '''
    

    for bb in blocks:
        bb_start = bb[0]
        bb_end = bb[1]    #指向当前块结束的下一个位置
        feas = [0] * 7 #fea[0] lw, fea[1] st, fea[2] offspring, fea[3] reg num, fea[4] add 计算offspring
        ea = bb_start

        regs = set()
        while ea < bb_end:
            opcode = print_insn_mnem(ea)
            feas[5] += 1

            const_nums, str_nums = get_ea_constant_str_nums(ea)
            feas[0] += const_nums
            feas[1] +=  str_nums
            if opcode in transfer:
                feas[3] += 1

            elif opcode in call:
                feas[4] += 1

            elif opcode in arithmetic:
                feas[6] += 1

            ea = next_head(ea)

        func_feas.append(feas)
    succs = get_block_succs(blocks)
    offspring_feas = get_offspring(succs)
    for i in range(len(offspring_feas)):
        func_feas[i][2] = offspring_feas[i]
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


if __name__ == "__main__":
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
    #funcname = get_unified_funcname(ea)

    
    #if funcname.startswith("_"):
    #    continue
        
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    new_blocks = []

    #some function has tail function call.
    # clang-3.9.1-O0-arm.idb strcpy [(0x7969c, 0x796c4), (0x7afb0, 0x7afb0)]
    for bb in blocks:
        if is_inBlock(bb[0], func.start_ea, func.end_ea) and is_inBlock(bb[1], func.start_ea, func.end_ea + 1):
            new_blocks.append(bb)
    blocks = new_blocks
    features = get_func_features(func, blocks)  # get function features and successor and so on.
    print(features["features"])