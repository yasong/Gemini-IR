#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2020-12-08 08:14:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2020-12-08 08:15:19

#extract the opcodes for IDA SDK allins.hpp

mips_load = {'lb','lbu','lh','lhu','lw','lwu','lwl','lwr','ld','ldl', 'ldr'}
mips_store = {'sb','sh','sw','swl','swr','sdl','sdr','sd'}
mips_branch = {'bgez','bgezl','bgtz','bgtzl','blez','blezl','bltz','bltzl', \
            'beq','beql','bne','bnel', 'bnez', 'bnezl','beqz','beqzl', 'j'}
mips_arithmetic = {'add', 'addu', 'sub', 'subu', 'slt', 'sltu', 'addi', 'addiu', 'slti', 'sltiu', \
            'clo', 'clz', 'multu', 'mult', 'mul', 'madd', 'maddu', 'msub', 'msubu', 'div', 'divu'}
mips_logic = {'and', 'or', 'xor', 'nor', 'andi', 'xori', 'ori', 'lui'}
mips_transfer = {'move'}
mips_regs = {'$zer0': 0, '$at': 1, '$v0': 2, '$v1': 3, '$a0': 4, '$a1': 5,\
            '$a2': 6, '$a3': 7, '$t0': 8, '$t1': 9, '$t2': 10, '$t3': 11,\
            '$t4': 12, '$t5': 13, '$t6': 14, '$t7': 15, '$s0': 16, '$s1': 17,\
            '$s2': 18, '$s3': 19, '$s4': 20, '$s5': 21, '$s6': 22, '$s7': 23,\
            '$t8': 24, '$t9': 25, '$k0': 26, '$k1': 27, '$gp': 28, '$sp': 29,\
            '$s8': 30, '$ra': 31}
mips_call = {'jal', 'jalr'}

arm_load = {'LDR','LDRB','LDRD','LDRT','LDRBT','LDRH','LDRSB','LDRSH','LDM'}
arm_store = {'STR','STRB','STRD','STRT','STRBT','STRH','STM'}
arm_branch = {'BEQ','BNE','BLT','BLE','BGT','BGE','BLS','BHS','BLO', 'BCS'}
arm_arithmetic = {'ADD', 'ADC', 'ADDS', 'SUB', 'SUBS', 'RSB', 'RSBS', 'SBC', \
            'RSC', "MUL", 'MLA', 'UMULL', 'UMLAL', 'SMULL', 'SMLAL'}
arm_logic = {'AND', 'ORR', 'EOR', 'BIC'}

arm_transfer = {'MOV'}
arm_call = {'BL', 'BLX'}
arm_regs = {'R0': 0, 'R1': 1, 'R2': 2, 'R3': 3, 'R4': 4, 'R5': 5,\
            'R6': 6, 'R7': 7, 'R8': 8, 'R9': 9, 'R10': 10, 'R11': 11,\
            'R12': 12, 'SP': 13, 'LR': 14, 'PC': 15}

ppc_load = {'lbz', 'lbzu', 'lbzux', 'lbzx', 'lha', 'lhau', 'lhaux', 'lhax', 'lhz', \
            'lhzu', 'lhzux', 'lhzx', 'lwz', 'lwzu', 'lwzux', 'lwzx'}
ppc_store = {'stb', 'stbu', 'stbux', 'stbx', 'sth', 'sthu', 'sthx', 
                'stw', 'stwu', 'stwux', 'stwx'}
ppc_branch = {'b', 'bne', 'beq', 'bge', 'ble', 'bgt','blt', 'bdnz'}

ppc_transfer = {'mr', 'mr.'}
ppc_call = {'bl', 'bctrl'}

ppc_regs = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4, 'r5': 5,\
            'r6': 6, 'r7': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,\
            'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15, 'r16': 16, 'r17': 17,\
            'r18': 18, 'r19': 19, 'r20': 20, 'r21': 21, 'r22': 22, 'r23': 23,\
            'r24': 24, 'r25': 25, 'r26': 26, 'r27': 27, 'r28': 28, 'r29': 29,\
            'r30': 30, 'r31': 31}

#for ppc if 'u' in the end of opcode, this means it contains a update opcode (arithmetic)

ppc_arithmetic = {'addi','addic', 'addic.', 'add.', 'add', 'subf', 'subfic', 'sub', 'subi', \
            'mulli', 'mullw', 'mulhw', 'mulhwu', 'divw', 'divwu'}
ppc_logic = {'and', 'or', 'xor', 'nand', 'nor', 'not', 'eqv', 'andc', 'orc'}
#x86_load = {'mov','movzx','movsz'}          #mov reg, {}
#x86_store = {'mov','movzx','movzx'}         #mov {}, reg

#rep movsb represents a loop with copy



x86_branch = {'ja','jae','jb','jbe','jc','jcxz','jecxz','jrcxz','je','jg','jge','jl', \
            'jle','jna','jnae','jnb','jnbe','jnc','jne','jng','jnge','jnl','jnle','jno', \
            'jnp','jns','jnz','jo','jp','jpe','jpo','js','jz'}
x86_arithmetic = {'add', 'inc', 'imul', 'mul', 'idiv', 'div', 'sub', 'adc', 'sbb', 'dec', 'neg'}
x86_transfer = {'mov','movzx','movzx'}
x86_logic = {'and', 'or', 'xor', 'not'}
x86_call = {'call'}
x86_regs = {'eax': 0, 'ebx': 1, 'ecx': 2, 'edx': 3, 'esi': 4, 'edi': 5, 'ebp': 6, 'esp': 7, 'eip': 8}

x64_load = {}
x64_stoee = {}
x64_branch = {}


