#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-05 08:14:53
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-05 08:15:19

#extract the opcodes for IDA SDK allins.hpp

load = {'LDbe', 'LDle'}
store = {'STbe', 'STle'}
branch = {'Ijk_Boring'}
arithmetic = {'Add32'}
cmp = {'CmpORD32S', 'CmpNE32'}
regs = {}
call = {'Ijk_Call'}
logic = {'And32'}



