#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-26 21:00:05
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-26 21:00:52

from idc import *
from idaapi import *
from idautils import *
import json
import argparse
import os
import sys
sys.path.append("G:\\Projects\\Similarity\\Gemini-IR\\")


from gen_pyvex_ir import *

if __name__ == '__main__':
    
    fea_dim = 7
    list_res = get_bin_features(fea_dim)
    binary_name = get_root_filename() + '.json'
    out = open(binary_name, "w")
    for res in list_res:
        res = str(res).replace('\'', '\"')
        print(res, file=out)
    out.close()