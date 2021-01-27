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
import sys
sys.path.append("G:\\Projects\\Similarity\\Gemini-IR\\")

import os
from features_get import *

if __name__ == '__main__':
    list_res = get_features()
    binary_name = get_root_filename() + '.json'
    out = open(binary_name, "w")
    for res in list_res:
        res = str(res).replace('\'', '\"')
        print(res, file=out)
    out.close()