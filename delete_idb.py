#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Gh0st Zer0
# @Date:   2021-01-23 20:14:28
# @Last Modified by:   Gh0st Zer0
# @Last Modified time: 2021-01-23 20:14:47

import sys
import os
import glob



if __name__ == "__main__":

    SSL_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\openssl\\*")
    BIN_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\binutils\\*")
    CORE_PATH = glob.glob("G:\\Projects\\Similarity\\Gemini-IR\\coreutils\\*")

    for path in SSL_PATH:
        #print(path)
        os.system("del /q " + path + "\\*.idb")
    for path in BIN_PATH:
        #print(path)
        os.system("del /q " + path + "\\*.idb")

    for path in CORE_PATH:
        #print(path)
        os.system("del /q " + path + "\\*.idb")