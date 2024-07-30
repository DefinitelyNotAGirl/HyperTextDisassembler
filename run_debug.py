#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os

if os.system("python ./build-system/main.py debug") != 0:
	exit (1)
os.system("./HyperTextDisas test1.elf")
os.system("./HyperTextDisas test.exe")
