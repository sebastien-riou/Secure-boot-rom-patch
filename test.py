#!/usr/bin/env python3
import os
import sys
import runpy

os.makedirs("./dat",exist_ok=True)
os.makedirs("./secrets",exist_ok=True)

assert(len(sys.argv)==1)
sys.argv.append("test.ihex")
sys.argv.append("./dat")
sys.argv.append("./secrets")
runpy.run_path("boot_rom_patch.py")
os.chdir("test")
sys.argv=[""]
sys.argv.append(os.path.join('..','inc'))
sys.argv.append(os.path.join('..','dat'))
sys.argv.append(os.path.join('..','secrets'))
runpy.run_path("build.py")
