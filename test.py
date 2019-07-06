#!/usr/bin/env python3
import os
import sys
import runpy

os.makedirs("./dat",exist_ok=True)
os.makedirs("./secrets",exist_ok=True)

for OTP_EXP in [1,2,4]:
    sys.argv=[""]
    sys.argv.append("test.ihex")
    sys.argv.append("./dat")
    sys.argv.append("./secrets")
    sys.argv.append("%d"%OTP_EXP)
    runpy.run_path("boot_rom_patch.py")
    os.chdir("test")
    sys.argv=[""]
    sys.argv.append(os.path.join('..','inc'))
    sys.argv.append(os.path.join('..','dat'))
    sys.argv.append(os.path.join('..','secrets'))
    runpy.run_path("build.py")
    os.chdir("..")
