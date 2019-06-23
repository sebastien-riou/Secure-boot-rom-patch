#!/usr/bin/env python3
import os
import sys

from os.path import dirname
sys.path.append(dirname(__file__))

print("current dir:",os.getcwd())

from psb import *

try:
    os.remove(a.exe)
except:
    pass
    
sources=os.path.join('..','inc')
sources=os.path.join('..','dat')
secrets=os.path.join('..','secrets')

#print(sys.argv)
if len(sys.argv)>1:    
    sources = sys.argv[1]
if len(sys.argv)>2:    
    dat = sys.argv[2]
if len(sys.argv)>3:    
    secrets = sys.argv[3]

#-Werror 
compile(["test.c"],output="a.exe",args="--std=c99 -Wall ",includes=['.',sources,dat,secrets], )

cmd = ["./a.exe"]
print(' '.join(cmd))
sys.stdout.flush()  
subprocess.run(cmd,check=True,shell=False)
