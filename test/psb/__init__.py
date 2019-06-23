


import os
import sys
import platform
import shutil
import subprocess

def np(*unix_paths):
    p = os.sep.join(unix_paths)
    return p.replace('/',os.sep)

def appendto(list,args,op=None):
    if args is None:
        return
    def nop(x):
        return x
    def process_arg(arg):
        arg=op(arg)
        #print(arg)
        if isinstance(arg, str) & (len(arg)>0):
            list.append(arg)
        else:
            for a in arg:
                list.append(a)
    if op is None:
        op = nop
    if isinstance(args, str) & (len(args)>0):
        process_arg(args)
    else:
        for a in args:
            process_arg(a)
    
def compile(files,output="a.out",args=None,includes=None,libs=None,cwd='.'):
    gcc = shutil.which('gcc')
    cmd = [gcc]
    appendto(cmd,args.split(" "))
    appendto(cmd,files,np)
    cmd.append('-o')
    cmd.append(np(output))
    appendto(cmd,includes,lambda inc: ['-I',inc])
    appendto(cmd,libs,lambda lib: '-l'+lib)
    #print(cmd)
    print(' '.join(cmd))
    sys.stdout.flush()
    subprocess.run(cmd,check=True,cwd=cwd)
