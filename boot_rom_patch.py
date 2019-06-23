#!/usr/bin/env python3

"""
Strong password protection for boot rom patch

What do we call "boot rom patch" ?
In case the first batch of an SOC turns out to be not functional, it is interesting to be able to download arbitrary code to investigate the issue. The boot rom patch enables that,
with minimum requirement on hardware: it is a minimal code which can be triggered right after reset release, before the ROM code starts to initialize the whole SOC.
If the SOC is supposed to have some security function, such boot rom patch needs obviously to be launched only by authorized staff at the SOC design house. 
The difficulty stems from doing the access control securely without using any fancy hardware since by definition the boot rom patch mechanism shall be minimalist and not use anything beyond the CPU, the ROM, the RAM and a communication interface.
The proposed scheme achieves security mostly at algorithmic level, only few implementation aspect need to be reviewed for security.

Functional description: 
- boot_rom_patch (BRP): it is a small RAM code which allows to download and execute arbitrary RAM patch. linking to RX/TX functions in ROM code, 64 bytes are typically enough.
- ROM contains the BRP in encrypted form
- ROM decrypts and execute (from RAM) the BRP only if it receives a correct activation password (BRP_APW).

Security concept:
    - ROM image preparation:
        - BRP_APW = 32 bytes random value
        - BRP_BLOCKS = (sizeof(BRP)+31) / 32
        - BRP_OTP(0) = SHA256(BRP_APW)
        - BRP_OTP(i) = SHA256(BRP_OTP(i-1))
        - BRP_DIGEST = BRP_OTP(BRP_BLOCKS)
        - BRP_ROM = BRP^BRP_OTP 
        Store BRP_BLOCKS, BRP_DIGEST and BRP_ROM in ROM image
    - ROM runtime execution:
        - PW = 32 bytes from outside (store in none executable area)
        - Write BRP_OTP to RAM (BRP_OTP(0) to BRP_OTP(BRP_BLOCKS))
        - if BRP_OTP(BRP_BLOCKS) different than BRP_DIGEST, go to error state
        - Replace BRP_OTP by BRP_ROM^BRP_OTP
        - make RAM executable, except area where we placed PW (ie. data directly controllable from outside)
        - launch execution from RAM

    This is equivalent to a password check to access a simple bootloader mode.
    The advantage is the intrinsic robustness against faults: the simple bootloader is not executable without the entry of the correct password.
    In practice, it would be enough for a skilled attacker to bypass the scheme by injecting two faults:
    - make whole RAM executable by direct laser fault on MPU
    - redirect execution to the user controlled buffer by whatever fault (for example by fault on CPU to force transfer of a pointer on this buffer to PC register)
    This is not trivial but some attackers do try hard.
    To prevent such attack, BRP_APW is coded on 64 bytes with all even bytes being fixed at a given value (0xF8 by default). The ROM code enforce those values and 
    get only the 32 odd bytes from outside. This encoding avoid to have malicious executable code sequence in the user controlled buffer.
    
    Recommended RAM layout, assuming stack grows down:
    
    highest address
        64 bytes buffer to write APW
        x bytes for stack
        area to download arbitrary patches using sbl
        sbl load area
    lowest address
    
    Advantages:
    - APW buffer overflow outside the RAM, typically reset the device
    - sbl and download area as far as possible from APW buffer, On hardware with MPUs with coarse granularity, this allows to have execution rights on sbl and download area while keeping APW buffer not executable.
    - sbl code can move the stack up if needed

Script I/Os:    
input: 
    - brp_ihex: ihex of the boot_rom_patch
    - sources: path to write brp_data.h
    - secrets: path to write brp_apw.*
output:
    - <sources>brp_dat.h: C99 header file declaring 
        - BRP_BLOCKS
        - BRP_DIGEST
        - BRP_ROM
    - <secrets>brp_apw.h: BRP_APW as C99 header file, do not disclose!
    - <secrets>brp_apw.tcl: BRP_APW as TCL list of bytes, do not disclose!
    - <secrets>brp_apw.py: BRP_APW as python list of bytes, do not disclose!
"""


import os
import sys
try:
    from Crypto.Hash import SHA256
except:
    from Cryptodome.Hash import SHA256

from intelhex import IntelHex

debug=0

if (len(sys.argv) > 5) | (len(sys.argv) < 4) :
    print("ERROR: incorrect arguments")
    print("Usage:")
    print("%s <brp_ihex> <sources> <secrets> [APW_EVEN]"%os.path.basename(__file__))
    print(sys.argv)
    exit()

BRP_APW_EVEN=0xF8    
    
ihexf = sys.argv[1]
sources = sys.argv[2]
secrets = sys.argv[3]
if len(sys.argv) > 4:
    BRP_APW_EVEN = int(sys.argv[4],0)
    
#generate BRP_APW
brp_seed = os.urandom(32)
brp_seed_iterations = 1000
brp_otp_state = brp_seed
def brp_otp():
    global brp_otp_state
    brp_otp_state = SHA256.new(brp_otp_state).digest()
    return brp_otp_state
for i in range(0,brp_seed_iterations):
    brp_otp()
BRP_APW_odd = brp_otp()
BRP_APW=bytearray()
for b in BRP_APW_odd:
    BRP_APW.append(0xF8)
    BRP_APW.append(b)
brp_otp_state = SHA256.new(BRP_APW).digest()
    
ih = IntelHex()
ih.loadhex(ihexf)
all_sections = ih.segments()
print("input hex file sections:")
for sec in all_sections:
    print("0x%08X 0x%08X"%(sec[0],sec[1]-1))

#ensure we have a single section
assert(1==len(all_sections))

#get BRP as raw bytes (boot_rom_patch shall be position independent code)
BRP = bytearray()            
for sec in all_sections:
    for i in range(sec[0],sec[1]):
        BRP.append(ih[i])
 
BRP_BLOCKS = (len(BRP)+31)//32

BRP_OTP = bytearray()
BRP_OTP+=brp_otp_state
for i in range(1,BRP_BLOCKS):
    BRP_OTP+=brp_otp()
BRP_DIGEST = brp_otp()

if debug:
    print("%032x"%int.from_bytes(brp_seed, byteorder='big'))
    print("%032x"%int.from_bytes(BRP_APW, byteorder='big'))
    print("%032x"%int.from_bytes(BRP_DIGEST, byteorder='big'))

BRP_ROM = bytearray()

for i in range(0,len(BRP)):
    BRP_ROM.append(BRP_OTP[i] ^ BRP[i])

def print_hexstr(ba):    
    for i in range(0,len(ba)):
        print("%02X "%ba[i],end="")
    print()

print_hexstr(BRP)
if debug:
    print_hexstr(BRP_OTP)
    print_hexstr(BRP_ROM)

f = os.path.join(sources,"brp_data.h")
with open(f, 'w') as out:
    out.write("""
#ifndef __BRP_DATA_H__
#define __BRP_DATA_H__
""")
    out.write('#define BRP_BLOCKS %d\n'%BRP_BLOCKS)
    out.write('#define BRP_APW_EVEN %d\n'%BRP_APW_EVEN)
    out.write('const uint8_t BRP_DIGEST[%d] = {'%len(BRP_DIGEST))
    for i in range(0,len(BRP_DIGEST)):
        out.write('0x%02X, '%BRP_DIGEST[i])
    out.write('};\n')
    out.write('const uint8_t BRP_ROM[%d] = {'%len(BRP_ROM))
    for i in range(0,len(BRP_ROM)):
        out.write('0x%02X, '%BRP_ROM[i])
    out.write('};\n')
    out.write("""#endif
""")

f = os.path.join(secrets,"brp_apw.h")
with open(f, 'w') as out:
    out.write("""
#ifndef __BRP_APW_H__
#define __BRP_APW_H__
""")
    out.write('#define BRP_BLOCKS %d\n'%BRP_BLOCKS)
    out.write('const uint8_t BRP_APW[%d] = {'%len(BRP_APW))
    for i in range(0,len(BRP_APW)):
        out.write('0x%02X, '%BRP_APW[i])
    out.write('};\n')
    out.write('const uint8_t BRP_APW_odd[%d] = {'%len(BRP_APW_odd))
    for i in range(0,len(BRP_APW_odd)):
        out.write('0x%02X, '%BRP_APW_odd[i])
    out.write('};\n')
    out.write('const uint8_t BRP[%d] = {'%len(BRP))
    for i in range(0,len(BRP)):
        out.write('0x%02X, '%BRP[i])
    out.write('};\n')
    out.write('const uint8_t BRP_OTP[%d] = {'%len(BRP_OTP))
    for i in range(0,len(BRP_OTP)):
        out.write('0x%02X, '%BRP_OTP[i])
    out.write('};\n')
    out.write("""#endif
""")

f = os.path.join(secrets,"brp_apw.tcl")
with open(f, 'w') as out:
    out.write('set brp_seed_iterations %d\n'%brp_seed_iterations)
    out.write('set brp_seed {')
    for i in range(0,len(brp_seed)):
        out.write('"%02X" '%brp_seed[i])
    out.write('}\n')
    out.write('set brp_apw {')
    for i in range(0,len(BRP_APW_odd)):
        out.write('"%02X" '%BRP_APW_odd[i])
    out.write('}\n')
    
f = os.path.join(secrets,"brp_apw.py")
with open(f, 'w') as out:
    out.write('brp_seed_iterations=%d\n'%brp_seed_iterations)
    brp_seed_hex = "0x%032x"%int.from_bytes(brp_seed, byteorder='big')
    out.write('brp_seed = %s.to_bytes(32,byteorder="big")\n'%brp_seed_hex)
    brp_apw_hex = "0x%032x"%int.from_bytes(BRP_APW_odd, byteorder='big')
    out.write('brp_apw = %s.to_bytes(32,byteorder="big")\n'%brp_apw_hex)
    brp_apw_full_hex = "0x%032x"%int.from_bytes(BRP_APW, byteorder='big')
    out.write('brp_apw_full = %s.to_bytes(32,byteorder="big")\n'%brp_apw_full_hex)
    