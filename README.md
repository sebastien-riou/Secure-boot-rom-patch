# Secure-boot-rom-patch

Strong password protection for boot rom patch.

## What do we call "boot rom patch" ?
In case the first batch of an SOC turns out to be not functional, it is interesting to be able to download arbitrary code to investigate the issue. The boot rom patch enables that,
with minimum requirement on hardware: it is a minimal code which can be triggered right after reset release, before the ROM code starts to initialize the whole SOC.
If the SOC is supposed to have some security function, such boot rom patch needs obviously to be launched only by authorized staff at the SOC design house.
The difficulty stems from doing the access control securely without using any fancy hardware since by definition the boot rom patch mechanism shall be minimalist and not use anything beyond the CPU, the ROM, the RAM and a communication interface.
The proposed scheme achieves security mostly at algorithmic level, only few implementation aspect need to be reviewed for security.

## Functional description:
- boot_rom_patch (BRP): it is a small RAM code which allows to download and execute arbitrary RAM patch. linking to RX/TX functions in ROM code, 64 bytes are typically enough.
- ROM contains the BRP in encrypted form
- ROM decrypts and execute (from RAM) the BRP only if it receives a correct activation password (BRP_APW).

## Security concept:
- ROM image preparation:
    - BRP_APW = 32 bytes random value
    - BRP_BLOCKS = (sizeof(BRP)+31) / 32
    - BRP_OTP(0) = SHA256(BRP_APW)
    - BRP_OTP(i) = SHA256(BRP_OTP(i-1))
    - BRP_DIGEST = BRP_OTP(BRP_BLOCKS)
    - BRP_ROM = BRP^BRP_OTP
    - Store BRP_BLOCKS, BRP_DIGEST and BRP_ROM in ROM image
- ROM runtime execution:
    - PW = 32 bytes from outside (store in none executable area)
    - Write BRP_OTP to RAM (BRP_OTP(0) to BRP_OTP(BRP_BLOCKS))
    - If BRP_OTP(BRP_BLOCKS) different than BRP_DIGEST, go to error state
    - Replace BRP_OTP by BRP_ROM^BRP_OTP
    - Make RAM executable, except area where we placed PW (ie. data directly controllable from outside)
    - Launch execution from RAM

This is equivalent to a password check to access a simple bootloader mode.
The advantage is the intrinsic robustness against faults: the simple bootloader is not executable without the entry of the correct password.

### Additional countermeasure against some fault attacks
In practice, it would be enough for a skilled attacker to bypass the scheme by injecting two faults:
- Make whole RAM executable by direct laser fault on MPU
- Redirect execution to the user controlled buffer by whatever fault (for example by fault on CPU to force transfer of a pointer on this buffer to PC register)

This is not trivial but some attackers do try hard.

To prevent such attack, BRP_APW is coded on 64 bytes with all even bytes being fixed at a given value (0xF8 by default). The ROM code enforce those values and
get only the 32 odd bytes from outside. This encoding avoid to have malicious executable code sequence in the user controlled buffer.

### Recommended RAM layout, assuming stack grows down:

    Highest address
        64 bytes buffer to write APW
        x bytes for stack
        Area to load arbitrary patches using SBL
        SBL load area
    Lowest address

Advantages:
- APW buffer overflow outside the RAM, typically reset the device
- SBL and patches load area as far as possible from APW buffer, On hardware with MPUs with coarse granularity, this allows to have execution rights on SBL and patches load area while keeping APW buffer not executable.
- SBL code can move the stack up if needed

## boot_rom_patch.py script:
This script is generating the various byte arrays to hardcode in the ROM code and generate BRP_APW.

The scripts works on Linux and Windows (On windows it has been tested only within [git bash](https://gitforwindows.org/)).

Inputs:
- brp_ihex: ihex of the boot_rom_patch
- sources: path to write brp_data.h
- secrets: path to write brp_apw.*
- BRP_APW_EVEN (optional): the value for even bytes of BRP_APW

Outputs:
- sources/brp_dat.h: C99 header file declaring
    - BRP_BLOCKS
    - BRP_DIGEST
    - BRP_ROM
- secrets/brp_apw.h: BRP_APW as C99 header file, do not disclose!
- secrets/brp_apw.tcl: BRP_APW as TCL list of bytes, do not disclose!
- secrets/brp_apw.py: BRP_APW as python list of bytes, do not disclose!
