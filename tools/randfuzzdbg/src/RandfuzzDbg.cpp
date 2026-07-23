/*
 * RandfuzzDbg — WinDbg / WinDbg Preview dbgeng extension stub.
 * Build on Windows with Debugging Tools SDK. See README.md.
 *
 * Boundary: dump walks + gadget citations for lab targets.
 * No shellcode / payload generation.
 */
#include <windows.h>
#include <dbgeng.h>
#include <stdio.h>

#ifndef __cplusplus
#error RandfuzzDbg requires C++
#endif

static IDebugClient* g_Client = nullptr;
static IDebugControl* g_Control = nullptr;

static HRESULT Out(PCSTR msg)
{
    if (!g_Control) return E_FAIL;
    return g_Control->Output(DEBUG_OUTPUT_NORMAL, "%s", msg);
}

extern "C" HRESULT CALLBACK rf_help(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    Out("RandfuzzDbg — fuzz crash analysis for WinDbg Preview\n");
    Out("  !rf.help      this text\n");
    Out("  !rf.crash     (planned) linked Randfuzz walk JSON\n");
    Out("  !rf.regs      (planned) fault registers\n");
    Out("  !rf.control   (planned) CONTROL @ offset hint\n");
    Out("  !rf.stack     (planned) stack / saved RET walk\n");
    Out("  !rf.modules   (planned) module list\n");
    Out("  !rf.rop       (planned) gadgets from *_rop.json\n");
    Out("  !rf.export    (planned) refresh walk path\n");
    Out("Until DLL commands land, use: $$>a< ...\\tools\\randfuzzdbg\\scripts\\rf_walk.txt\n");
    Out("Host: randall rop … · randall windbg walk · docs/WINDBG_FUZZ_PKG.md\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags)
{
    *version = DEBUG_EXTENSION_VERSION(1, 0);
    *flags = 0;
    if (FAILED(DebugCreate(__uuidof(IDebugClient), (void**)&g_Client)))
        return E_FAIL;
    if (FAILED(g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control)))
        return E_FAIL;
    return S_OK;
}

extern "C" void CALLBACK DebugExtensionUninitialize()
{
    if (g_Control) { g_Control->Release(); g_Control = nullptr; }
    if (g_Client) { g_Client->Release(); g_Client = nullptr; }
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }
