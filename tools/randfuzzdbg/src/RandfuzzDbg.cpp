/*
 * RandfuzzDbg — WinDbg / WinDbg Preview dbgeng extension.
 * Build on Windows with Debugging Tools SDK. See README.md.
 *
 * Boundary: dump walks + gadget citations for lab targets.
 * No shellcode / payload generation.
 */
#include <windows.h>
#include <dbgeng.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifndef __cplusplus
#error RandfuzzDbg requires C++
#endif

static IDebugClient* g_Client = nullptr;
static IDebugControl* g_Control = nullptr;
static char g_WalkPath[MAX_PATH] = {0};
static char g_RopPath[MAX_PATH] = {0};

static HRESULT Out(PCSTR msg)
{
    if (!g_Control) return E_FAIL;
    return g_Control->Output(DEBUG_OUTPUT_NORMAL, "%s", msg);
}

static HRESULT Outf(PCSTR fmt, ...)
{
    if (!g_Control) return E_FAIL;
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    return g_Control->Output(DEBUG_OUTPUT_NORMAL, "%s", buf);
}

static void TrimArgs(PSTR args)
{
    if (!args) return;
    while (*args == ' ' || *args == '\t') args++;
}

static bool ReadFileText(PCSTR path, PSTR out, size_t outLen)
{
    out[0] = 0;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
    size_t n = fread(out, 1, outLen - 1, f);
    fclose(f);
    out[n] = 0;
    return n > 0;
}

static void ExtractJsonString(PCSTR json, PCSTR key, PSTR dest, size_t destLen)
{
    dest[0] = 0;
    char needle[128];
    _snprintf_s(needle, sizeof(needle), _TRUNCATE, "\"%s\"", key);
    PCSTR p = strstr(json, needle);
    if (!p) return;
    p = strchr(p + strlen(needle), ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == 'null') return;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < destLen)
    {
        if (*p == '\\' && p[1]) { p++; }
        dest[i++] = *p++;
    }
    dest[i] = 0;
}

static void ExtractJsonNumber(PCSTR json, PCSTR key, PSTR dest, size_t destLen)
{
    dest[0] = 0;
    char needle[128];
    _snprintf_s(needle, sizeof(needle), _TRUNCATE, "\"%s\"", key);
    PCSTR p = strstr(json, needle);
    if (!p) return;
    p = strchr(p + strlen(needle), ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == 'null') return;
    size_t i = 0;
    while ((*p >= '0' && *p <= '9') || *p == '-')
    {
        if (i + 1 >= destLen) break;
        dest[i++] = *p++;
    }
    dest[i] = 0;
}

static HRESULT Exec(PCSTR cmd)
{
    if (!g_Control) return E_FAIL;
    return g_Control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd, DEBUG_EXECUTE_DEFAULT);
}

extern "C" HRESULT CALLBACK rf_help(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    Out("RandfuzzDbg — fuzz crash analysis for WinDbg Preview\n");
    Out("  !rf.help                 this text\n");
    Out("  !rf.walk                 run register/stack/module walk\n");
    Out("  !rf.crash [walk.json]    show linked Randfuzz walk JSON\n");
    Out("  !rf.regs                 fault registers (r)\n");
    Out("  !rf.control              CONTROL @ offset from walk file\n");
    Out("  !rf.stack                stack / saved RET walk (k)\n");
    Out("  !rf.modules              module list (lm)\n");
    Out("  !rf.rop [rop.json]       print sibling *_rop.json sketch\n");
    Out("  !rf.export               host refresh hint (randall windbg walk)\n");
    Out("Set walk path: !rf.crash C:\\path\\to\\<guid>_windbg_walk.json\n");
    Out("Host: randall rop … · randall windbg walk · docs/WINDBG_FUZZ_PKG.md\n");
    Out("Boundary: lab sketches only — no shellcode / payloads.\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK rf_walk(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    Out("=== RANDFUZZDBG WALK BEGIN ===\n");
    Out("--- registers ---\n");
    Exec("r");
    Out("--- stack ---\n");
    Exec("k");
    Out("--- PEB ---\n");
    Exec("!peb");
    Out("--- modules ---\n");
    Exec("lm");
    Out("--- exception ---\n");
    Exec(".exr -1");
    Out("=== RANDFUZZDBG WALK END ===\n");
    Out("Next: !rf.crash <walk.json> · !rf.rop · randall rop from-crash\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK rf_regs(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    return Exec("r");
}

extern "C" HRESULT CALLBACK rf_stack(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    return Exec("k");
}

extern "C" HRESULT CALLBACK rf_modules(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    return Exec("lm");
}

extern "C" HRESULT CALLBACK rf_crash(PDEBUG_CLIENT /*client*/, PCSTR args)
{
    char path[MAX_PATH] = {0};
    if (args)
    {
        while (*args == ' ' || *args == '\t') args++;
        if (*args)
            strncpy_s(path, args, _TRUNCATE);
    }
    if (!path[0] && g_WalkPath[0])
        strncpy_s(path, g_WalkPath, _TRUNCATE);

    if (!path[0])
    {
        Out("Usage: !rf.crash <path-to-*_windbg_walk.json>\n");
        Out("Or set path once; later !rf.crash / !rf.control / !rf.rop reuse it.\n");
        Out("Host: randall windbg walk -i <crash-guid>\n");
        return S_OK;
    }

    strncpy_s(g_WalkPath, path, _TRUNCATE);

    char json[65536];
    if (!ReadFileText(path, json, sizeof(json)))
    {
        Outf("!rf.crash: cannot read %s\n", path);
        return E_FAIL;
    }

    char crashId[80] = {0}, project[128] = {0}, dump[512] = {0};
    char ctrlReg[64] = {0}, ctrlOff[32] = {0}, summary[256] = {0}, rop[512] = {0};
    ExtractJsonString(json, "crashId", crashId, sizeof(crashId));
    ExtractJsonString(json, "project", project, sizeof(project));
    ExtractJsonString(json, "dumpPath", dump, sizeof(dump));
    ExtractJsonString(json, "controlledRegister", ctrlReg, sizeof(ctrlReg));
    ExtractJsonNumber(json, "controlledOffset", ctrlOff, sizeof(ctrlOff));
    ExtractJsonString(json, "summaryLine", summary, sizeof(summary));
    ExtractJsonString(json, "ropPath", rop, sizeof(rop));
    if (rop[0]) strncpy_s(g_RopPath, rop, _TRUNCATE);

    Out("=== RANDFUZZ CRASH WALK ===\n");
    Outf("file:    %s\n", path);
    if (crashId[0]) Outf("crash:   %s\n", crashId);
    if (project[0]) Outf("project: %s\n", project);
    if (dump[0]) Outf("dump:    %s\n", dump);
    if (ctrlReg[0] || ctrlOff[0])
        Outf("control: %s @ %s\n", ctrlReg[0] ? ctrlReg : "(reg?)", ctrlOff[0] ? ctrlOff : "?");
    if (summary[0]) Outf("summary: %s\n", summary);
    if (g_RopPath[0]) Outf("rop:     %s\n", g_RopPath);
    Out("Tip: !rf.walk · !rf.control · !rf.rop\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK rf_control(PDEBUG_CLIENT /*client*/, PCSTR args)
{
    char path[MAX_PATH] = {0};
    if (args)
    {
        while (*args == ' ' || *args == '\t') args++;
        if (*args) strncpy_s(path, args, _TRUNCATE);
    }
    if (!path[0] && g_WalkPath[0]) strncpy_s(path, g_WalkPath, _TRUNCATE);
    if (!path[0])
    {
        Out("Usage: !rf.control [walk.json]  (or !rf.crash <path> first)\n");
        return S_OK;
    }

    char json[65536];
    if (!ReadFileText(path, json, sizeof(json)))
    {
        Outf("!rf.control: cannot read %s\n", path);
        return E_FAIL;
    }

    char ctrlReg[64] = {0}, ctrlOff[32] = {0};
    ExtractJsonString(json, "controlledRegister", ctrlReg, sizeof(ctrlReg));
    ExtractJsonNumber(json, "controlledOffset", ctrlOff, sizeof(ctrlOff));
    Out("=== CONTROL HINT ===\n");
    if (!ctrlOff[0] && !ctrlReg[0])
        Out("(no controlledOffset in walk — run pattern/offset on host)\n");
    else
        Outf("CONTROL @ %s (%s)\n", ctrlOff[0] ? ctrlOff : "?", ctrlReg[0] ? ctrlReg : "IP");
    Out("Host: randall pattern offset · randall exploitdev · randall exploit guide\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK rf_rop(PDEBUG_CLIENT /*client*/, PCSTR args)
{
    char path[MAX_PATH] = {0};
    if (args)
    {
        while (*args == ' ' || *args == '\t') args++;
        if (*args) strncpy_s(path, args, _TRUNCATE);
    }
    if (!path[0] && g_RopPath[0]) strncpy_s(path, g_RopPath, _TRUNCATE);
    if (!path[0])
    {
        Out("Usage: !rf.rop [*_rop.json]  (or !rf.crash walk.json first)\n");
        Out("Host: randall rop from-crash -i <guid> --goal pivot\n");
        return S_OK;
    }

    char json[131072];
    if (!ReadFileText(path, json, sizeof(json)))
    {
        Outf("!rf.rop: cannot read %s\n", path);
        return E_FAIL;
    }

    char goal[64] = {0}, summary[256] = {0}, module[512] = {0};
    ExtractJsonString(json, "goal", goal, sizeof(goal));
    ExtractJsonString(json, "summaryLine", summary, sizeof(summary));
    ExtractJsonString(json, "modulePath", module, sizeof(module));

    Out("=== ROP STUDIO SKETCH (citations only) ===\n");
    Outf("file:   %s\n", path);
    if (goal[0]) Outf("goal:   %s\n", goal);
    if (module[0]) Outf("module: %s\n", module);
    if (summary[0]) Outf("summary:%s\n", summary);

    // Print instruction citations from the sketch JSON (naive scan).
    int shown = 0;
    PCSTR p = json;
    while (shown < 12)
    {
        PCSTR key = strstr(p, "\"instruction\"");
        if (!key) break;
        PCSTR colon = strchr(key, ':');
        if (!colon) break;
        colon++;
        while (*colon == ' ' || *colon == '\t') colon++;
        if (*colon != '"') { p = key + 12; continue; }
        colon++;
        char insn[256];
        size_t i = 0;
        while (*colon && *colon != '"' && i + 1 < sizeof(insn))
        {
            if (*colon == '\\' && colon[1]) colon++;
            insn[i++] = *colon++;
        }
        insn[i] = 0;
        if (insn[0])
            Outf("  [%d] %s\n", ++shown, insn);
        p = colon;
    }
    if (shown == 0)
        Out("(no gadget steps in file — run randall rop from-crash)\n");
    Out("Boundary: ordered gadget citations — not a payload.\n");
    return S_OK;
}

extern "C" HRESULT CALLBACK rf_export(PDEBUG_CLIENT /*client*/, PCSTR /*args*/)
{
    Out("Refresh walk on host, then reload here:\n");
    Out("  randall windbg walk -i <crash-guid>\n");
    Out("  randall rop from-crash -i <crash-guid> --goal pivot\n");
    Out("  !rf.crash <repo>\\data\\crashes\\<project>\\<guid>_windbg_walk.json\n");
    if (g_WalkPath[0]) Outf("Current walk: %s\n", g_WalkPath);
    if (g_RopPath[0]) Outf("Current rop:  %s\n", g_RopPath);
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
