/*
 * Lab-only intentional fault harness for the Debugger Regression Corpus.
 * Research use — no network, no weaponized payloads.
 *
 * Usage: debugger_corpus_fault.exe <fault-id> [--delay-ms N]
 *
 * Fault ids: null-deref, null-read, av-read, av-write, ascii-write, ascii-read,
 *            divide-zero, illegal-instruction,
 *            heap-overflow / oob-write / uaf / double-free / stack-corrupt /
 *            integer-trunc (stubs or simple native faults)
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void sleep_ms(int ms)
{
    if (ms > 0)
        Sleep((DWORD)ms);
}

static void fault_null_deref(void)
{
    *(volatile int*)0 = 1;
}

static void fault_null_read(void)
{
    volatile int x = *(volatile int*)0;
    (void)x;
}

static void fault_av_read(void)
{
    volatile int x = *(volatile int*)(uintptr_t)0xDEADBEEF;
    (void)x;
}

static void fault_av_write(void)
{
    *(volatile int*)(uintptr_t)0xDEADBEEF = 0x12345678;
}

static void fault_ascii_write(void)
{
    *(volatile int*)(uintptr_t)0x41414141 = 0x42424242;
}

static void fault_ascii_read(void)
{
    volatile int x = *(volatile int*)(uintptr_t)0x41414141;
    (void)x;
}

static void fault_divide_zero(void)
{
    volatile int a = 1;
    volatile int b = 0;
    volatile int c = a / b;
    (void)c;
}

static void fault_illegal_instruction(void)
{
    RaiseException(0xC000001D, 0, 0, NULL);
}

static void fault_heap_overflow_stub(void)
{
    fprintf(stderr, "heap-overflow: stub — not implemented (see tests/debugger-corpus/heap-overflow)\n");
    ExitProcess(2);
}

static void fault_uaf_stub(void)
{
    fprintf(stderr, "uaf: stub — not implemented (see tests/debugger-corpus/uaf)\n");
    ExitProcess(2);
}

static void fault_double_free_stub(void)
{
    fprintf(stderr, "double-free: stub — not implemented (see tests/debugger-corpus/double-free)\n");
    ExitProcess(2);
}

static void fault_stack_corrupt_stub(void)
{
    fprintf(stderr, "stack-corrupt: stub — not implemented (see tests/debugger-corpus/stack-corrupt)\n");
    ExitProcess(2);
}

static void fault_integer_trunc_stub(void)
{
    fprintf(stderr, "integer-trunc: stub — not implemented (see tests/debugger-corpus/integer-trunc)\n");
    ExitProcess(2);
}

static void fault_oob_write_stub(void)
{
    fprintf(stderr, "oob-write: stub — alias of heap-overflow (see tests/debugger-corpus/oob-write)\n");
    ExitProcess(2);
}

static void usage(const char* exe)
{
    fprintf(stderr,
        "Usage: %s <fault-id> [--delay-ms N]\n"
        "  null-deref | null-read | av-read | av-write | ascii-write | ascii-read |\n"
        "  divide-zero | illegal-instruction |\n"
        "  heap-overflow | oob-write | uaf | double-free | stack-corrupt | integer-trunc\n",
        exe);
}

int main(int argc, char** argv)
{
    int delay = 1500;
    const char* fault = "null-deref";

    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    fault = argv[1];
    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "--delay-ms") == 0 && i + 1 < argc)
        {
            delay = atoi(argv[++i]);
        }
    }

    sleep_ms(delay);

    if (strcmp(fault, "null-deref") == 0)
        fault_null_deref();
    else if (strcmp(fault, "null-read") == 0)
        fault_null_read();
    else if (strcmp(fault, "av-read") == 0)
        fault_av_read();
    else if (strcmp(fault, "av-write") == 0)
        fault_av_write();
    else if (strcmp(fault, "ascii-write") == 0)
        fault_ascii_write();
    else if (strcmp(fault, "ascii-read") == 0)
        fault_ascii_read();
    else if (strcmp(fault, "divide-zero") == 0)
        fault_divide_zero();
    else if (strcmp(fault, "illegal-instruction") == 0)
        fault_illegal_instruction();
    else if (strcmp(fault, "heap-overflow") == 0)
        fault_heap_overflow_stub();
    else if (strcmp(fault, "oob-write") == 0)
        fault_oob_write_stub();
    else if (strcmp(fault, "uaf") == 0)
        fault_uaf_stub();
    else if (strcmp(fault, "double-free") == 0)
        fault_double_free_stub();
    else if (strcmp(fault, "stack-corrupt") == 0)
        fault_stack_corrupt_stub();
    else if (strcmp(fault, "integer-trunc") == 0)
        fault_integer_trunc_stub();
    else
    {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
