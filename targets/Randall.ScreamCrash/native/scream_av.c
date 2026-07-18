/* Lab-only: force a real SEH ACCESS_VIOLATION for Scream regression tests. */
#ifdef _WIN32
__declspec(dllexport)
#endif
void crash_av(void)
{
    *(volatile int*)0 = 0x41414141;
}
