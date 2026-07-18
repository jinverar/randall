/*
 * Lab-only native crash process for Scream selftest.
 * Sleeps briefly so the watcher can attach, then ACCESS_VIOLATIONs.
 */
#include <windows.h>

int main(void)
{
    Sleep(1500);
    *(volatile int*)0 = 0x41414141;
    return 0;
}
